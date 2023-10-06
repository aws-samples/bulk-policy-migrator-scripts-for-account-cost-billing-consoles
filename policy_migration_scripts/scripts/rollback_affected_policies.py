# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import argparse
import datetime
import json
import os
import sys

import boto3

# Add project root to sys path so that interpreter is able to find our package and modules
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
sys.path.append(project_root)

from policy_migration_scripts.utils.iam import IamHelper
from policy_migration_scripts.utils.identity_center import IdentityCenterHelper
from policy_migration_scripts.utils.log import get_logger
from policy_migration_scripts.utils.model import (
    PermissionSetProvisionRequest,
    PolicyType,
    RollbackPoliciesExecutionResult,
    SummaryReport,
)
from policy_migration_scripts.utils.org import OrgHelper
from policy_migration_scripts.utils.utils import (
    is_china_region,
    is_sso_role,
    read_accounts_from_file,
)
from policy_migration_scripts.utils.validation import (
    rollback_args_deep_validate,
    rollback_args_fast_validate,
    validate_if_being_run_by_payer_account,
)

LOGGER = get_logger(__name__)


def main():
    args = parse_args()
    rollback_args_fast_validate(args)
    sts_client = boto3.client('sts')
    org_client = boto3.client('organizations')
    sso_admin_client = boto3.client('sso-admin')
    LOGGER.info("Running with boto client region = %s", sts_client.meta.region_name)
    payer_account = sts_client.get_caller_identity()['Account']
    is_china = is_china_region(sts_client)
    validate_if_being_run_by_payer_account(org_client, payer_account)
    # get accounts according to command line arguments
    all_member_accounts = OrgHelper.get_all_org_accounts(org_client)
    rollback_args_deep_validate(args, payer_account, all_member_accounts)
    member_accounts = get_accounts_in_rollback_scope(all_member_accounts, args, payer_account)
    main_summary_report = SummaryReport()
    try:
        for member_account in member_accounts:
            do_rollback(member_account, payer_account, org_client, sso_admin_client, main_summary_report, is_china)
        write_summary_report(main_summary_report)
    except Exception as e:
        LOGGER.error("The rolling back process was interrupted by an expected error. "
                     "Please review the error and refer to FAQ on next steps.")
        raise e


def do_rollback(member_account, payer_account, org_client, sso_admin_client, main_summary_report, is_china):
    LOGGER.info(f'Running for account: {member_account}')

    iam_client_for_member_account = IamHelper.get_iam_client(member_account, payer_account)
    permission_set_provision_requests = None
    if member_account == payer_account and not is_china:
        execution_result = rollback_permission_sets(sso_admin_client, member_account)
        merge_summary_report(main_summary_report, execution_result.summary_report)
        permission_set_provision_requests = execution_result.permission_set_provision_requests

        execution_result = rollback_scp_policies(org_client, member_account)
        merge_summary_report(main_summary_report, execution_result.summary_report)

    execution_result = rollback_customer_managed_policies(iam_client_for_member_account, member_account)
    merge_summary_report(main_summary_report, execution_result.summary_report)

    execution_result = rollback_user_inline_policies(iam_client_for_member_account, member_account)
    merge_summary_report(main_summary_report, execution_result.summary_report)

    execution_result = rollback_role_inline_policies(iam_client_for_member_account, member_account)
    merge_summary_report(main_summary_report, execution_result.summary_report)

    execution_result = rollback_group_inline_policies(iam_client_for_member_account, member_account)
    merge_summary_report(main_summary_report, execution_result.summary_report)

    if permission_set_provision_requests:
        permission_set_provisioning_report = IdentityCenterHelper.get_permission_set_provisioning_status_report(
            sso_admin_client,
            permission_set_provision_requests
        )
        merge_summary_report(main_summary_report, permission_set_provisioning_report)


def merge_summary_report(main_summary_report: SummaryReport, summary_report: SummaryReport):
    main_summary_report.failure_report += summary_report.failure_report
    main_summary_report.success_report += summary_report.success_report


def write_summary_report(summary_report: SummaryReport):
    json_report = {
        "Failure Cases": summary_report.failure_report,
        "Success Cases": summary_report.success_report,
    }
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H-%M-%S-%f")
    filename = f'RollBack-Report-{timestamp}.json'
    with open(filename, 'w') as fp:
        json.dump(json_report, fp, indent=4)
    LOGGER.info("Successfully rolled back all policies")
    LOGGER.info(f"Rollback summary report written to file {filename}.")


def parse_args():
    arg_parser = argparse.ArgumentParser()

    group = arg_parser.add_mutually_exclusive_group()
    group.add_argument(
        "--all",
        action="store_true",
        help="The script runs for the entire AWS Organization"
    )
    group.add_argument(
        "--accounts",
        dest="accounts",
        required=False,
        type=str,
        default=None,
        help="Comma separated list of AWS account IDs, The script runs only for these accounts"
    )
    group.add_argument(
        '--accounts-file',
        dest='accounts_file',
        help='Absolute path of the CSV file containing AWS account IDs',
        type=str
    )

    arg_parser.add_argument(
        "--exclude-accounts",
        dest="excluded_accounts",
        required=False,
        type=str,
        default=None,
        help="Comma separated list of AWS account IDs. "
             "This can only be specified when --all argument is used. "
             "This is used to run the script for all accounts in the org "
             "except the accounts specified using this argument"
    )
    args = arg_parser.parse_args()
    parsed_args = {
        "include_all": True if args.all else False,
        "accounts": _get_accounts_from_args(args),
        "excluded_accounts":
            [account.strip() for account in args.excluded_accounts.split(",")] if args.excluded_accounts else [],
    }
    LOGGER.info(parsed_args)
    return parsed_args


def _get_accounts_from_args(args):
    if args.accounts:
        return [account.strip() for account in args.accounts.split(",")]
    elif args.accounts_file:
        return read_accounts_from_file(args.accounts_file)
    else:
        return []


def get_accounts_in_rollback_scope(all_member_accounts, args, payer_account):
    if args["include_all"]:
        # get the list of accounts in the organization
        LOGGER.info(f'Running in ORG mode for payer account: {payer_account}')
        member_accounts = all_member_accounts
        if args["excluded_accounts"]:
            member_accounts = filter_member_accounts(args["excluded_accounts"], member_accounts)
            LOGGER.info(f'Excluding accounts: {args["excluded_accounts"]}')
    else:
        member_accounts = args["accounts"]
        LOGGER.info(f'Running in LINKED ACCOUNT mode with accounts: {args["accounts"]}')
    if not member_accounts:
        LOGGER.info(f'Running in PAYER ACCOUNT mode for payer account: {payer_account}')
        LOGGER.info(f'Since no cli argument is given, '
                    f'by default only payer account {payer_account} will be in the scope of rollback operation.')
        member_accounts = [payer_account]
    return member_accounts


def filter_member_accounts(excluded_accounts, all_accounts):
    return [account for account in all_accounts if account not in excluded_accounts]


def rollback_customer_managed_policies(iam_client_, account_id):
    LOGGER.info("Scanning for Customer Managed Policies")
    execution_result = RollbackPoliciesExecutionResult()
    for policies in IamHelper.get_customer_managed_policies(iam_client_):
        for policy in policies:
            policy_document, should_update = clean_up_suggested_customer_managed_statements_if_found_any(policy)
            if should_update:
                report = {
                    "Account": account_id,
                    "PolicyName": policy['PolicyName'],
                    "PolicyId": policy['PolicyId'],
                    "Arn": policy['Arn'],
                    "Type": "CUSTOMER_MANAGED_POLICY"
                }
                try:
                    oldest_version_id, limit_reached = check_if_reached_versions_limit(policy)
                    if limit_reached:
                        policy_arn = policy['Arn']
                        delete_oldest_version_in_customer_managed_policy(iam_client_, policy_arn, oldest_version_id)
                    update_customer_managed_policy_with_cleaned_document(iam_client_, policy, policy_document)
                    report["Status"] = "SUCCESS"
                    execution_result.summary_report.success_report.append(report)
                    LOGGER.info(
                        f"Successfully rolled back policy. PolicyName = {policy['PolicyName']}, "
                        f"PolicyType = Customer_Managed_Policy, PolicyId = {policy['PolicyId']}, "
                        f"Account = {account_id}.")
                except Exception as e:
                    report["Status"] = "FAILURE"
                    report["ErrorMessage"] = f"{type(e).__name__}: {e}"
                    LOGGER.error(
                        f"Failed rolling back policy. PolicyName = {policy['PolicyName']}, "
                        f"PolicyType = Customer_Managed_Policy, PolicyId = {policy['PolicyId']}, "
                        f"Account = {account_id}, Error = {e}")
                    execution_result.summary_report.failure_report.append(report)
    return execution_result


def check_if_reached_versions_limit(policy, max_limit=5):
    limit_reached = True
    policy_versions = policy['PolicyVersionList']
    if len(policy_versions) < max_limit:
        return None, limit_reached is not True
    policy_version_ids = [version['VersionId'] for version in policy_versions if not version["IsDefaultVersion"]]
    policy_version_ids.sort(reverse=True)
    return policy_version_ids.pop(), limit_reached


def delete_oldest_version_in_customer_managed_policy(iam_client_, policy_arn, oldest_version_id_):
    iam_client_.delete_policy_version(PolicyArn=policy_arn, VersionId=oldest_version_id_)


def rollback_user_inline_policies(iam_client_, account_id):
    LOGGER.info("Scanning for User Inline Policies")
    execution_result = RollbackPoliciesExecutionResult()
    for users in IamHelper.get_users(iam_client_):
        for user in users:
            if 'UserPolicyList' in user:
                user_name = user['UserName']
                # a user can have multiple inline policies
                for user_policy in user['UserPolicyList']:
                    policy_document, should_update = \
                        clean_up_suggested_inline_statements(user_policy['PolicyDocument'])
                    if should_update:
                        report = {
                            "Account": account_id,
                            "UserName": user_name,
                            "UserId": user['UserId'],
                            "Arn": user['Arn'],
                            "PolicyName": user_policy['PolicyName'],
                        }
                        try:
                            update_inline_policy_with_cleaned_document(iam_client_,
                                                                       user_policy['PolicyName'],
                                                                       user_name,
                                                                       policy_document)
                            report["Status"] = "SUCCESS"
                            execution_result.summary_report.success_report.append(report)
                            LOGGER.info(
                                f"Successfully rolled back policy. PolicyName = {user_policy['PolicyName']}, "
                                f"UserName = {user_name}, UserId = {user['UserId']}, Account = {account_id}.")
                        except Exception as e:
                            report["Status"] = "FAILURE"
                            report["ErrorMessage"] = f"{type(e).__name__}: {e}"
                            LOGGER.error(
                                f"Failed rolling back policy. PolicyName = {user_policy['PolicyName']}, "
                                f"UserName = {user_name}, UserId = {user['UserId']}, Account = {account_id}, "
                                f"Error = {e}")
                            execution_result.summary_report.failure_report.append(report)
    return execution_result


def rollback_scp_policies(org_client_, account_id):
    LOGGER.info("Scanning for SCPs")
    execution_result = RollbackPoliciesExecutionResult()
    for policies in OrgHelper.get_all_scps(org_client_):
        for policy in policies:
            policy_id = policy['Id']
            policy_document = OrgHelper.get_scp(org_client_, policy_id)
            updated_policy_document, should_update = \
                clean_up_suggested_inline_statements(policy_document)
            if should_update:
                report = {
                    "Account": account_id,
                    "Name": policy['Name'],
                    "Id": policy_id,
                    "Arn": policy['Arn'],
                    "Type": policy['Type'],
                }
                try:
                    OrgHelper.update_scp(org_client_, policy_id, updated_policy_document)
                    report["Status"] = "SUCCESS"
                    execution_result.summary_report.success_report.append(report)
                    LOGGER.info(
                        f"Successfully rolled back policy. PolicyName = {policy['Name']}, "
                        f"PolicyType = Service_Control_Policy, PolicyId = {policy_id}, Account = {account_id}.")
                except Exception as e:
                    report["Status"] = "FAILURE"
                    report["ErrorMessage"] = f"{type(e).__name__}: {e}"
                    execution_result.summary_report.failure_report.append(report)
                    LOGGER.error(
                        f"Failed rolling back policy. PolicyName = {policy['Name']}, "
                        f"PolicyType = Service_Control_Policy, PolicyId = {policy_id}, Account = {account_id}, "
                        f"Error = {e}")
    return execution_result


def rollback_permission_sets(sso_admin_client, account_id) -> RollbackPoliciesExecutionResult:
    LOGGER.info("Scanning for Permission Sets")
    execution_result = RollbackPoliciesExecutionResult()
    instance_arns = IdentityCenterHelper.get_all_instance_arns(sso_admin_client)
    for instance_arn in instance_arns:
        permission_set_arns = IdentityCenterHelper.get_all_permission_set_arns(sso_admin_client, instance_arn)
        for permission_set_arn in permission_set_arns:
            policy_document = IdentityCenterHelper.get_inline_policy_for_permission_set(sso_admin_client, instance_arn,
                                                                                        permission_set_arn)
            if policy_document:
                updated_policy_document, should_update = \
                    clean_up_suggested_inline_statements(policy_document)
                if should_update:
                    policy_name = IdentityCenterHelper.get_permission_set_name(sso_admin_client, instance_arn,
                                                                               permission_set_arn)
                    try:
                        IdentityCenterHelper.update_inline_policy_for_permission_set(sso_admin_client, instance_arn,
                                                                                     permission_set_arn,
                                                                                     updated_policy_document)
                        request_id = IdentityCenterHelper.provision_permission_set_and_get_request_id(sso_admin_client,
                                                                                                      instance_arn,
                                                                                                      permission_set_arn)
                        execution_result.permission_set_provision_requests.append(
                            PermissionSetProvisionRequest(account_id, instance_arn, policy_name, request_id))
                        LOGGER.info(f"Successfully triggered permission set rollback. PermissionSetName = {policy_name}, "
                                    f"InstanceArn = {instance_arn}, Account = {account_id}")
                    except Exception as e:
                        LOGGER.error(
                            f"Failed rolling back permission set. PermissionSetName = {policy_name}, "
                            f"InstanceArn = {instance_arn}, Account = {account_id}, Error = {e}")
                        execution_result.summary_report.failure_report.append({
                            "Account": account_id,
                            "PolicyName": policy_name,
                            "Type": PolicyType.PermissionSet.value,
                            "IAMIdentityCenterInstanceArn": instance_arn,
                            "Status": "FAILURE",
                            "ErrorMessage": f"{type(e).__name__}: {e}"
                        })

    return execution_result


def rollback_group_inline_policies(iam_client_, account_id):
    LOGGER.info("Scanning for Group Inline Policies")
    execution_result = RollbackPoliciesExecutionResult()
    for groups in IamHelper.get_groups(iam_client_):
        for group in groups:
            if 'GroupPolicyList' in group:
                group_name = group['GroupName']
                for group_policy in group['GroupPolicyList']:
                    updated_policy_document, should_update = \
                        clean_up_suggested_inline_statements(group_policy['PolicyDocument'])
                    if should_update:
                        report = {
                            "Account": account_id,
                            "GroupName": group_name,
                            "GroupId": group['GroupId'],
                            "Arn": group['Arn'],
                            "PolicyName": group_policy['PolicyName'],
                        }
                        try:
                            IamHelper.update_inline_policy(iam_client_,
                                                           PolicyType.GroupInlinePolicy.value,
                                                           group_policy['PolicyName'],
                                                           group_name,
                                                           updated_policy_document)
                            report["Status"] = "SUCCESS"
                            execution_result.summary_report.success_report.append(report)
                            LOGGER.info(
                                f"Successfully rolled back policy. PolicyName = {group_policy['PolicyName']}, "
                                f"GroupName = {group_name}, GroupId = {group['GroupId']}, Account = {account_id}.")
                        except Exception as e:
                            report["Status"] = "FAILURE"
                            report["ErrorMessage"] = f"{type(e).__name__}: {e}"
                            LOGGER.error(
                                f"Failed rolling back policy. PolicyName = {group_policy['PolicyName']}, "
                                f"GroupName = {group_name}, GroupId = {group['GroupId']}, Account = {account_id}, "
                                f"Error = {e}")
                            execution_result.summary_report.failure_report.append(report)
    return execution_result


def rollback_role_inline_policies(iam_client_, account_id):
    LOGGER.info("Scanning for Role Inline Policies")
    execution_result = RollbackPoliciesExecutionResult()
    for roles in IamHelper.get_roles(iam_client_):
        for role in roles:
            if not is_sso_role(role['RoleName']) and 'RolePolicyList' in role:
                role_name = role['RoleName']
                for role_policy in role['RolePolicyList']:
                    updated_policy_document, should_update = \
                        clean_up_suggested_inline_statements(role_policy['PolicyDocument'])
                    if should_update:
                        report = {
                            "Account": account_id,
                            "RoleName": role_name,
                            "RoleId": role['RoleId'],
                            "Arn": role['Arn'],
                            "PolicyName": role_policy['PolicyName'],
                        }
                        try:
                            IamHelper.update_inline_policy(iam_client_,
                                                           PolicyType.RoleInlinePolicy.value,
                                                           role_policy['PolicyName'],
                                                           role_name,
                                                           updated_policy_document)
                            report["Status"] = "SUCCESS"
                            execution_result.summary_report.success_report.append(report)
                            LOGGER.info(
                                f"Successfully rolled back policy. PolicyName = {role_policy['PolicyName']}, "
                                f"RoleName = {role_name}, RoleId = {role['RoleId']}, Account = {account_id}.")
                        except Exception as e:
                            report["Status"] = "FAILURE"
                            report["ErrorMessage"] = f"{type(e).__name__}: {e}"
                            LOGGER.error(
                                f"Failed rolling back policy. PolicyName = {role_policy['PolicyName']}, "
                                f"RoleName = {role_name}, RoleId = {role['RoleId']}, Account = {account_id}, "
                                f"Error = {e}")
                            execution_result.summary_report.failure_report.append(report)
    return execution_result


def is_suggested_policy_statement(statement):
    if 'Sid' in statement and 'BillingConsolePolicyMigrator' in statement['Sid']:
        return True
    return False


def clean_up_suggested_customer_managed_statements_if_found_any(policy: dict):
    # there is only default version in policy version list
    # this function finds it and cleans it up
    should_update = True
    for policy_version in policy['PolicyVersionList']:
        if not policy_version['IsDefaultVersion']:  # which means it is not in use
            continue
        policy_document = policy_version['Document']
        old_statements = (policy_document['Statement']
                          if isinstance(policy_document['Statement'], list)
                          else [policy_document['Statement']])
        new_statements = []
        for statement in old_statements:
            if is_suggested_policy_statement(statement):
                continue
            else:
                new_statements.append(statement)
        rearrange_policy_statements(policy_document, new_statements)
        if suggested_statements_found_and_removed(new_statements, old_statements):
            return policy_document, should_update
    return None, False


def clean_up_suggested_inline_statements(policy_document_: dict):
    new_statements = []
    old_statements = (policy_document_['Statement']
                      if isinstance(policy_document_['Statement'], list)
                      else [policy_document_['Statement']])
    should_update = True
    for statement in old_statements:
        if is_suggested_policy_statement(statement):
            continue
        else:
            new_statements.append(statement)
    if len(new_statements) != len(policy_document_['Statement']):
        rearrange_policy_statements(policy_document_, new_statements)
        return policy_document_, should_update
    return None, False


def update_inline_policy_with_cleaned_document(iam_client_,
                                               policy_name_: str,
                                               iam_identity_name_: str,
                                               policy_document_: dict):
    iam_client_.put_user_policy(
        UserName=iam_identity_name_,
        PolicyName=policy_name_,
        PolicyDocument=json.dumps(policy_document_)
    )


def rearrange_policy_statements(policy_document_: dict, new_statements_: list):
    policy_document_['Statement'] = new_statements_


def suggested_statements_found_and_removed(new_statements_: list, old_statements_: list):
    return len(new_statements_) != len(old_statements_)


def update_customer_managed_policy_with_cleaned_document(iam_client_, policy_: dict, policy_document_: dict):
    iam_client_.create_policy_version(
        PolicyArn=policy_['Arn'],
        PolicyDocument=json.dumps(policy_document_),
        SetAsDefault=True
    )


if __name__ == '__main__':
    main()

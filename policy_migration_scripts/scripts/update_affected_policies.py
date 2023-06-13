# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import argparse
import datetime
import json
import os.path
import re
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from botocore.exceptions import ClientError

# Add project root to sys path so that interpreter is able to find our package and modules
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
sys.path.append(project_root)

from policy_migration_scripts.utils.constants import MAX_WORKERS, MEMBER_ACCOUNT_ROLE_NAME
from policy_migration_scripts.utils.hashing import generate_policy_hash, normalize_policy
from policy_migration_scripts.utils.iam import IamHelper
from policy_migration_scripts.utils.log import get_logger
from policy_migration_scripts.utils.model import PolicyType, ValidationException
from policy_migration_scripts.utils.org import OrgHelper
from policy_migration_scripts.utils.utils import is_impacted_action, is_policy_migrated
from policy_migration_scripts.utils.validation import validate_if_being_run_by_payer_account

LOGGER = get_logger(__name__)


def validate(affected_policies_data, org_accounts):
    """ Validations """
    LOGGER.info("Validating input data...")
    if not affected_policies_data:
        raise ValidationException("Input file 'affected_policies_and_suggestions.json' is empty")

    group_names = set()  # type: ignore
    for affected_policy in affected_policies_data:
        if 'AccountsScanned' in affected_policy:
            validate_metadata(affected_policy)
        else:
            validate_group_name(affected_policy, group_names)
            validate_impacted_policies(affected_policy, org_accounts)
            validate_impacted_policy_statements(affected_policy)
            validate_suggested_policy_statements(affected_policy)

    LOGGER.info("Finished validating input data")


def validate_metadata(metadata):
    """ Validate the metadata section of input data """
    accounts_scanned = metadata.get('AccountsScanned')
    if not accounts_scanned:
        raise ValidationException("Invalid data: 'AccountsScanned' field is missing in metadata")
    if 'TotalAffectedAccounts' not in metadata:
        raise ValidationException("Invalid data: 'TotalAffectedAccounts' field is missing in metadata")
    if 'TotalAffectedPolicies' not in metadata:
        raise ValidationException("Invalid data: 'TotalAffectedPolicies' field is missing in metadata")
    if 'TotalSimilarPolicyGroups' not in metadata:
        raise ValidationException("Invalid data: 'TotalSimilarPolicyGroups' field is missing in metadata")


def validate_group_name(affected_policy, group_names):
    """ A unique GroupName must exist """
    group_name = affected_policy.get('GroupName')
    if not group_name:
        raise ValidationException("Invalid data: 'GroupName' field is missing")
    if group_name in group_names:
        raise ValidationException(f"Invalid data: Duplicate `GroupName` found with value {group_name}")
    group_names.add(group_name)


def validate_impacted_policies(affected_policy, org_accounts):
    """ Validate 'ImpactedPolicies' section of the group """
    group_name = affected_policy['GroupName']
    impacted_policies = affected_policy.get('ImpactedPolicies')
    if not impacted_policies:
        raise ValidationException(f"Invalid data: 'ImpactedPolicies' field is missing for Group {group_name}")
    for impacted_policy in impacted_policies:
        validate_account_id(impacted_policy, group_name, org_accounts)
        validate_policy_info(impacted_policy, group_name)


def validate_suggested_policy_statements(affected_policy):
    """ Validate 'SuggestedPolicyStatementsToAppend' section of the group """
    group_name = affected_policy['GroupName']
    suggested_policy_statements = affected_policy.get('SuggestedPolicyStatementsToAppend')
    if not suggested_policy_statements:
        raise ValidationException(
            f"Invalid data: 'SuggestedPolicyStatementsToAppend' field is missing for Group {group_name}")
    new_actions_prefix = {'account', 'billing', 'ce', 'consolidatedbilling', 'cur', 'freetier', 'invoicing', 'payments',
                          'tax', 'purchase-orders'}
    for statement in suggested_policy_statements:
        sid = statement.get('Sid')
        if not sid:
            raise ValidationException(
                f"Invalid data: 'Sid' is missing in SuggestedPolicyStatementsToAppend for Group {group_name}")
        if not sid.startswith('BillingConsolePolicyMigrator'):
            raise ValidationException(
                f"Invalid data: 'Sid' {sid} doesn't have the prefix 'BillingConsolePolicyMigrator' in "
                f"SuggestedPolicyStatementsToAppend for Group {group_name}")
        actions = extract_actions_from_policy_statement(statement)
        for action in actions:
            prefix = action.split(':')[0]
            # Checking prefix instead of full action name since customers can tweak the suggestions as per their needs,
            #   and we need to flexible enough to accommodate wildcards.
            if prefix not in new_actions_prefix:
                raise ValidationException(
                    f"Invalid data: SuggestedPolicyStatementsToAppend in Group {group_name} contains action(s) not in "
                    f"scope of this migration")


def validate_impacted_policy_statements(affected_policy):
    """ Validate 'ImpactedPolicyStatements' section of the group """
    group_name = affected_policy['GroupName']
    impacted_statements = affected_policy.get('ImpactedPolicyStatements')
    if not impacted_statements:
        raise ValidationException(
            f"Invalid data: 'ImpactedPolicyStatements' field is missing for Group {group_name}")
    for statement in impacted_statements:
        actions = extract_actions_from_policy_statement(statement)
        if not actions:
            raise ValidationException(
                f"Invalid data: ImpactedPolicyStatements in Group {group_name} has empty action list")
        if not contains_only_impacted_actions(actions):
            raise ValidationException(
                f"Invalid data: ImpactedPolicyStatements in Group {group_name} should only contain actions that are "
                f"being deprecated")


def contains_only_impacted_actions(actions):
    """
    Checks if the input list contains only the actions that we are deprecating and no other unrelated IAM actions
    """
    for action in actions:
        if not is_impacted_action(action):
            return False
    return True


def validate_policy_info(impacted_policy, group_name):
    """ Validate policy metadata is present in the input """
    policy_name = impacted_policy.get('PolicyName')
    if not policy_name:
        raise ValidationException(
            f"Invalid data: 'PolicyName' field is missing in ImpactedPolicies for Group {group_name}")
    policy_type = impacted_policy.get('PolicyType')
    if not policy_type:
        raise ValidationException(
            f"Invalid data: 'PolicyType' field is missing for PolicyName {policy_name} in Group {group_name}")
    if policy_type not in PolicyType.list():
        raise ValidationException(
            f"Invalid data: 'PolicyType' should be one of: {PolicyType.list()}, but found {policy_type} "
            f"for policy {policy_name} and Group {group_name}")
    if 'PolicyIdentifier' not in impacted_policy:
        raise ValidationException(
            f"Invalid data: 'PolicyIdentifier' field is missing for PolicyName {policy_name} in Group {group_name}")


def validate_account_id(impacted_policy, group_name, org_accounts):
    """ Validate Accounts IDs specified in the input """
    account = impacted_policy.get('Account')
    if not account:
        raise ValidationException(
            f"Invalid data: 'Account' field is missing in ImpactedPolicies for Group {group_name}")
    r = re.compile(r'^\d{12}$')
    if not r.match(account):
        raise ValidationException(
            f"Invalid account ID - {account} in Group {group_name}. Please provide a valid 12 digit AWS account")
    if account not in org_accounts:
        raise ValidationException(
            f"Invalid data: account {account} in Group {group_name} is not part of the caller's AWS organization")


def validate_input_directory(input_directory):
    """ Validate input directory exists and contains the file having affected policies and suggestions """
    LOGGER.info("Validating input directory: %s", input_directory)

    if not os.path.exists(input_directory):
        raise ValidationException(f"Path {input_directory} does not exist")
    if not os.path.isdir(input_directory):
        raise ValidationException(f"{input_directory} is not a directory. "
                                  f"Please provide absolute path to the directory containing the affected policies file")
    file_names = os.listdir(input_directory)
    if not file_names:
        raise ValidationException(f"Input directory {input_directory} is empty")

    if 'affected_policies_and_suggestions.json' not in file_names:
        raise ValidationException(
            f"Input directory {input_directory} is missing the file 'affected_policies_and_suggestions.json'")


def update_policies_and_get_error_report(sts_client, org_client, caller_account, affected_policies_group):
    """
    Update all policies in the input file with the corresponding suggestions and return all failures encountered
    during this process
    """
    error_report = []  # type: ignore

    # Skip metadata
    if 'AccountsScanned' in affected_policies_group:
        return error_report

    group_name = affected_policies_group['GroupName']
    LOGGER.info("Starting to update policies in Group %s", group_name)

    for impacted_policy in affected_policies_group['ImpactedPolicies']:
        account = impacted_policy['Account']
        policy_type = impacted_policy['PolicyType']
        policy_name = impacted_policy['PolicyName']
        policy_identifier = impacted_policy['PolicyIdentifier']
        try:
            if account == caller_account:
                iam_client = boto3.client('iam')
            else:
                assumed_role_object = sts_client.assume_role(
                    RoleArn=f'arn:aws:iam::{account}:role/{MEMBER_ACCOUNT_ROLE_NAME}',
                    RoleSessionName=f"AssumeRoleSession{uuid.uuid4()}"
                )
                credentials = assumed_role_object['Credentials']
                iam_client = boto3.client(
                    'iam',
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken'],
                )
            policy_document = get_policy(iam_client, org_client, policy_type, policy_name, policy_identifier)
            if is_policy_migrated(policy_document):
                LOGGER.warning(f"Skipped updating policy. PolicyName = {policy_name}, PolicyType = {policy_type}, "
                               f"PolicyIdentifier = {policy_identifier}, Account = {account}, "
                               f"Reason = Policy already migrated")
                error_report.append({
                    "GroupName": group_name,
                    "Account": account,
                    "PolicyType": policy_type,
                    "PolicyName": policy_name,
                    "PolicyIdentifier": policy_identifier,
                    "Status": "SKIPPED",
                    "ErrorMessage": "Policy has Sid with prefix `BillingConsolePolicyMigrator`. We consider this as "
                                    "migrated. If you wish to update this policy again, please refer to the FAQ"
                })
                continue
            if is_policy_changed(policy_document, affected_policies_group['ImpactedPolicyStatements']):
                LOGGER.warning(f"Skipped updating policy. PolicyName = {policy_name}, PolicyType = {policy_type}, "
                               f"PolicyIdentifier = {policy_identifier}, Account = {account}, "
                               f"Reason = Impacted policy statements have changed")
                error_report.append({
                    "GroupName": group_name,
                    "Account": account,
                    "PolicyType": policy_type,
                    "PolicyName": policy_name,
                    "PolicyIdentifier": policy_identifier,
                    "Status": "SKIPPED",
                    "ErrorMessage": "Impacted policy statements in the policy have changed since the last run of "
                                    "identify_affected_policies.py script. Please re-run the identify script followed "
                                    "by update script"
                })
                continue
            update_policy_document(policy_document, affected_policies_group['SuggestedPolicyStatementsToAppend'])
            update_policy(iam_client, org_client, policy_type, policy_name, policy_identifier, policy_document)
            LOGGER.info(f"Successfully updated policy. PolicyName = {policy_name}, PolicyType = {policy_type}, "
                        f"PolicyIdentifier = {policy_identifier}, Account = {account}")
        except ClientError as err:
            LOGGER.error(f"Failed updating policy. PolicyName = {policy_name}, PolicyType = {policy_type}, "
                         f"PolicyIdentifier = {policy_identifier}, Account = {account}, "
                         f"Error = {err}")
            error_msg = f"{err.response['Error']['Code']}: {err.response['Error']['Message']}"
            error_report.append({
                "GroupName": group_name,
                "Account": account,
                "PolicyType": policy_type,
                "PolicyName": policy_name,
                "UserOrGroupOrRoleName": policy_identifier,
                "Status": "FAILURE",
                "ErrorMessage": error_msg
            })
        except Exception as err:
            LOGGER.error(f"Failed updating policy. PolicyName = {policy_name}, PolicyType = {policy_type}, "
                         f"PolicyIdentifier = {policy_identifier}, Account = {account}, "
                         f"Error = {err}")
            error_msg = f"{type(err).__name__}: {err}"
            error_report.append({
                "GroupName": group_name,
                "Account": account,
                "PolicyType": policy_type,
                "PolicyName": policy_name,
                "UserOrGroupOrRoleName": policy_identifier,
                "Status": "FAILURE",
                "ErrorMessage": error_msg
            })

    LOGGER.info("Finished updating policies in Group %s", group_name)
    return error_report


def get_policy(iam_client, org_client, policy_type, policy_name, policy_identifier):
    """ Fetches the latest policy document for the input policy """
    if policy_type == PolicyType.CustomerManagedPolicy.value:
        return get_managed_policy(iam_client, policy_identifier)
    elif PolicyType.is_inline_policy(policy_type):
        return get_inline_policy(iam_client, policy_type, policy_name, policy_identifier)
    elif policy_type == PolicyType.SCP.value:
        return OrgHelper.get_scp(org_client, policy_identifier)
    else:
        raise Exception(f"Failed to get policy. Reason: unknown policy type: {policy_type}")


def is_policy_changed(current_policy_document, prior_impacted_statements):
    """
    Additional check enforced to see if an affected policy has changed from when the Identify script was last run.
    This is mostly to avoid time-of-check to time-of-use software bug.
    """
    normalized_current_policy = normalize_policy(current_policy_document)
    current_policy_hash = generate_policy_hash(normalized_current_policy)
    prior_policy_hash = generate_policy_hash({'Statement': prior_impacted_statements})
    return current_policy_hash != prior_policy_hash


def extract_actions_from_policy_statement(statement):
    """ Return the list of IAM actions used in the input policy statement """
    if 'Action' in statement:
        actions = statement['Action'] if isinstance(statement['Action'], list) else [statement['Action']]
    else:
        actions = statement['NotAction'] if isinstance(statement['NotAction'], list) else [statement['NotAction']]
    return actions


def update_policy(iam_client, org_client, policy_type, policy_name, policy_identifier, policy_document):
    """ Updates the policy with the new policy document """
    if policy_type == PolicyType.CustomerManagedPolicy.value:
        update_managed_policy(iam_client, policy_identifier, policy_document)
    elif PolicyType.is_inline_policy(policy_type):
        IamHelper.update_inline_policy(iam_client, policy_type, policy_name, policy_identifier, policy_document)
    elif policy_type == PolicyType.SCP.value:
        OrgHelper.update_scp(org_client, policy_identifier, policy_document)
    else:
        raise Exception(f"Failed to update policy. Reason: Unknown policy type: {policy_type}")


def write_error_report(error_report):
    """
    Write the Error Report as JSON file to local file system. This file will contain all the failures encountered
    when updating the affected policies.
    """
    LOGGER.error("Encountered errors when updating affected policies")
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H-%M-%S-%f")
    filename = f'UpdateAffectedPolicies-ErrorReport-{timestamp}.json'
    with open(filename, 'w') as fp:
        json.dump(error_report, fp, indent=4)
    LOGGER.error(f"Error report written to file {filename}. Please review the errors and refer to FAQ on next steps")


def update_policy_document(original, additions):
    """ Appends the additional policy statements to the original policy statements. This is an in-place update."""
    policy_statement = original['Statement'] if isinstance(original['Statement'], list) else [
        original['Statement']]
    policy_statement.extend(additions)
    original['Statement'] = policy_statement


def get_managed_policy(iam_client, policy_arn):
    """ Given a managed policy ARN, fetch and return the latest policy document """
    response = iam_client.get_policy(PolicyArn=policy_arn)
    version_id = response['Policy']['DefaultVersionId']
    response = iam_client.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=version_id
    )
    return response['PolicyVersion']['Document']


def update_managed_policy(iam_client, policy_arn, policy_document):
    """ Updates the managed policy with the specified policy document """
    version_to_delete = get_managed_policy_version_to_delete(iam_client, policy_arn)
    if version_to_delete:
        iam_client.delete_policy_version(PolicyArn=policy_arn, VersionId=version_to_delete)
    iam_client.create_policy_version(
        PolicyArn=policy_arn,
        PolicyDocument=json.dumps(policy_document),
        SetAsDefault=True
    )


def get_managed_policy_version_to_delete(iam_client, policy_arn):
    """
    Managed policy can only have 5 versions. So before creating a new version, we need to delete the oldest version
    which is not the default version ID. If there are less than 5 version, then return None
    """
    result = []
    response = iam_client.list_policy_versions(PolicyArn=policy_arn)
    result.extend(response['Versions'])
    while response['IsTruncated']:
        response = iam_client.list_policy_versions(PolicyArn=policy_arn, Marker=response['Marker'])
        result.extend(response['Versions'])
    if len(result) < 5:
        return None
    versions = list(filter(lambda x: x['IsDefaultVersion'] is False, result))
    version_ids = list(map(lambda x: x['VersionId'], versions))
    version_ids.sort(reverse=True)
    return version_ids.pop()


def get_inline_policy(iam_client, policy_type, policy_name, iam_identity_name):
    """ Fetch and return the latest policy document of the specified inline policy """
    if policy_type == PolicyType.UserInlinePolicy.value:
        response = iam_client.get_user_policy(UserName=iam_identity_name, PolicyName=policy_name)
    elif policy_type == PolicyType.GroupInlinePolicy.value:
        response = iam_client.get_group_policy(GroupName=iam_identity_name, PolicyName=policy_name)
    elif policy_type == PolicyType.RoleInlinePolicy.value:
        response = iam_client.get_role_policy(RoleName=iam_identity_name, PolicyName=policy_name)
    else:
        raise Exception(
            f"Failed to fetch inline policy for {policy_name}. Policy type {policy_type} is not Inline policy")
    return response['PolicyDocument']


def main():
    args = parse_args()
    input_directory = args.input_directory
    LOGGER.info("Running update script with argument: %s", input_directory)

    sts_client = boto3.client('sts')
    org_client = boto3.client('organizations')
    caller_account = sts_client.get_caller_identity()['Account']
    LOGGER.info("Caller account: %s", caller_account)

    validate_if_being_run_by_payer_account(org_client, caller_account)

    validate_input_directory(input_directory)

    affected_policies_file = os.path.join(input_directory, 'affected_policies_and_suggestions.json')

    with open(affected_policies_file, 'r') as fp:
        affected_policies_data = json.load(fp)

    org_accounts = OrgHelper.get_all_org_accounts(org_client)

    validate(affected_policies_data, org_accounts)

    error_report = []

    num_of_workers = min(len(affected_policies_data), MAX_WORKERS)
    LOGGER.info("Number of worker threads used: %s", num_of_workers)
    with ThreadPoolExecutor(max_workers=num_of_workers) as executor:
        futures = [
            executor.submit(update_policies_and_get_error_report, sts_client, org_client, caller_account,
                            affected_policy_group)
            for affected_policy_group in affected_policies_data]
        for future in as_completed(futures):
            error_report.extend(future.result())

    if error_report:
        write_error_report(error_report)
    else:
        LOGGER.info("Successfully updated all policies")

    LOGGER.info("Done")


def parse_args():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        "--affected-policies-directory",
        dest="input_directory",
        required=True,
        type=str,
        help="Absolute path to the directory containing affected policy file(s). This is the output of "
             "identify_affected_policies.py script",
    )
    args = arg_parser.parse_args()
    return args


if __name__ == '__main__':
    main()

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import argparse
import datetime
import json
import os
import re
import sys
from copy import deepcopy

import boto3

# Add project root to sys path so that interpreter is able to find our package and modules
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
sys.path.append(project_root)

from policy_migration_scripts.utils.hashing import generate_policy_hash, normalize_policy
from policy_migration_scripts.utils.iam import IamHelper
from policy_migration_scripts.utils.log import get_logger
from policy_migration_scripts.utils.model import PolicyType
from policy_migration_scripts.utils.org import OrgHelper
from policy_migration_scripts.utils.utils import (
    get_default_old_to_new_action_map,
    is_policy_migrated,
)
from policy_migration_scripts.utils.validation import (
    validate_if_being_run_by_payer_account,
    validate_org_accounts,
)

LOGGER = get_logger(__name__)


class Maps:
    def __init__(self):
        self.policy_id_to_original = {}
        self.policy_id_to_impacted_statements = {}
        self.policy_id_to_metadata = {}
        self.policy_id_to_hash = {}
        self.policy_hash_to_policy_ids: dict = {}
        self.policy_hash_to_suggested_replacements = {}


def identify_affected_policies(maps, caller_account, account_pool, action_mapping):
    for account in account_pool:
        LOGGER.info(f'Running with account: {account}')
        LOGGER.info('Identifying affected policies...')

        identify_affected_customer_managed_policies(maps, caller_account, account, action_mapping)
        identify_affected_user_inline_policies(maps, caller_account, account, action_mapping)
        identify_affected_group_inline_policies(maps, caller_account, account, action_mapping)
        identify_affected_role_inline_policies(maps, caller_account, account, action_mapping)
        if account == caller_account:
            identify_affected_scps(maps, account, action_mapping)


def identify_affected_customer_managed_policies(maps, caller_account, account, action_mapping):
    iam_client = IamHelper.get_iam_client(account, caller_account)
    for policies in IamHelper.get_customer_managed_policies(iam_client):
        LOGGER.info(f'Scanning {len(policies)} customer managed policies')
        for policy in policies:
            for policy_version in policy['PolicyVersionList']:
                impacted_statements = []
                if policy_version['IsDefaultVersion']:  # Only process active policy version
                    policy_document = policy_version['Document']
                    if not is_policy_migrated(policy_document):
                        policy_id = policy['Arn']
                        policy_document_copy = deepcopy(policy_document)
                        statements = (policy_document['Statement']
                                      if isinstance(policy_document['Statement'], list)
                                      else [policy_document['Statement']])

                        for statement in statements:
                            deprecated_actions = get_policy_deprecated_actions(action_mapping, statement)
                            if deprecated_actions:
                                impacted_statements.append(statement)

                        if impacted_statements:
                            maps.policy_id_to_original[policy_id] = policy_document_copy
                            process_affected_policy(
                                maps,
                                action_mapping,
                                account,
                                policy_id,
                                policy['PolicyName'],
                                PolicyType.CustomerManagedPolicy.value,
                                policy_document,
                                impacted_statements
                            )


def identify_affected_user_inline_policies(maps, caller_account, account, action_mapping):
    iam_client = IamHelper.get_iam_client(account, caller_account)
    for users in IamHelper.get_users(iam_client):
        LOGGER.info(f'Scanning {len(users)} users')
        for user in users:
            if 'UserPolicyList' in user:
                for policy in user['UserPolicyList']:
                    policy_document = policy['PolicyDocument']
                    if not is_policy_migrated(policy_document):
                        impacted_statements = []
                        policy_id = f"{user['UserName']}${policy['PolicyName']}"
                        policy_document_copy = policy_document.copy()
                        statements = (policy_document['Statement']
                                      if isinstance(policy_document['Statement'], list)
                                      else [policy_document['Statement']])

                        for statement in statements:
                            deprecated_actions = get_policy_deprecated_actions(action_mapping, statement)
                            if deprecated_actions:
                                impacted_statements.append(statement)

                        if impacted_statements:
                            maps.policy_id_to_original[policy_id] = policy_document_copy
                            process_affected_policy(
                                maps,
                                action_mapping,
                                account,
                                policy_id,
                                policy['PolicyName'],
                                PolicyType.UserInlinePolicy.value,
                                policy_document,
                                impacted_statements
                            )


def identify_affected_group_inline_policies(maps, caller_account, account, action_mapping):
    iam_client = IamHelper.get_iam_client(account, caller_account)
    for groups in IamHelper.get_groups(iam_client):
        LOGGER.info(f'Scanning {len(groups)} groups')
        for group in groups:
            if 'GroupPolicyList' in group:
                for policy in group['GroupPolicyList']:
                    policy_document = policy['PolicyDocument']
                    if not is_policy_migrated(policy_document):
                        impacted_statements = []
                        policy_id = f"{group['GroupName']}${policy['PolicyName']}"
                        policy_document_copy = policy_document.copy()
                        statements = (policy_document['Statement']
                                      if isinstance(policy_document['Statement'], list)
                                      else [policy_document['Statement']])

                        for statement in statements:
                            deprecated_actions = get_policy_deprecated_actions(action_mapping, statement)
                            if deprecated_actions:
                                impacted_statements.append(statement)

                        if impacted_statements:
                            maps.policy_id_to_original[policy_id] = policy_document_copy
                            process_affected_policy(
                                maps,
                                action_mapping,
                                account,
                                policy_id,
                                policy['PolicyName'],
                                PolicyType.GroupInlinePolicy.value,
                                policy_document,
                                impacted_statements
                            )


def identify_affected_role_inline_policies(maps, caller_account, account, action_mapping):
    iam_client = IamHelper.get_iam_client(account, caller_account)
    for roles in IamHelper.get_roles(iam_client):
        LOGGER.info(f'Scanning {len(roles)} roles')
        for role in roles:
            if 'RolePolicyList' in role:
                for policy in role['RolePolicyList']:
                    policy_document = policy['PolicyDocument']
                    if not is_policy_migrated(policy_document):
                        impacted_statements = []
                        policy_id = f"{role['RoleName']}${policy['PolicyName']}"
                        policy_document_copy = policy_document.copy()
                        statements = (policy_document['Statement']
                                      if isinstance(policy_document['Statement'], list)
                                      else [policy_document['Statement']])

                        for statement in statements:
                            deprecated_actions = get_policy_deprecated_actions(action_mapping, statement)
                            if deprecated_actions:
                                impacted_statements.append(statement)

                        if impacted_statements:
                            maps.policy_id_to_original[policy_id] = policy_document_copy
                            process_affected_policy(
                                maps,
                                action_mapping,
                                account,
                                policy_id,
                                policy['PolicyName'],
                                PolicyType.RoleInlinePolicy.value,
                                policy_document,
                                impacted_statements
                            )


def identify_affected_scps(maps, account, action_mapping):
    org_client = boto3.client('organizations')
    for policies in OrgHelper.get_all_scps(org_client):
        LOGGER.info(f'Scanning {len(policies)} SCPs')
        for policy in policies:
            policy_id = policy['Id']
            response = org_client.describe_policy(PolicyId=policy_id)
            policy_document = json.loads(response['Policy']['Content'])
            if not is_policy_migrated(policy_document):
                impacted_statements = []
                policy_document_copy = policy_document.copy()
                statements = (policy_document['Statement']
                              if isinstance(policy_document['Statement'], list)
                              else [policy_document['Statement']])

                for statement in statements:
                    deprecated_actions = get_policy_deprecated_actions(action_mapping, statement)
                    if deprecated_actions:
                        impacted_statements.append(statement)

                if impacted_statements:
                    maps.policy_id_to_original[policy_id] = policy_document_copy
                    process_affected_policy(
                        maps,
                        action_mapping,
                        account,
                        policy_id,
                        response['Policy']['PolicySummary']['Name'],
                        PolicyType.SCP.value,
                        policy_document,
                        impacted_statements
                    )


def process_affected_policy(maps, action_mapping, account, policy_id, policy_name, policy_type, policy_document, impacted_statements):
    normalized_policy = normalize_policy(policy_document)
    maps.policy_id_to_impacted_statements[policy_id] = normalized_policy['Statement']
    policy_hash = generate_policy_hash(normalized_policy)
    maps.policy_id_to_hash[policy_id] = policy_hash

    if policy_hash in maps.policy_hash_to_policy_ids:
        maps.policy_hash_to_policy_ids[policy_hash].append(policy_id)
    else:
        maps.policy_hash_to_policy_ids[policy_hash] = [policy_id]

    maps.policy_id_to_metadata[policy_id] = {
        'Account': account,
        'PolicyType': policy_type,
        'PolicyName': policy_name,
    }
    maps.policy_hash_to_suggested_replacements[policy_hash] = (
        generate_suggested_policy_statement_replacements(action_mapping, impacted_statements))


def get_policy_deprecated_actions(action_mapping, policy_statement):
    actions_or_not_actions = []
    if 'Action' in policy_statement:
        actions_or_not_actions = (policy_statement['Action']
                                  if isinstance(policy_statement['Action'], list)
                                  else [policy_statement['Action']])
    elif 'NotAction' in policy_statement:
        actions_or_not_actions = (policy_statement['NotAction']
                                  if isinstance(policy_statement['NotAction'], list)
                                  else [policy_statement['NotAction']])

    deprecated_actions = set()
    for action in actions_or_not_actions:
        if action != '*':  # Skip handling statements with admin privileges
            pattern = action.replace('*', '.*').replace('?', '.?')
            r = re.compile(pattern)
            for mapped_action in action_mapping.keys():
                if r.match(mapped_action):
                    deprecated_actions.add(action)

    return list(deprecated_actions)


def generate_suggested_policy_statement_replacements(action_mapping, policy_statements):
    """
    Take in list of policy statements from an individual policy.
    Returns a list of suggested policy replacements.
    """
    replacement_statements, sid_counter = [], 0
    for statement in policy_statements:
        replacement_statement = statement.copy()
        replacement_statement['Sid'] = f'BillingConsolePolicyMigrator{sid_counter}'

        if 'Action' in statement:
            actions = (statement['Action']
                       if isinstance(statement['Action'], list)
                       else [statement['Action']])
            replacement_statement['Action'] = generate_replacement_actions_from_actions(
                action_mapping,
                actions
            )
        elif 'NotAction' in statement:
            not_actions = (statement['NotAction']
                           if isinstance(statement['NotAction'], list)
                           else [statement['NotAction']])
            replacement_statement['NotAction'] = generate_replacement_actions_from_actions(
                action_mapping,
                not_actions
            )

        replacement_statements.append(replacement_statement)
        sid_counter += 1

    return replacement_statements


def generate_replacement_actions_from_actions(action_mapping, actions: list):
    """
    Take in list of old actions and generates unique list of replacement actions.
    """
    replacement_actions = set()  # using set to prevent duplicate actions

    for action in actions:
        pattern = action.replace('*', '.*').replace('?', '.?')
        r = re.compile(pattern)
        for mapped_action in action_mapping.keys():
            if r.match(mapped_action):
                replacement_actions.update(action_mapping[mapped_action])

    replacement_actions_list = list(replacement_actions)
    replacement_actions_list.sort()

    return replacement_actions_list


def get_policy_id(policy_id, policy_type):
    '''
    Return user/group/role name for inline policies.
    policy_id is set to <UserOrGroupOrRole>$<PolicyName> during script execution
    to ensure the value is unique for hashing.
    '''
    if (
        policy_type == PolicyType.UserInlinePolicy.value
        or policy_type == PolicyType.GroupInlinePolicy.value
        or policy_type == PolicyType.RoleInlinePolicy.value
    ):
        return policy_id.split('$')[0]
    return policy_id


def generate_policy_groups_report(maps, account_pool):
    report, affected_accounts = [], set()

    for policy_id in maps.policy_id_to_metadata:
        affected_accounts.add(maps.policy_id_to_metadata[policy_id]['Account'])

    report.append({
        'AccountsScanned': account_pool,
        'TotalAffectedAccounts': len(affected_accounts),
        'TotalAffectedPolicies': len(maps.policy_id_to_impacted_statements),
        'TotalSimilarPolicyGroups': len(maps.policy_hash_to_policy_ids)
    })

    group_counter = 1
    for policy_hash in maps.policy_hash_to_policy_ids:
        impacted_policies = []
        impacted_policy_statements = []
        for policy_id in maps.policy_hash_to_policy_ids[policy_hash]:
            policy_metadata = maps.policy_id_to_metadata[policy_id]
            formatted_policy_id = get_policy_id(policy_id, policy_metadata['PolicyType'])
            impacted_policies.append({
                'Account': policy_metadata['Account'],
                'PolicyType': policy_metadata['PolicyType'],
                'PolicyName': policy_metadata['PolicyName'],
                'PolicyIdentifier': formatted_policy_id,
            })

            impacted_policy_statements.append(maps.policy_id_to_impacted_statements[policy_id])

        report.append({
            'GroupName': f"Group{group_counter}",
            'ImpactedPolicies': impacted_policies,
            'ImpactedPolicyStatements': impacted_policy_statements[0],
            'SuggestedPolicyStatementsToAppend': maps.policy_hash_to_suggested_replacements[policy_hash],
        })
        group_counter += 1

    return report


def generate_detailed_policy_report(maps):
    report = []
    for policy_id in maps.policy_id_to_original:
        policy_metadata = maps.policy_id_to_metadata[policy_id]
        formatted_policy_id = get_policy_id(policy_id, policy_metadata['PolicyType'])
        report.append({
            'Account': policy_metadata['Account'],
            'PolicyType': policy_metadata['PolicyType'],
            'PolicyName': policy_metadata['PolicyName'],
            'PolicyIdentifier': formatted_policy_id,
            'PolicyDocument': maps.policy_id_to_original[policy_id]
        })
    return report


def write_report(file_path, report):
    with open(file_path, 'w') as fp:
        json.dump(report, fp, indent=4)


def main():
    maps = Maps()
    action_mapping = {}
    args = parse_args()
    sts_client = boto3.client('sts')
    org_client = boto3.client('organizations')
    caller_account = sts_client.get_caller_identity()['Account']
    validate_if_being_run_by_payer_account(org_client, caller_account)
    LOGGER.info(f'Caller account: {caller_account}')

    if args.all and args.accounts:
        raise RuntimeError('Invalid input: cannot pass in both --all and --accounts flags')

    if args.action_mapping_config_file:
        LOGGER.info(f"Using custom action mapping config file: {args.action_mapping_config_file}")
        with open(args.action_mapping_config_file) as fp:
            action_mapping = json.load(fp)
    else:
        LOGGER.info("Using default action mapping config file")
        action_mapping = get_default_old_to_new_action_map()

    if args.all:
        LOGGER.info(f'Running in ORG mode for payer account: {caller_account}')
        account_pool = OrgHelper.get_all_org_accounts(org_client)
        if args.exclude_accounts:
            [account_pool.remove(account) for account in [args.exclude_accounts]]
            LOGGER.info(f'Excluding accounts: {args.exclude_accounts}')
    elif args.accounts:
        account_pool = [s.strip() for s in (args.accounts).split(',')]
        all_org_accounts = OrgHelper.get_all_org_accounts(org_client)
        validate_org_accounts(account_pool, caller_account, all_org_accounts)
        LOGGER.info(f'Running in LINKED ACCOUNT mode with accounts: {account_pool}')
        if args.exclude_accounts:
            raise RuntimeError('Invalid input: cannot pass in both --exclude-accounts and \
                --accounts flag')
    else:
        LOGGER.info(f'Running in PAYER ACCOUNT mode for payer account: {caller_account}')
        account_pool = [caller_account]

    identify_affected_policies(maps, caller_account, account_pool, action_mapping)

    policy_groups_report = generate_policy_groups_report(maps, account_pool)
    detailed_policy_report = generate_detailed_policy_report(maps)

    timestamp = datetime.datetime.now().strftime('%Y%m%d-%H-%M-%S-%f')
    folder_name = f'Affected_Policies_{timestamp}'
    try:
        os.makedirs(folder_name)
    except FileExistsError:
        pass

    file_path = os.path.join(folder_name, 'affected_policies_and_suggestions.json')
    write_report(file_path, policy_groups_report)
    LOGGER.info(f'Affected policy report written to {file_path}')

    file_path = os.path.join(folder_name, 'detailed_affected_policies.json')
    write_report(file_path, detailed_policy_report)
    LOGGER.info(f'Detailed policy report written to {file_path}')

    LOGGER.info('Done')


def parse_args():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        '--action-mapping-config-file',
        dest='action_mapping_config_file',
        required=False,
        type=str,
        help='Absolute path to the mapping action configuration file (mapping of old to new actions)'
    )
    arg_parser.add_argument(
        '-a', '--accounts', help='comma separated list of up to 10 AWS account IDs', type=str
    )
    arg_parser.add_argument(
        '--all', help="runs script for the entire AWS Organization", action='store_true'
    )
    arg_parser.add_argument(
        '--exclude-accounts',
        help='comma separated list of AWS account IDs to be excluded, only applies when --all flag \
            is used', type=str
    )

    args = arg_parser.parse_args()
    return args


if __name__ == '__main__':
    main()

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json

from policy_migration_scripts.utils.utils import is_impacted_action


def normalize_policy(policy, action_mapping):
    """
    Reformat policy dictionary to conform to common structure.
    Omits Version and ID policy elements.
    """
    normalized_policy = {}
    if 'Statement' in policy:
        statements = (policy['Statement']
                      if isinstance(policy['Statement'], list)
                      else [policy['Statement']])
        normalized_policy['Statement'] = normalize_statements(statements, action_mapping)
    return normalized_policy


def normalize_statements(statements, action_mapping):
    normalized_statements = []
    statements.sort(key=sid_comparator)  # sort statements by Sid
    for statement in statements:
        """
        Reformat policy statements to conform to common structure.
        Omits only Sid statement element.
        """
        actions_or_not_actions = []
        if 'Action' in statement:
            # filter impacted actions
            actions_or_not_actions = list(filter(lambda action: is_impacted_action(action, action_mapping),
                                                 (statement['Action']
                                                  if isinstance(statement['Action'], list)
                                                  else [statement['Action']])
                                                 ))
        elif 'NotAction' in statement:
            actions_or_not_actions = list(filter(lambda action: is_impacted_action(action, action_mapping),
                                                 (statement['NotAction']
                                                  if isinstance(statement['NotAction'], list)
                                                  else [statement['NotAction']])
                                                 ))

        if actions_or_not_actions:  # only consider impacted statements
            normalized_statement = {}
            actions_or_not_actions.sort()  # sort actions alphabetically

            if 'Effect' in statement:
                normalized_statement['Effect'] = statement['Effect']

            if 'Action' in statement:
                normalized_statement['Action'] = actions_or_not_actions
            elif 'NotAction' in statement:
                normalized_statement['NotAction'] = actions_or_not_actions

            if 'Condition' in statement:
                normalized_statement['Condition'] = statement['Condition']
            if 'Principal' in statement:
                normalized_statement['Principal'] = statement['Principal']
            if 'NotPrincipal' in statement:
                normalized_statement['NotPrincipal'] = statement['NotPrincipal']
            if 'Resource' in statement:
                normalized_statement['Resource'] = statement['Resource']
            if 'NotResource' in statement:
                normalized_statement['NotResource'] = statement['NotResource']

            normalized_statements.append(normalized_statement)
    return normalized_statements


def generate_policy_hash(policy_json):
    """
    Generate policy hash based on normalized json formatting.
    Some policies may have identical statements/resources that are ordered differently,
    so policy is converted to a sorted string to handle such cases.
    """
    normalized_json_str = json.dumps(policy_json)
    normalized_json_str_sorted = ''.join(sorted(normalized_json_str))
    policy_hash = hash(normalized_json_str_sorted)
    return policy_hash


def sid_comparator(statement):
    """
    Used to sort statements by Sid
    """
    if 'Sid' in statement:
        return statement['Sid']
    return ''

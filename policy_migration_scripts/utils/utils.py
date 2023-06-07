# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json
import os
import re

from policy_migration_scripts.utils.log import get_logger

LOGGER = get_logger(__name__)


def get_default_old_to_new_action_map():
    """
    Read the action mapping config file and return as dictionary.
    Config file is named 'action_mapping_config.json' and should be present under `config` directory of the package
    """
    try:
        file_path = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'config',
                                 'action_mapping_config.json')
        LOGGER.info(f"Loading default old to new action mapping file from {file_path}")
        with open(file_path, 'r') as fp:
            action_map = json.load(fp)
        return action_map
    except Exception as err:
        LOGGER.error("Failed to read the old to new action mapping config file 'action_mapping_config.json'")
        raise err


def is_policy_migrated(policy_document):
    """
    Check if the policy already has Sid with prefix `BillingConsolePolicyMigrator`. If so, we consider this policy
    to be already migrated
    """
    statements = policy_document['Statement'] if isinstance(policy_document['Statement'], list) else [
        policy_document['Statement']]
    for statement in statements:
        sid = statement.get('Sid')
        if sid and sid.startswith('BillingConsolePolicyMigrator'):
            return True
    return False


def is_impacted_action(action):
    """
    Check if the input action belongs to the list of actions being deprecated
    """
    prefix = action.split(':')[0]
    if prefix == '*':
        return False
    if prefix not in ['aws-portal', 'purchase-orders']:
        return False
    pattern = action.replace('*', '.*').replace('?', '.?')
    r = re.compile(pattern)
    for old_action in get_default_old_to_new_action_map().keys():
        if r.match(old_action):
            return True
    return False

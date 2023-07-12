# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import csv
import json
import os
import re

from policy_migration_scripts.utils.constants import ACCOUNT_ID_LENGTH
from policy_migration_scripts.utils.log import get_logger
from policy_migration_scripts.utils.model import ValidationException

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


def is_impacted_action(action, action_mapping):
    """
    Check if the input action belongs to the list of actions being deprecated.
    `action_mapping` is a dictionary of old action to the corresponding list of new actions.
    """
    prefix = action.split(':')[0]
    if prefix == '*':
        return False
    if prefix not in ['aws-portal', 'purchase-orders']:
        return False
    pattern = action.replace('*', '.*').replace('?', '.?')
    r = re.compile(pattern)
    for old_action in action_mapping.keys():
        if r.match(old_action):
            return True
    return False


def is_valid_account_id(account_id):
    return account_id.isnumeric() and len(account_id) == ACCOUNT_ID_LENGTH


def read_accounts_from_file(file_path):
    """
    Read CSV file containing AWS Account IDs and return the list of accounts
    """
    try:
        accounts = []
        LOGGER.info(f"Reading accounts from file: {file_path}")
        with open(file_path, 'r') as fp:
            rows = csv.reader(fp)
            for row in rows:
                # Skip empty rows
                if not ''.join(row).strip():
                    continue
                account_id = row[0]
                if is_valid_account_id(account_id):
                    accounts.append(account_id)
                else:
                    raise ValidationException(
                        f"Invalid data in file {file_path}.\nThe file should contain only 12 digit AWS Account IDs")
        return accounts
    except Exception as err:
        LOGGER.error(f"Failed when reading accounts from file: {file_path}")
        raise err

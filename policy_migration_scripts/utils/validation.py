# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from botocore.exceptions import ClientError

from policy_migration_scripts.utils.constants import ACCOUNT_ID_LENGTH
from policy_migration_scripts.utils.log import get_logger
from policy_migration_scripts.utils.model import ValidationException

LOGGER = get_logger(__name__)


def rollback_args_fast_validate(args_):
    if args_["accounts"]:
        if args_["include_all"]:
            raise ValidationException("no need of --all when --accounts is given")
        if args_["excluded_accounts"]:
            raise ValidationException("no need of --exclude-accounts when --accounts is given")
        for account_id in args_["accounts"]:
            _validate_account(account_id)
    if args_["excluded_accounts"]:
        if args_["include_all"] is False:
            raise ValidationException("--all must be given when --exclude-accounts is given.")
        for account_id in args_["excluded_accounts"]:
            _validate_account(account_id)


def rollback_args_deep_validate(args_, payer_account_, all_member_accounts_):
    if args_["accounts"]:
        validate_org_accounts(args_["accounts"], payer_account_, all_member_accounts_)
    if args_["excluded_accounts"]:
        validate_org_accounts(args_["excluded_accounts"], payer_account_, all_member_accounts_)


def is_valid_account_id(account_id):
    return account_id.isnumeric() and len(account_id) == ACCOUNT_ID_LENGTH


def _validate_account(account_id):
    if is_valid_account_id(account_id) is not True:
        raise ValidationException(f'Invalid input: {account_id} must be a 12 digit numeric string')


def validate_org_accounts(input_accounts, payer_account, all_member_accounts):
    # validate accounts passed in are linked accounts in payer's org
    for account in input_accounts:
        if account not in all_member_accounts:
            raise ValidationException(
                f"Invalid input: {account} is not a member of payer ({payer_account}) org")


def validate_if_being_run_by_payer_account(org_client, caller_account):
    """ Validate that the script is being run by payer account """
    try:
        response = org_client.describe_organization()
        management_account = response["Organization"]["MasterAccountId"]
        if caller_account != management_account:
            LOGGER.error("Script being run by a member account of AWS organization")
            raise ValidationException("Script can only be run by management account of an AWS Organization")

    except ClientError as err:
        if err.response["Error"]["Code"] == "AWSOrganizationsNotInUseException":
            LOGGER.error("Script being run by an account which is not part of an AWS Organization")
            raise ValidationException("Script can only be run by management account of an AWS Organization")
        else:
            raise err
    except Exception as err:
        LOGGER.error("Failed calling Organization DescribeOrganization API")
        raise err

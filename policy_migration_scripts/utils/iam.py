# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json
import uuid

import boto3

from policy_migration_scripts.utils.constants import MEMBER_ACCOUNT_ROLE_NAME
from policy_migration_scripts.utils.model import PolicyType


class IamHelper:
    @staticmethod
    def get_iam_client(account_id_, payer_account_, assume_role=MEMBER_ACCOUNT_ROLE_NAME):
        if account_id_ == payer_account_:
            iam_client = boto3.client('iam')
        else:
            sts_client = boto3.client('sts')
            assumed_role_object = sts_client.assume_role(
                RoleArn=f'arn:aws:iam::{account_id_}:role/{assume_role}',
                RoleSessionName=f'AssumeRoleSession{uuid.uuid4()}'
            )
            credentials = assumed_role_object['Credentials']
            iam_client = boto3.client(
                'iam',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
            )
        return iam_client

    @staticmethod
    def get_customer_managed_policies(iam_client_, max_items_=10):
        marker = None
        while True:
            response = IamHelper.get_response_from_iam(iam_client_, 'LocalManagedPolicy', marker, max_items_)
            yield response['Policies']
            if response['IsTruncated']:
                marker = response['Marker']
            else:
                break

    @staticmethod
    def get_users(iam_client_, max_items_=10):
        marker = None
        while True:
            response = IamHelper.get_response_from_iam(iam_client_, 'User', marker, max_items_)
            yield response['UserDetailList']
            if response['IsTruncated']:
                marker = response['Marker']
            else:
                break

    @staticmethod
    def get_roles(iam_client_, max_items_=10):
        marker = None
        while True:
            response = IamHelper.get_response_from_iam(iam_client_, 'Role', marker, max_items_)
            yield response['RoleDetailList']
            if response['IsTruncated']:
                marker = response['Marker']
            else:
                break

    @staticmethod
    def get_groups(iam_client_, max_items_=10):
        marker = None
        while True:
            response = IamHelper.get_response_from_iam(iam_client_, 'Group', marker, max_items_)
            yield response['GroupDetailList']
            if response['IsTruncated']:
                marker = response['Marker']
            else:
                break

    @staticmethod
    def get_response_from_iam(iam_client_, filter_: str, marker_, max_items_: int):
        if marker_:
            return iam_client_.get_account_authorization_details(Filter=[filter_], MaxItems=max_items_, Marker=marker_)
        else:
            return iam_client_.get_account_authorization_details(Filter=[filter_], MaxItems=max_items_)

    @staticmethod
    def update_inline_policy(iam_client, policy_type, policy_name, iam_identity_name, policy_document):
        """ Updates the inline policy with the specified policy document """
        if policy_type == PolicyType.UserInlinePolicy.value:
            iam_client.put_user_policy(
                UserName=iam_identity_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document)
            )
        elif policy_type == PolicyType.GroupInlinePolicy.value:
            iam_client.put_group_policy(
                GroupName=iam_identity_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document)
            )
        elif policy_type == PolicyType.RoleInlinePolicy.value:
            iam_client.put_role_policy(
                RoleName=iam_identity_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document)
            )
        else:
            raise Exception(
                f"Failed to update inline policy for {policy_name}. Policy type {policy_type} is not Inline policy")

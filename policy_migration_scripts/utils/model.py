# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from enum import Enum


class PolicyType(Enum):
    CustomerManagedPolicy = 'CustomerManagedPolicy'
    UserInlinePolicy = 'UserInlinePolicy'
    GroupInlinePolicy = 'GroupInlinePolicy'
    RoleInlinePolicy = 'RoleInlinePolicy'
    SCP = 'SCP'

    @classmethod
    def list(cls):
        return list(map(lambda x: x.value, cls))  # type: ignore

    @classmethod
    def is_inline_policy(cls, policy_type: str):
        inline_policies = list(filter(lambda x: 'Inline' in x, cls.list()))
        return policy_type in inline_policies


class ValidationException(Exception):
    """
    Thrown when validations fail
    """
    pass

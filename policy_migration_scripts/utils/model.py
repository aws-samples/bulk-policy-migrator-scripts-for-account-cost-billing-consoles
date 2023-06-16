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


class Maps:
    """ A collection of maps used in identify script """

    def __init__(self):
        self.policy_id_to_original = {}
        self.policy_id_to_impacted_statements = {}
        self.policy_id_to_metadata = {}
        self.policy_id_to_hash = {}
        self.policy_hash_to_policy_ids: dict = {}
        self.policy_hash_to_suggested_replacements = {}

    def __eq__(self, other):
        if not isinstance(other, Maps):
            return False
        if self.policy_id_to_original != other.policy_id_to_original:
            return False
        if self.policy_id_to_impacted_statements != other.policy_id_to_impacted_statements:
            return False
        if self.policy_id_to_metadata != other.policy_id_to_metadata:
            return False
        if self.policy_id_to_hash != other.policy_id_to_hash:
            return False
        if self.policy_hash_to_policy_ids != other.policy_hash_to_policy_ids:
            return False
        if self.policy_hash_to_suggested_replacements != other.policy_hash_to_suggested_replacements:
            return False
        return True

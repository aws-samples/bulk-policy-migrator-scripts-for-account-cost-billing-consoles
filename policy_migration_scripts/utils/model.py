# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from enum import Enum
from typing import List


class PolicyType(Enum):
    CustomerManagedPolicy = 'CustomerManagedPolicy'
    UserInlinePolicy = 'UserInlinePolicy'
    GroupInlinePolicy = 'GroupInlinePolicy'
    RoleInlinePolicy = 'RoleInlinePolicy'
    SCP = 'SCP'
    PermissionSet = 'PermissionSet'

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

    def is_empty(self):
        return len(self.policy_id_to_original) == len(self.policy_id_to_impacted_statements) == len(
            self.policy_id_to_metadata) == len(self.policy_id_to_hash) == len(self.policy_hash_to_policy_ids) == len(
            self.policy_hash_to_suggested_replacements) == 0


class PermissionSetProvisionRequest:
    def __init__(self, account, instance_arn, permission_set_name, request_id):
        self.account = account
        self.instance_arn = instance_arn
        self.permission_set_name = permission_set_name
        self.request_id = request_id


class UpdatePoliciesExecutionResult:
    def __init__(self):
        self.error_report = []
        self.permission_set_provision_requests: List[PermissionSetProvisionRequest] = []

    def is_empty(self):
        return len(self.error_report) == len(self.permission_set_provision_requests) == 0


class SummaryReport:
    """ Used in Update and Rollback scripts to capture the summary report that gets written to file as output """
    def __init__(self):
        self.failure_report = []
        self.success_report = []


class RollbackPoliciesExecutionResult:
    def __init__(self):
        self.summary_report: SummaryReport = SummaryReport()
        self.permission_set_provision_requests: List[PermissionSetProvisionRequest] = []

    def is_empty(self):
        return len(self.summary_report.success_report) == len(self.summary_report.failure_report) == len(
            self.permission_set_provision_requests) == 0

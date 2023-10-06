# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json
import time
from typing import List

from botocore.exceptions import ClientError

from policy_migration_scripts.utils.constants import (
    PERMISSION_SET_STATUS_CHECKER_RETRIES,
    PERMISSION_SET_STATUS_CHECKER_SLEEP_TIME,
)
from policy_migration_scripts.utils.log import get_logger
from policy_migration_scripts.utils.model import (
    PermissionSetProvisionRequest,
    PolicyType,
    SummaryReport,
)

LOGGER = get_logger(__name__)


class IdentityCenterHelper:
    @staticmethod
    def get_all_instance_arns(sso_admin_client):
        try:
            response = sso_admin_client.list_instances()
            result = list(map(lambda x: x['InstanceArn'], response['Instances']))
            while 'NextToken' in response and response['NextToken']:
                response = sso_admin_client.list_instances(NextToken=response['NextToken'])
                result.extend(list(map(lambda x: x['InstanceArn'], response['Instances'])))
            return result
        except ClientError as err:
            if err.response["Error"]["Code"] == "AccessDeniedException":
                LOGGER.error(
                    "AccessDeniedException when calling sso:ListInstances with Error Message = %s. Either IAM Identity "
                    "Center (SSO) is not enabled or the user does not have necessary permissions to call this API. "
                    "If you do not use IAM Identity Center (SSO), please disregard this message. Else, add the missing "
                    "permissions and re-run the script.", err.response['Error']['Message']
                )
                return []  # Returning empty list to handle scenario where Identity Center is not enabled
            else:
                raise err

    @staticmethod
    def get_all_permission_set_arns(sso_admin_client, instance_arn):
        response = sso_admin_client.list_permission_sets(InstanceArn=instance_arn)
        result = response['PermissionSets']
        while 'NextToken' in response and response['NextToken']:
            response = sso_admin_client.list_permission_sets(
                InstanceArn=instance_arn,
                NextToken=response['NextToken']
            )
            result.extend(response['PermissionSets'])
        return result

    @staticmethod
    def get_inline_policy_for_permission_set(sso_admin_client, instance_arn, permission_set_arn):
        response = sso_admin_client.get_inline_policy_for_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn
        )
        if 'InlinePolicy' in response and response['InlinePolicy']:
            policy_document = json.loads(response['InlinePolicy'])
            return policy_document
        return None

    @staticmethod
    def get_permission_set_name(sso_admin_client, instance_arn, permission_set_arn):
        response = sso_admin_client.describe_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn
        )
        return response['PermissionSet']['Name']

    @staticmethod
    def update_inline_policy_for_permission_set(sso_admin_client, instance_arn, permission_set_arn, policy_document):
        sso_admin_client.put_inline_policy_to_permission_set(
            InlinePolicy=json.dumps(policy_document),
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn
        )

    @staticmethod
    def provision_permission_set_and_get_request_id(sso_admin_client, instance_arn, permission_set_arn):
        """
        Call ProvisionPermissionSet API and return the RequestId of PermissionSetProvisioningStatus so that
        we can poll this request to monitor the provisioning status.
        """
        response = sso_admin_client.provision_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn,
            TargetType='ALL_PROVISIONED_ACCOUNTS'
        )
        return response['PermissionSetProvisioningStatus']['RequestId']

    @staticmethod
    def get_permission_set_provisioning_status(sso_admin_client, instance_arn, request_id):
        response = sso_admin_client.describe_permission_set_provisioning_status(
            InstanceArn=instance_arn,
            ProvisionPermissionSetRequestId=request_id
        )
        return response['PermissionSetProvisioningStatus']

    @staticmethod
    def get_permission_set_provisioning_status_report(
            sso_admin_client,
            permission_set_provision_requests: List[PermissionSetProvisionRequest],
            sleep_time_in_seconds=PERMISSION_SET_STATUS_CHECKER_SLEEP_TIME,
            max_retries=PERMISSION_SET_STATUS_CHECKER_RETRIES
    ) -> SummaryReport:
        """
        Check the provisioning status for the given permission set requests. If the status is still in-progress,
        pause and retry till either the status goes to success or we hit time out. Return the status report at
        the end.
        """
        summary_report = SummaryReport()
        for request in permission_set_provision_requests:
            LOGGER.info("Checking permission set provisioning status for %s", request.permission_set_name)
            provisioning_status = IdentityCenterHelper.get_permission_set_provisioning_status(
                sso_admin_client,
                request.instance_arn,
                request.request_id
            )
            retries = 0
            while provisioning_status['Status'] == 'IN_PROGRESS' and retries < max_retries:
                LOGGER.info(
                    "Permission set provisioning status still IN_PROGRESS, it can take up to %s minutes. Will check "
                    "again in %s seconds",
                    ((max_retries * sleep_time_in_seconds) // 60),
                    sleep_time_in_seconds)

                time.sleep(sleep_time_in_seconds)
                provisioning_status = IdentityCenterHelper.get_permission_set_provisioning_status(
                    sso_admin_client,
                    request.instance_arn,
                    request.request_id
                )
                retries = retries + 1
            if provisioning_status['Status'] == 'FAILED':
                LOGGER.error("Failed provisioning permission set. PermissionSetName = %s, InstanceArn = %s, "
                             "ProvisionPermissionSetRequestId = %s, FailureReason = %s", request.permission_set_name,
                             request.instance_arn, request.request_id, provisioning_status['FailureReason'])
                summary_report.failure_report.append({
                    "Account": request.account,
                    "PolicyType": PolicyType.PermissionSet.value,
                    "PolicyName": request.permission_set_name,
                    "IAMIdentityCenterInstanceArn": request.instance_arn,
                    "ProvisionPermissionSetRequestId": request.request_id,
                    "Status": "FAILED",
                    "ErrorMessage": provisioning_status['FailureReason']
                })
            elif provisioning_status['Status'] == 'IN_PROGRESS':
                LOGGER.error("Timed out verifying permission set provisioning status. PermissionSetName = %s, "
                             "InstanceArn = %s, ProvisionPermissionSetRequestId = %s. Please visit the IAM Identity "
                             "Center console to monitor and verify that the permission set provisioning is complete.",
                             request.permission_set_name, request.instance_arn, request.request_id)
                summary_report.failure_report.append({
                    "Account": request.account,
                    "PolicyType": PolicyType.PermissionSet.value,
                    "PolicyName": request.permission_set_name,
                    "IAMIdentityCenterInstanceArn": request.instance_arn,
                    "ProvisionPermissionSetRequestId": request.request_id,
                    "Status": "UNABLE_TO_VERIFY_STATUS",
                    "ErrorMessage": "Timed out verifying permission set provisioning status. Please visit the IAM "
                                    "Identity Center console to monitor and verify that the permission set "
                                    "provisioning is complete."
                })
            else:
                LOGGER.info("Successfully provisioned Permission Set = %s", request.permission_set_name)
                summary_report.success_report.append({
                    "Account": request.account,
                    "PolicyType": PolicyType.PermissionSet.value,
                    "PolicyName": request.permission_set_name,
                    "IAMIdentityCenterInstanceArn": request.instance_arn,
                    "Status": "SUCCEEDED"
                })
        return summary_report

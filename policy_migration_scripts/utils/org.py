# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json


class OrgHelper:
    @staticmethod
    def get_all_org_accounts(org_client_):
        result = []
        response = org_client_.list_accounts()
        result.extend(list(map(lambda x: x['Id'], response['Accounts'])))
        while 'NextToken' in response and response['NextToken']:
            response = org_client_.list_accounts(NextToken=response['NextToken'])
            result.extend(list(map(lambda x: x['Id'], response['Accounts'])))
        return result

    @staticmethod
    def get_all_scps(org_client_, max_items_=10):
        response = org_client_.list_policies(Filter='SERVICE_CONTROL_POLICY', MaxResults=max_items_)
        yield response['Policies']
        while 'NextToken' in response and response['NextToken']:
            response = org_client_.list_policies(
                Filter='SERVICE_CONTROL_POLICY',
                MaxResults=max_items_,
                NextToken=response['NextToken']
            )
            yield response['Policies']

    @staticmethod
    def get_scp(org_client, policy_id):
        """ Fetch and return the latest policy document of the specified SCP """
        response = org_client.describe_policy(PolicyId=policy_id)
        return json.loads(response['Policy']['Content'])

    @staticmethod
    def update_scp(org_client, policy_id, policy_document):
        """" Updates the SCP with the specified policy document"""
        org_client.update_policy(PolicyId=policy_id, Content=json.dumps(policy_document))

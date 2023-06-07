## Bulk Policy Migrator Scripts for Account, Cost and Billing Consoles

These scripts can be used to help migrate your IAM policies to use fine-grained actions (new actions).

These scripts should be run from the payer account of your organization to identify the following affected policies
in your organization that use the old IAM actions:

* Customer managed IAM policies
* Role, group, and user IAM inline policies
* Service control policies (SCPs) (for the payer account only)

The scripts generate suggestions for new actions that correspond to the old actions used in the policy. You then
review the suggestions and use the scripts to add the new actions across all affected polices in your organization.

These scripts provide the following benefits:

* Streamline the policy updates to help you manage the affected policies from the payer account.
* Reduce the amount of time that you need to update the policies. You don't need to sign in to each member account and
  manually update the policies.
* Group identical policies from different member accounts together. You can then review and apply the same updates
  across all identical policies, instead of reviewing them one by one.
* Ensure that user access remains unaffected after AWS retires the old IAM actions.

## Prerequisites

1.These scripts are designed to run using Python 3. Credentials must be pre-configured using the
AWS CLI. You can read more about how to
pre-authenticate [here](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html)


2.Permissions needed to run the script are as follows:

```
"iam:GetAccountAuthorizationDetails",
"iam:GetPolicy",
"iam:GetPolicyVersion",
"iam:GetUserPolicy",
"iam:GetGroupPolicy",
"iam:GetRolePolicy",
"iam:CreatePolicyVersion",
"iam:DeletePolicyVersion",
"iam:ListPolicyVersions",
"iam:PutUserPolicy",
"iam:PutGroupPolicy",
"iam:PutRolePolicy",
"iam:SetDefaultPolicyVersion",
"organizations:ListAccounts",
"organizations:ListPolicies",
"organizations:DescribePolicy",
"organizations:UpdatePolicy",
"organizations:DescribeOrganization",
"sts:AssumeRole"
```

3.IAM role named `BillingConsolePolicyMigratorRole` has to be deployed in all member accounts of an AWS Organization
for payer account to access affected policies within those accounts. The CFN template for this role is available in
this
repo. Please refer to user guide for instructions on how to set this up.

## Installation Steps

1.Clone the project to your local directory

```
git clone https://github.com/aws-samples/bulk-policy-migrator-scripts-for-account-cost-billing-consoles.git
```

2.Navigate into the project

```
cd bulk-policy-migrator-scripts-for-account-cost-billing-consoles
```

3.Setup virtualenv

```
python3 -m venv venv
```

4.Activate virtualenv

```
source venv/bin/activate
```

5.Install dependencies

```
pip install -r requirements.txt
```

6.Navigate to directory containing the scripts

```
cd policy_migration_scripts/scripts
```

## Running the scripts

### 1. Identify the affected policies

Following input parameters are supported:

* --all – Scans all member accounts in your organization.

```
python identify_affected_policies.py --all
```

* --accounts – Scans a subset of member accounts in your organization.

```
python identify_affected_policies.py --accounts 111122223333,444455556666,777788889999
```

* --exclude-accounts – Excludes specific member accounts in your organization. Can only be used with --all

```
python identify_affected_policies.py --all --exclude-accounts 111111111111,222222222222,333333333333
```

* -action-mapping-config-file (Optional) - Specify the path to your custom old-to-new-action-mapping JSON file.
  This is only an optional step when the provided action mapping does not fit your needs. This file is used to generate
  suggested updates for affected policies.
  If you don't specify the path, the script uses the action_mapping_config.json file in the repo.

```
python identify_affected_policies.py –-action-mapping-config-file /path/to/action_mapping_config.json –-all
```

* If no argument is provided, script runs for the current account (payer account)

```
python identify_affected_policies.py
```

### 2. Update the affected policies

The script takes as argument the absolute path of the directory created by running identify_affected_policies.py script

```
python update_affected_policies.py --affected-policies-directory /path/to/Affected_Policies_<Timestamp>
```

### 3. Revert changes done by update script (Optional)

Following input parameters are supported:

* --all – Applies to all member accounts in your organization.

```
python rollback_affected_policies.py --all
```

* --accounts – Applies to the specified accounts in your organization.

```
python rollback_affected_policies.py --accounts 111122223333,444455556666,777788889999
```

* --exclude-accounts – Applies to all accounts in your organization excluding specific member accounts.
  Can only be used with --all

```
python rollback_affected_policies.py --all --exclude-accounts 111111111111,222222222222,333333333333
```

* If no argument is provided, applies to the current account (payer account)

```
python rollback_affected_policies.py
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
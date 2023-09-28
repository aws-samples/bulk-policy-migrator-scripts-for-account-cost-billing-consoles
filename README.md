## Bulk Policy Migrator Scripts for Account, Cost and Billing Consoles

These scripts can be used to help migrate your IAM policies to use fine-grained actions (new actions).

These scripts should be run from the payer account of your organization to identify the following affected policies
in your organization that use the old IAM actions:

* Customer managed IAM policies
* Role, group, and user IAM inline policies
* Service control policies (SCPs) (for the payer account only)
* Permission Sets (AWS SSO) (for the payer account only)

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

1. Download and install [Python 3](https://www.python.org/downloads/).

2. Ensure that you have an IAM principal in your payer account that has the following IAM permissions:
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
"sts:AssumeRole",
"sso:ListInstances",
"sso:ListPermissionSets",
"sso:GetInlinePolicyForPermissionSet",
"sso:DescribePermissionSet",
"sso:PutInlinePolicyToPermissionSet",
"sso:ProvisionPermissionSet",
"sso:DescribePermissionSetProvisioningStatus",
"iam:GetRole",
"iam:ListAttachedRolePolicies"
```
These are the permissions needed to execute the script. You will be using this IAM principal to configure aws credentials
before running the scripts.

## Step 1: Set up the environment

1. Clone the project to your local directory
    ```
    git clone https://github.com/aws-samples/bulk-policy-migrator-scripts-for-account-cost-billing-consoles.git
    ```

2. Navigate into the project
    ```
    cd bulk-policy-migrator-scripts-for-account-cost-billing-consoles
    ```

3. Setup virtualenv
    ```
    python3 -m venv venv
    ```

4. Activate virtualenv
    ```
    source venv/bin/activate
    ```

5. Install dependencies
    ```
    pip install -r requirements.txt
    ```

6. Navigate to directory containing the scripts
    ```
    cd policy_migration_scripts/scripts
    ```

7. Configure the credentials using AWS CLI. You can read more about how to do this [here](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html#interactive-configuration).
   Credentials can be configured in multiple ways. Regardless of the method that you choose, you must have both **AWS credentials**
   and an **AWS Region** set before running the scripts. The simplest way is to do this in an interactive manner using AWS CLI
   and running `aws configure` command to set up your credentials and default region. Follow the prompts, and it will generate
   configuration files in the correct locations for you.

**Note:**
Specifying incorrect region can cause errors during script execution. For e.g. when running the script in China regions,
if the region is set to *us-east-1* you will see errors like - `The security token included in the request is invalid`.
For China regions, the region value should be either *cn-north-1* or *cn-northwest-1*.

## Step 2: Create the CloudFormation stack set

Follow this procedure to create a CloudFormation stack set. The stack set creates an IAM role named *BillingConsolePolicyMigratorRole*
across all member accounts of your organization. This IAM role will be assumed by the payer account during the script execution
to access affected policies in the member accounts.

**Note**:
You only need to complete this step once from the management account (payer account).

**To create the CloudFormation stack set**

1. In a text editor, open the [billing_console_policy_migrator_role.json](policy_migration_scripts/cfn_template/billing_console_policy_migrator_role.json) template file
   and replace each instance of *<management_account>* with the account ID of the payer account (for example, 123456789012).
2. Save the file.
3. Sign in to the AWS Management Console as the payer account.
4. In the CloudFormation console, create a stack set with the template file that you updated.

For more information, see [Creating a stack set on the AWS CloudFormation console](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-getting-started-create.html)
in the AWS CloudFormation User Guide.

After CloudFormation creates the stack set, each member account in your organization has *BillingConsolePolicyMigratorRole* IAM role.
The IAM role contains the following permissions:
```
"iam:GetAccountAuthorizationDetails",
"iam:GetPolicy",
"iam:GetPolicyVersion",
"iam:GetUserPolicy",
"iam:GetGroupPolicy",
"iam:GetRolePolicy",
"iam:CreatePolicyVersion",
"iam:DeletePolicyVersion",
"iam:ListPolicyVersions"
"iam:PutUserPolicy",
"iam:PutGroupPolicy",
"iam:PutRolePolicy",
"iam:SetDefaultPolicyVersion"
```

## Step 3: Identify the affected policies

To identify affected policies run the `identify_affected_policies.py` script

Following input parameters are supported:

* --all – Scans all member accounts in your organization.

```
python identify_affected_policies.py --all
```

* --accounts – Scans a subset of member accounts in your organization.

```
python identify_affected_policies.py --accounts 111122223333,444455556666,777788889999
```

* --accounts-file – Absolute path to the CSV file containing a subset of member accounts in your organization that needs
  to be scanned. The CSV file should have no headers and contain 12 digit AWS Account IDs in the first column of the file.

```
python identify_affected_policies.py --accounts-file /path/to/accounts_file.csv
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

After you run the script, it creates two JSON files in an Affected_Policies_<*Timestamp*> folder:
* affected_policies_and_suggestions.json - Lists affected policies along with the suggested new actions.
* detailed_affected_policies.json - Contains the complete policy document of all affected policies that was identified

## Step 4: Review the suggested changes

1. In a text editor, open the *affected_policies_and_suggestions.json* file.
2. In the AccountsScanned section, verify that the number of similar groups identified across the scanned accounts is expected.
3. Review the suggested fine-grained actions that will be added to the affected policies.
4. Update your file as needed and then save it.

## Step 5: Update the affected policies

After you review and refine the suggested replacements, run the `update_affected_policies.py` script.
The script takes as argument the absolute path of the directory created by running *identify_affected_policies.py* script

```
python update_affected_policies.py --affected-policies-directory /path/to/Affected_Policies_<Timestamp>
```

## Step 6: Revert your changes (Optional)

The `rollback_affected_polices.py` script reverts the changes applied to each affected policy for the specified accounts.
The script removes all `Sid` blocks that the `update_affected_policies.py` script appended. These `Sid` blocks have
the `BillingConsolePolicyMigrator#` format.

Following input parameters are supported:

* --all – Applies to all member accounts in your organization.

```
python rollback_affected_policies.py --all
```

* --accounts – Applies to the specified accounts in your organization.

```
python rollback_affected_policies.py --accounts 111122223333,444455556666,777788889999
```

* --accounts-file – Absolute path to the CSV file containing a subset of member accounts in your organization that needs
  to be scanned. The CSV file should have no headers and contain 12 digit AWS Account IDs in the first column of the file.

```
python identify_affected_policies.py --accounts-file /path/to/accounts_file.csv
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
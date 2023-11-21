Here are some of the common issues that you might see when you run the bulk policy migrator scripts:

## Throttling/Rate Exceeded Error

**Sample error msg:**
>botocore.exceptions.ClientError: An error occurred (Throttling) when calling the GetAccountAuthorizationDetails operation (reached max retries: 4): Rate exceeded
<br>File "identify_affected_policies.py"

To improve the runtime, the scripts make concurrent calls to the IAM service when identifying and updating the affected policies.
As a result, the IAM service might throttle your requests. To solve this, you need to reduce the concurrency. The concurrency
for `identify_affected_policies.py` script is defined [here](https://github.com/aws-samples/bulk-policy-migrator-scripts-for-account-cost-billing-consoles/blob/c8078b8bac25252910d764dc0bd625d1951abcad/policy_migration_scripts/utils/constants.py#L6) 
and that for `update_affected_policies.py` script is defined [here](https://github.com/aws-samples/bulk-policy-migrator-scripts-for-account-cost-billing-consoles/blob/c8078b8bac25252910d764dc0bd625d1951abcad/policy_migration_scripts/utils/constants.py#L5).
Depending on which script is throwing this error, please change the appropriate value to a smaller number that works for your workload.
We recommend reducing in steps of `5` and re-running the script till you arrive at the optimal number for your workload.
The lowest value that should be used is `1` which makes the script run sequentially. This means that the script won't get throttled,
and can take longer to run.

For large organizations, we recommend that you use a concurrency of `5` to avoid throttling.

## Maximum policy size exceeded when updating policies

This issue occurs particularly to those policies which are already large and contains the old billing console permissions
that are retired. For example, if there is an impacted policy which in addition to all other IAM permissions, also
contains `aws-portal:*`, we need to add **87** fine-grained actions as the equivalent replacement for `aws-portal:*`.
Since the policy is already large, adding the extra 87 IAM actions will increase the policy size to beyond the maximum
limit imposed by IAM for a policy.

There are three options in this scenario:

### 1. Use wildcard characters in “action_mapping_config.json"

Old to new action mapping is maintained as a config in the code base. Accounts in AWS commercial Regions (aws partition)
use [this config](policy_migration_scripts/config/aws/action_mapping_config.json) file. Accounts in the China Regions
(aws-cn partition) use [this config](policy_migration_scripts/config/aws-cn/action_mapping_config.json) file. This JSON
file serves as the input for the Identify script, which suggests fine-grained IAM actions to use as replacements.
Our default action mapping configuration file doesn't use wildcard characters. However, you can update this file to use
wildcards such as `billing:Get*` and `payments:List*` to reduce the number of actions to add to the policy.

For example, here is one possible mapping for the `aws-portal:ViewBilling` action:
```
"aws-portal:ViewBilling": [
    "account:Get*",
    "billing:Get*",
    "billing:List*",
    "ce:Describe*",
    "ce:Get*",
    "ce:List*",
    "consolidatedbilling:Get*",
    "consolidatedbilling:List*",
    "cur:Get*",
    "cur:Validate*",
    "freetier:Get*",
    "invoicing:Get*",
    "invoicing:List*",
    "payments:Get*",
    "payments:List*",
    "tax:Get*",
    "tax:List*"
  ]
```

The complete mapping of the existing(old) to new fine-grained actions for each IAM action that we’re retiring can be found
in [this guide](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/migrate-granularaccess-iam-mapping-reference.html).
Please refer to this mapping carefully and come up with your custom mapping as you see fit for your use case.

**NOTE:**
* When using wildcards, verify that you're granting only the required permissions and not creating overly permissive policies.
* If you do not want to alter the default action_mapping_config.json file, you can create your own custom mapping config file
  and pass this in as argument when running the identify script.  Please refer to `action-mapping-config-file` parameter
  under this [section](README.md#step-3-identify-the-affected-policies). Ensure that the format of your custom config is
  compliant with the format being used in the default config file.

### 2. Create New IAM Policies/Break down the large existing policies:

Instead of using a single large policy, you can break it down into separate policies and associate them with the same IAM principals.
**Note:** The bulk migrator scripts don't break large policies into smaller ones. We recommend that your IAM administrator manually
complete this task for your account.

For example, you can move all the impacted actions (any action under aws-portal, purchase-orders:ViewPurchaseOrders,
and purchase-orders:ModifyPurchaseOrders) from the existing policy into its own policy. Once you have your smaller IAM
policies, run the scripts again to identify and update the affected policies. Because the affected policies are smaller,
the updated policy won't exceed the character limit after the script adds the new fine-grained actions.

### 3. Leverage AWS Managed Policies:

You can use AWS managed policies based on the role or function that you want to enable. AWS managed policies are
automatically updated and already have the required permissions. This helps you reduce your dependency on maintaining
customer managed or inline policies. For example, if you want to allow your users full access to the Billing console,
use the **Billing** AWS managed policy.

## IAM role “BillingConsolePolicyMigratorRole” not created in all member accounts of an AWS Organization

This issue mostly occurs when you create a stack instead of a **“stack set”** in [step 2](README.md#step-2-create-the-cloudformation-stack-set)
of this procedure. If you create a stack, this only creates the required IAM role in the management account.
You must create a CloudFormation “stack set” in the management account of your AWS organization. Using a stack set
ensures that the required IAM role is created for all member accounts in the organization.


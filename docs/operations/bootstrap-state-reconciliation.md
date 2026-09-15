# Bootstrap-state reconciliation

## Reconciled deployment: 2026-09-08

The existing Seoul deployment has completed the separately reviewed bootstrap
reconciliation. Do not replay the initial import procedure below against it.
Its canonical bootstrap state is now
`s3://node-operator-tfstate-123456789012-apne2/node-operator/bootstrap/terraform.tfstate`.
The legacy baseline remains at `node-operator/t2/terraform.tfstate`; it is not
the bootstrap state and was not migrated by this operation.

The bootstrap root owns 17 managed resources. The state bucket and DynamoDB
lock table now use CMK `23528ef1-681c-41c3-a565-d19d3ec98c37`; the state bucket's
native SSE-C block is preserved. A named backend-role canary verified encrypted
state read/write and locking, including a read/lock check after DynamoDB's key
cache window. The final full bootstrap plan reported no changes. These checks
do not prove that foundation, ops-access, or the entire baseline is reconciled.

Normal `init -migrate-state` into the empty remote key changed the bootstrap
lineage from `43433424-4274-677a-050f-5f725c172eac` (serial 23) to
`1ab1c89b-c841-5119-dff7-48606a2148bf` (serial 1). All state content excluding
those two metadata fields was identical. This matches the empty-remote refresh
path in [Terraform 1.5.7's remote state manager](https://github.com/hashicorp/terraform/blob/v1.5.7/internal/states/remote/state.go):
it clears imported metadata before creating the first remote snapshot. Do not
rewrite the lineage or force-copy state to conceal this transition. The private
pre-migration backup and remote version `X2cjuh3ZRlBqyKuEArU8.xJEH_tbOiw.` are
retained. Future migrations must independently compare content, resource IDs,
outputs, metadata and the final plan; this observation is not permission to
ignore an arbitrary state mismatch.

## Historical initial inventory and procedure

The inventory below describes the pre-reconciliation state, not the current
deployment. Re-inventory and obtain a new reviewed plan for any future action.

This module defaults to a new deployment name and baseline state key:

- bucket: `node-operator-tfstate-<account-id>-apnortheast2`
- key: `node-operator/baseline/terraform.tfstate`

The current account has an older bucket name,
`node-operator-tfstate-123456789012-apne2`, and the existing baseline backend
uses `node-operator/t2/terraform.tfstate`. Reconciliation is an explicit,
reviewed import exercise. It is not a fresh `terraform apply`, and it must not
be automated by CI or release tooling.

## Prepare reviewed inputs

No import, state copy, backend migration, plan approval, or apply is
authorized by this document. For a future separately approved review, create a
fresh private operator directory outside Git, copy the module and its lockfile
there, and run all Terraform commands only against that copy:

```sh
operator_root="$(mktemp -d "${TMPDIR:-/tmp}/node-operator-bootstrap-state.XXXXXX")"
chmod 700 "$operator_root"
cp -R /ABSOLUTE/PATH/TO/REPOSITORY/infra/bootstrap-state "$operator_root/module"
```

Using a permissions-restricted editor in `$operator_root`, create a non-secret
`bootstrap-state.reconciliation.tfvars` file with the exact observed values.
Do not commit the file or any Terraform state, plan, backend configuration, or
`.terraform/` directory.

```hcl
aws_account_id      = "123456789012"
state_bucket_name   = "node-operator-tfstate-123456789012-apne2"
baseline_state_key  = "node-operator/t2/terraform.tfstate"
backend_principal_arns = [
  "arn:aws:iam::123456789012:role/REVIEWED_TERRAFORM_BACKEND_ROLE",
]
```

The allowlist accepts only exact same-account IAM role ARNs. It is empty by
default. The S3 state CMK policy then grants listed roles only `Decrypt`,
`GenerateDataKey`, and `DescribeKey`, with account, S3 service, and state
bucket encryption-context restrictions. For the regional DynamoDB lock table,
it also grants the exact crypto actions only through DynamoDB in the configured
Region and only with the exact lock-table/account encryption context. Backend
roles receive no `CreateGrant` or key-administration permission. The separately
authorized bootstrap updater must already have the permissions DynamoDB needs
to create its service-managed grants when changing the table key. Global tables
and cross-Region DynamoDB use are outside this module's contract.

Changing encryption still requires a reviewed imported-state plan. Verify the
actual backend role can read/write a non-sensitive canary and acquire/release
an isolated lock; repeat its read after DynamoDB's five-minute key cache window.
Never use a real Terraform lock ID as the canary. A successful administrator
request is not proof of backend-role access.

## Explicit backend encryption

Use **all** fields of the verified `backend` output, including `kms_key_id`.
In Terraform 1.5.7, `encrypt = true` without `kms_key_id` explicitly requests
SSE-S3, overriding a bucket's SSE-KMS default. The baseline's checked-in backend
configuration names this deployment's reviewed state CMK; new deployments must
use their own bootstrap output, never that account-specific backend file.

For example, render a non-secret backend configuration in the private operator
directory after the approved bootstrap apply. Select the state key for the root
being migrated; do not reuse the baseline key for operations access:

```sh
terraform -chdir="$operator_root/module" output -json backend |
  jq -r '.key = "node-operator/ops-access/terraform.tfstate" |
    to_entries[] | "\(.key) = \(.value | tojson)"' > "$operator_root/ops.backend.hcl"
```

Changing backend configuration requires a separately reviewed `init` operation.
Use `-reconfigure` only when the bucket/key/state identity is unchanged, or the
reviewed `-migrate-state` procedure when moving the existing local ops state.
Do not use `-force-copy`. Verify the resulting object metadata reports `aws:kms`
and the exact CMK after a scoped backend write. Existing historical SSE-S3
versions do not become CMK-encrypted merely by changing bucket defaults.

## Import workflow

1. In the private operator directory, place the reviewed tfvars file and
   authenticate as the approved account role. Never put credentials, backend
   configuration, `.terraform/`, `terraform.tfstate*`, or plan files in Git.
2. Confirm identity and the existing resource inventory with read-only AWS
   commands. The six observed existing resources are listed below. Do
   not infer an additional resource ID from a generated Terraform name.

   | Terraform address | Reviewed import ID |
   | --- | --- |
   | `aws_s3_bucket.state` | `node-operator-tfstate-123456789012-apne2` |
   | `aws_s3_bucket_versioning.state` | `node-operator-tfstate-123456789012-apne2` |
   | `aws_s3_bucket_server_side_encryption_configuration.state` | `node-operator-tfstate-123456789012-apne2` |
   | `aws_s3_bucket_public_access_block.state` | `node-operator-tfstate-123456789012-apne2` |
   | `aws_s3_bucket_policy.state` | `node-operator-tfstate-123456789012-apne2` |
   | `aws_dynamodb_table.lock` | `node-operator-terraform-lock` |

   The current state bucket uses SSE-S3. No existing state CMK was observed,
   so `aws_kms_key.state` is not an import target.
   The observed state bucket policy denies insecure transport. Preserve that
   denial and add the scoped SSE-C write denial; never overwrite other policy
   statements without reviewing a fresh inventory. Also verify the bucket's
   native `BlockedEncryptionTypes` remains `SSE-C` before and after changing
   default encryption. Provider 5.x does not represent that native setting;
   a zero-drift Terraform plan alone cannot prove it was preserved.
3. Initialise without a backend and validate the reviewed configuration:

   ```sh
   terraform -chdir="$operator_root/module" init -backend=false -lockfile=readonly
   terraform -chdir="$operator_root/module" validate
   ```

4. Only if a later approval explicitly authorizes import, use explicit
   Terraform state commands for exactly the reviewed address/ID pairs:

   ```sh
   terraform -chdir="$operator_root/module" import -var-file="$operator_root/bootstrap-state.reconciliation.tfvars" aws_s3_bucket.state node-operator-tfstate-123456789012-apne2
   terraform -chdir="$operator_root/module" import -var-file="$operator_root/bootstrap-state.reconciliation.tfvars" aws_s3_bucket_versioning.state node-operator-tfstate-123456789012-apne2
   terraform -chdir="$operator_root/module" import -var-file="$operator_root/bootstrap-state.reconciliation.tfvars" aws_s3_bucket_server_side_encryption_configuration.state node-operator-tfstate-123456789012-apne2
   terraform -chdir="$operator_root/module" import -var-file="$operator_root/bootstrap-state.reconciliation.tfvars" aws_s3_bucket_public_access_block.state node-operator-tfstate-123456789012-apne2
   terraform -chdir="$operator_root/module" import -var-file="$operator_root/bootstrap-state.reconciliation.tfvars" aws_s3_bucket_policy.state node-operator-tfstate-123456789012-apne2
   terraform -chdir="$operator_root/module" import -var-file="$operator_root/bootstrap-state.reconciliation.tfvars" aws_dynamodb_table.lock node-operator-terraform-lock
   ```

   Keep the resulting local state private. Do not import any remaining module
   resource without a new observed inventory and approval.
5. Run a refresh-only plan and a normal plan with the same private inputs.
   A reviewer must verify that there are no replacements or deletes before any
   change is considered. New CMK and unobserved child-resource configuration
   creation is separate from importing these six resources, and requires a
   saved, reviewed imported-state plan. `prevent_destroy` protects the state
   bucket and lock table, but it is not an approval to alter their live
   settings.
6. Only after that review, configure the remote backend explicitly through a
   private backend configuration file or the approved `terraform init
   -backend-config=...` invocation from `$operator_root/module`. Do not copy
   state to a backend or apply this module as part of this workflow without
   separate authorization.

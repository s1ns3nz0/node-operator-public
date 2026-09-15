# Deployment ownership and cleanup

The installer distinguishes resources belonging to this deployment from resources managed by other Terraform states. An existing AWS account is not an empty deployment: unrelated VPCs, buckets, keys and roles must retain their original ownership.

| Situation | Installer behavior |
| --- | --- |
| No matching deployment resources exist | Create a dedicated bootstrap backend and new deployment resources. |
| The same deployment has a bootstrap state | Restore that state before planning; preserve resource IDs and the state encryption key. |
| An interrupted bootstrap left resources without a complete state | Verify ownership before importing the matching resources. Ambiguous ownership or an unreadable API result stops reconciliation. |
| Other Terraform deployments exist | Leave them in their current states. Their names or account membership do not authorize adoption. Explicit existing-network inputs reference externally owned network objects as data. |

Terraform-managed, taggable resources use `Project=node-operator`, `Deployment=<deployment name>`, `DeploymentRegion=<origin region>` and `ManagedBy=terraform` (or `node-operator-installer` for direct installer creation). Provider defaults cover Terraform resources that do not declare their own tags, including the audit replica and separate SSM root. Data sources do not receive tags. The EBS CSI controller and VPC CNI receive explicit extra-tag configuration for newly created PVC volumes and network interfaces. These settings do not retroactively tag existing objects. Other AWS-created children require verified parent relationships during cleanup; unknown or foreign ownership must block deletion.

New backend IAM roles default to a deployment-and-region-specific name. An explicitly supplied existing role ARN is an external dependency: it is read and referenced, never retagged. Do not share a deployment-owned role with another environment that must survive its cleanup.

Use a unique deployment name for each independent environment. Reuse the same name and existing state to resume an environment. Do not import a resource into a second active Terraform state. Legacy resources without a deployment tag require ownership reconciliation; cleanup must not guess their owner from a name prefix.

## One cleanup command

Preview one deployment across the account's opted-in regions:

```bash
scripts/release/delete-all-node-operator-resources.sh \
  --deployment node-op-example --all-regions
```

Delete that deployment after reviewing the preview, using the account shown by `aws sts get-caller-identity`:

```bash
scripts/release/delete-all-node-operator-resources.sh \
  --deployment node-op-example --all-regions \
  --execute --account 123456789012
```

Select every tagged project deployment explicitly:

```bash
scripts/release/delete-all-node-operator-resources.sh \
  --all-project-deployments --all-regions \
  --execute --account 123456789012
```

Omit `--execute` to preview; use `--region ap-northeast-2` to restrict the regional scan. Discovery errors are not evidence of absence. A denied deletion, unsupported resource or retained object must remain visible in the result instead of producing a success claim. KMS cleanup schedules a seven-day pending deletion, which is not immediate physical removal. Object Lock retention and legal holds may prevent immediate S3 deletion. These are AWS service constraints, not protections that a tag or administrator role can bypass. See [AWS KMS deletion behavior](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html).

API cleanup bypasses Terraform's `prevent_destroy` lifecycle protections, not AWS authorization or retention. It is intended for an explicitly selected disposable deployment. Stop Terraform applies and workloads before executing it. Keep a private recovery copy of state before choosing total cleanup. The state bucket and lock must be retained when dependent deletions fail; KMS keys must be retained when encrypted objects remain. A deleted backend cannot be used to recover remaining resource ownership. Existing private working directories may retain sensitive Terraform state and must be handled separately from AWS cleanup.

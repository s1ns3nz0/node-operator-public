# Isolated Vault recovery infrastructure

This Terraform root provisions only a temporary recovery environment. It does
not download a snapshot, restore Vault data, retrieve recovery shares or
tokens, start Vault, or change live EKS, networking, keys, or PVCs.

The root creates a new `10.91.0.0/24` VPC and one private `10.91.0.0/25`
subnet. It deliberately creates no internet gateway, NAT gateway, peering,
transit attachment, public IP, or non-local route. The host can reach only the
regional S3 managed prefix list and HTTPS interface endpoints for SSM,
SSM Messages, EC2 Messages, KMS, and ECR. The S3 gateway endpoint and host
role restrict access to the exact snapshot object version and regional ECR
layer bucket; endpoint policies additionally constrain the host principal.
The sole exception is the exact regional ECR starport layer-bucket resource:
ECR retrieves layers using presigned S3 URLs, so its gateway endpoint policy
permits that read principal while the host IAM policy remains read-only and
resource-scoped.

The new VPC's default security group is adopted and emptied. VPC Flow Logs
record `ALL` traffic metadata to a dedicated CloudWatch Logs group encrypted
by a new recovery-only KMS key. Logs retain for 365 days and contain no Vault
payload. The KMS key has a 30-day deletion window; neither retention nor the
expiry authorization deny automatically deletes resources. Before explicitly
deleting the log group or key during approved cleanup, retain or export any
required evidence because retention does not survive resource deletion.

The EC2 role is custom and intentionally does not attach
`AmazonSSMManagedInstanceCore`: it contains only the SSM agent channel/update
actions plus the scoped S3, KMS, and ECR reads. It cannot create grants or
modify key policies. The instance uses a reviewed explicit Amazon-owned ECS
AL2023 x86_64 AMI (Docker preinstalled), has no SSH key or public address,
requires IMDSv2 with hop limit one, uses basic monitoring and an encrypted
gp3 root volume of at least 30 GiB. Its user-data masks ECS, starts Docker and
the SSM agent, and checks binaries plus instance metadata only.

The expiry tag is also enforced by explicit IAM denies for snapshot-version
reads and both KMS keys, including against a temporary KMS grant. It does not
delete resources or stop EC2 automatically; the approved cleanup owner must
tear the environment down before expiry.

The existing auto-unseal key policy does not delegate cryptographic use through
account IAM for this new role. A separate, reviewed temporary KMS grant (or
other key-owner-approved authorization) for this exact host role is required
before any recovery ceremony. This root neither replaces key policies nor
creates grants.

## Use

1. Copy both examples outside source control and replace placeholders with
   reviewed values. Use a distinct remote S3 backend key.
2. Run offline checks first, then initialize only with the reviewed backend:

   ```sh
   terraform -chdir=infra/vault-recovery init -backend-config=/approved/path/backend.hcl
   terraform -chdir=infra/vault-recovery validate
   terraform -chdir=infra/vault-recovery plan -var-file=/approved/path/recovery.tfvars -out=reviewed-recovery.tfplan
   ```

3. A separately reviewed recovery ceremony owns snapshot download, checksum
   verification, recovery shares/tokens, restore, custody, validation, and
   teardown. This module contains none of those operations.

Do not run `apply` until the separate saved-plan, principal, isolation, and
SSM-health reviews are approved. Never put snapshot contents, recovery shares,
tokens, or credentials in Terraform variables, state, output, CI logs, or this
repository.

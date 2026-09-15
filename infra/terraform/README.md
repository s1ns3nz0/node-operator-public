# Private EKS Terraform baseline

This directory is a contract-free Terraform baseline for the node-operator
infrastructure. State uses the approved encrypted S3 backend with DynamoDB
locking, and the configuration invokes no remote Terraform modules. It creates
no Internet gateway, NAT gateway, public subnet, public IP assignment, or
public EKS API endpoint.

## Encryption and Vault boundary

The cluster version must be EKS 1.28 or later. EKS then applies its default
AWS-owned envelope encryption to all Kubernetes API data, including Secrets.
This baseline deliberately does not create an EKS customer-managed KMS key or
an `encryption_config` override. That avoids treating a cluster-control-plane
key as an application-secret store.

Vault runs with EKS Pod Identity and uses the dedicated `vault-unseal` KMS key
only for auto-unseal. Workload secret payload encryption, signing, and
tokenization are Vault responsibilities; the unseal key must not be reused for
those payloads. AWS-managed storage and audit paths retain separate keys:
`ebs` encrypts node and CSI volumes, while `audit` and the replica audit key
protect CloudTrail and control-plane log delivery. These keys remain separate
so their service principals and grants can be constrained independently.

## Private AWS service access

Platform nodes have no NAT gateway or public route requirement. They use an S3
gateway endpoint on the private route table and interface endpoints, with
private DNS enabled in both private subnets, for `eks-auth`, `ec2`, `ecr.api`,
`ecr.dkr`, and `kms`. When the private release signer is explicitly enabled,
it also creates private `sts` and `logs` interface endpoints. The endpoint
security group accepts only TCP/443 ingress from the managed-node security
group and, when enabled, the dedicated signer security group. It has no broad CIDR or
public ingress rule.

These endpoints are the must-have baseline for private node bootstrap and
image pulls. They intentionally exclude the EKS management API endpoint
(needed only for management callers inside the VPC) and conditional endpoints such as
CloudWatch Logs and STS (except the signer pair above), Secrets Manager, SSM, EC2 Messages, SSM Messages, EFS,
and ELB. Add a conditional endpoint only when the corresponding workload,
add-on, logging destination, identity flow, or operations tooling has been
approved and its endpoint security and policy requirements are specified.

`aws_eks_node_group.private` explicitly depends on these endpoints, preventing
managed-node bootstrap from racing their creation. The EKS Kubernetes API is
already private-only through EKS control-plane ENIs; it is not modelled as an
`aws_vpc_endpoint`.

Hoodi client nodes are separate from the platform pool. An approved, existing
NAT gateway may be supplied at apply time only for those private nodes because
their peers use dynamic public addresses. Their dedicated security group limits
that egress to HTTPS and Hoodi P2P ports, while VPC Flow Logs retain the audit
trail. The module reads rather than creates that NAT gateway or its route.

## Offline validation

Use only the repository's checksum-verified provider mirror and committed
provider lock file when an authorized build task supplies them. The PR evidence
collector configures Terraform with a filesystem mirror, `-backend=false`,
`-get=false`, and `-lockfile=readonly`; it must not fall back to direct
downloads.

The committed lock file includes the provider checksums required by the pinned
Linux validation image. Offline validation may run `terraform init` with
`-backend=false`, followed by `validate` and a synthetic `plan`; it must not
contact the configured remote backend or use cloud credentials. `apply` remains
outside this baseline's validation scope.
For that synthetic plan alone, the node security group uses the published
Seoul S3 managed-prefix-list identifier instead of querying AWS. A live plan
always resolves the prefix list from AWS.

`fixtures/offline-baseline.tfvars` and `terraform.tfvars.example` contain a
synthetic, non-secret 12-digit account ID solely to make variable validation
reproducible. They are not deployment inputs.

## Private release signer ECR mirror

`enable_release_signer_ecr_mirror=false` is the default and creates no ECR
mirror resources. When separately reviewed with `enable_release_signer=true`,
Terraform creates a dedicated KMS-encrypted, scan-on-push, immutable ECR
repository. The CodeBuild signer accepts only that same-account,
`ap-northeast-2` repository URL with an immutable SHA-256 digest; it cannot
pull GHCR or a tag-only image from the private-only VPC.

The optional GitHub OIDC mirror role is restricted to the configured
`github_repository` and the GitHub environment `ecr-signer-mirror`. Its only
repository actions upload image layers and manifests to this repository.
This Terraform contract deliberately creates no mirroring workflow, image
publication, AWS credential, or ECR image.

## Validator runtime image mirrors

`enable_validator_runtime_ecr_mirror=false` is the default and creates no
runtime mirror resources. When explicitly enabled, Terraform creates separate
KMS-encrypted, scan-on-push, immutable repositories for Web3Signer and
PostgreSQL. The `validator-runtime-ecr-mirror` GitHub Environment must be
given the non-secret account ID and the emitted
`github_validator_runtime_ecr_mirror_role_arn`. Its OIDC role can upload only
to those two repositories; it cannot delete images, alter repository policy,
or access Vault.

The corresponding manual workflow has no arbitrary image input. It mirrors
only digest references committed in `.ci/validator/approved-runtime-images.json`.
Changing that allowlist is a reviewed source change; after a successful mirror,
the ECR digest, rather than a tag, is the only value accepted by the signer
runtime renderer.

## Private GitOps OCI mirror

`enable_private_gitops_foundation=true` is the promoted default for this live
baseline. The two artifact repositories use `prevent_destroy`; removing the
foundation therefore requires an explicit configuration change and a reviewed
destroy plan. The isolated offline baseline and release-signer fixtures set
the flag to `false` so their plans continue to test only their own scope.

The `gitops-oci-mirror` GitHub Environment supplies only non-secret bootstrap
configuration: the AWS account ID, the Terraform output
`github_gitops_oci_mirror_role_arn`, and a repository-owned, digest-pinned
`GITOPS_OCI_MIRROR_TOOL_IMAGE`. Its GitHub OIDC role permits ECR login,
reading a destination manifest digest, and uploading layers/manifests to the
two dedicated repositories. It cannot delete images, modify repository policy,
or access Vault. The manual workflow accepts a fully digest-pinned upstream
OCI reference, uses its digest as the immutable ECR tag, and compares the ECR
digest after the copy with the approved source digest. The source must also be
an exact entry in `.ci/gitops/approved-oci-artifacts.json`; an empty allowlist
is a safe default that permits no publication.

## Authorized AWS apply and destroy runbook

This runbook is bounded to an explicitly approved, non-production account and
the Terraform state workspace created for this baseline. Do not run it from a
developer workstation using ambient credentials.

1. Confirm the approved account, `ap-northeast-2` region, change ticket,
   controlled state backend, provider mirror, and a reviewed plan showing only
   this baseline's resources. Confirm no NAT gateway, internet gateway, public
   subnet, or public EKS endpoint is proposed. For Hoodi enablement, also
   confirm the supplied NAT ID is the approved existing private-subnet route.
2. In the controlled runner, initialize only from the approved provider mirror,
   create the plan with the approved non-secret tfvars, and have the designated
   reviewer approve the exact plan artifact before apply. Record the plan
   digest, caller identity, state workspace, and endpoint IDs in change
   evidence.
3. After apply, verify the EKS API is private-only, every interface endpoint is
   available with private DNS in both private subnets, the S3 gateway endpoint
   is associated with the private route table, and endpoint ingress is limited
   to node-security-group TCP/443. Verify the module created no NAT or internet
   gateway; inspect the separately approved NAT route and its Flow Logs when
   Hoodi pools are enabled.
4. To destroy, first stop dependent workloads and remove any resources that
   retain or reference the cluster. In the same controlled state workspace,
   review and approve a destroy plan, execute it, then verify the endpoint
   ENIs, EKS resources, route-table endpoint entry, and associated security
   groups have been removed. Retain the reviewed plan and verification evidence.

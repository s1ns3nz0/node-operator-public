# Private ECR signer mirror contract

The release signer runs in a VPC with no NAT, Internet gateway, public subnet,
or public registry route. Its runtime image therefore comes only from the
same-account `ap-northeast-2` ECR repository
`<account>.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-vault-release-signer@sha256:<digest>`.
The image must be a digest, not a tag.

`enable_release_signer_ecr_mirror` remains false by default. When it is
enabled in a reviewed live plan, Terraform creates a dedicated KMS-encrypted
ECR repository with immutable tags and scan-on-push. It exposes only the
non-secret repository ARN and URL. It does not mirror, publish, delete, or
retag any image.

The mirror identity uses GitHub OIDC and trust subject exactly
`repo:<github_repository>:environment:ecr-signer-mirror`; it allows only the
ECR authorization token and the layer/manifest upload API set for that single
repository. No static AWS credential, ECR password, broad ECR wildcard, image
delete, or repository-policy permission is defined.

When `enable_release_signer` is also true, CodeBuild uses its service role to
pull only from this repository, with `ecr:GetAuthorizationToken` and the
minimum ECR layer/manifest read actions. The VPC adds private STS and
CloudWatch Logs interface endpoints, and their security group
permits signer ingress only from its dedicated security group on TCP/443.
ECR API, ECR DKR, and S3 private endpoint paths already exist. This contract
does not activate the signer, create a workflow, or access AWS, ECR, Vault, or
EKS.

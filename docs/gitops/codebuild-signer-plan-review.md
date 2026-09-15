# CodeBuild signer enabled-plan review

The reproducible offline review uses
`fixtures/offline-release-signer.tfvars`. It is deliberately non-secret and
sets `offline_validation=true`; its account ID and subnet IDs are synthetic.
Run it with:

```sh
npm run test:codebuild-signer-enabled-plan
```

The reviewed configuration pins the signer image to:

```text
ghcr.io/s1ns3nz0/node-operator/vault-release-signer@sha256:3674b70a8c02a7fd0734e8e0d7c7f4f33fe7701f30b4c6f21569877721d55d07
```

## Offline result

The enabled synthetic plan creates 149 resources. It includes the CodeBuild
signer project, its private security group, encrypted signer log group, three
dedicated KMS keys, and encrypted/versioned release artifact buckets plus a
replica. The plan boundary check found no NAT gateway, Internet gateway, or
resource with `public_access=true`.

This result is a configuration review only. It uses no backend, refresh, AWS
provider API, deployed subnet, or live state. It is not an apply approval and
does not prove that the synthetic subnet IDs exist.

## Live-plan inputs and blockers

A controlled, read-only AWS plan must use the approved backend and the actual
account ID. `release_signer_subnet_ids` must come from the deployed baseline
state's `private_subnet_ids` output, not this fixture. The release signer also
requires a private Vault route and the reviewed AWS-auth role before it can
perform a Transit operation.

The GHCR reference is not enabled in the private-only CodeBuild project. The
signer security group permits HTTPS only inside the VPC CIDR and the baseline
has no NAT route, while GHCR is an external registry. The next code contract
replaces it with an immutable same-account ECR digest in `ap-northeast-2`,
adds a KMS-encrypted scan-on-push ECR mirror repository, and limits the mirror
OIDC role to the `ecr-signer-mirror` environment. It also adds conditional
private STS and CloudWatch Logs endpoints with signer-security-group TCP/443
ingress. A future live plan must confirm the actual ECR digest, subnet IDs,
Vault private route, and AWS-auth role before any apply.

No Terraform apply, AWS, Vault, or EKS action occurred during this review.

References: [AWS CodeBuild VPC networking](https://docs.aws.amazon.com/codebuild/latest/userguide/vpc-support.html) and [AWS CodeBuild troubleshooting for custom images](https://docs.aws.amazon.com/codebuild/latest/userguide/troubleshooting.html).

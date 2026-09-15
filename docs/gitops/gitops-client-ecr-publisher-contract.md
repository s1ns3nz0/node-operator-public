# Dedicated GitOps client ECR publisher

`gitops-client-ecr-publisher.tf` defines a distinct OCI-image destination for
the private repository `s1ns3nz0/node-operator-gitops`:

`ACCOUNT.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-client/node-operator-client`

It is deliberately not `private_gitops["nodes"]`. The pre-existing GitOps OCI
mirror can write deployment charts and mirrored runtime inputs; this publisher
can upload layers and manifests to only the client chart repository. Helm OCI
derives the final path by appending the chart name, so Terraform creates that
exact path before publishing. It cannot
read or write the other GitOps repositories, delete images, retag an immutable
tag, modify repository policy or lifecycle policy, access EKS or Vault, or
assume any other AWS role.

## Enablement input

An approved Terraform input sets only the non-secret flag below. The GitHub
repository and environment variables are locked by validation so a plan cannot
silently broaden the trust boundary.

```hcl
enable_gitops_client_ecr_publisher = true
```

The resulting role output is
`github_gitops_client_ecr_publisher_role_arn`. Configure that exact ARN in the
`node-operator-gitops` repository as the repository variable
`GITOPS_CLIENT_ECR_PUBLISHER_ROLE_ARN`; do not store AWS credentials in GitHub.

## GitHub environment requirements

Create the protected environment named `gitops-client-ecr-publish` in the
private `s1ns3nz0/node-operator-gitops` repository before triggering its
publisher workflow. The workflow must request `id-token: write`, run in that
environment, and use `sts:AssumeRoleWithWebIdentity` for the output role. The
trust policy requires all of:

- audience `sts.amazonaws.com`;
- repository `s1ns3nz0/node-operator-gitops`; and
- the exact `gitops-client-ecr-publish` environment subject.

The GitHub environment should require the reviewed deployment branch and an
operator approval. The OIDC role is an image-push identity only; GitHub
repository write, Argo CD sync, Kubernetes access, and Vault access remain
separate capabilities.

## Publishing contract

Publish a content-addressed client image to the repository URL output. Tags are
immutable and ECR scans every pushed image. Record the emitted digest in the
GitOps manifest and have Argo CD deploy the digest form (`@sha256:...`), not a
mutable tag. Retain the most recent ten immutable images; recover an older
revision through Git's pinned digest while it is retained.

`ecr:GetAuthorizationToken` is the sole wildcard-resource action because ECR
does not support resource-scoped authorization tokens. Every layer and manifest
upload API is scoped to this single repository.

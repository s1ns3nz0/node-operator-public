# Private GitOps source and Vault boundary

## Decision

Argo CD reads deployment inputs only from the private ECR GitOps repositories.
It must not connect directly to `github.com`: the EKS VPC intentionally has no
NAT or public egress. Approved OCI artifacts are copied into ECR by the
existing digest-reviewed mirror workflow before an Argo CD source may refer to
them.

## Future Git mirror identity

GitHub remains the authoring system. A future mirror integration uses a
dedicated GitHub App rather than a personal access token or deploy key. Its
installation is restricted to the intended GitOps source repository and has
only `Contents: read` and `Metadata: read` repository permissions. It may
publish a reviewed, immutable OCI artifact through the existing protected
GitOps mirror boundary; it receives no Kubernetes, EKS, Vault, or Terraform
permission.

The GitHub App is not created in this repository task. Its App ID and
installation ID are non-secret configuration, while its private key is secret
material and must never be committed, placed in Terraform state, or passed to
an Argo CD Application manifest.

## Future Vault and VSO delivery

When Vault and Vault Secrets Operator (VSO) are separately approved and
deployed, the GitHub App private key may be stored at the KV v2 logical path
`kv/platform/argocd/repository-credentials`. A namespace-bound VSO
`VaultAuth` may read only that path and may create only the destination
repository-credential Secret in the `argocd` namespace. The destination must
use the Argo CD repository credential label and contain `githubAppID`,
`githubAppInstallationID`, and `githubAppPrivateKey` fields.

VSO synchronizes Vault data to a Kubernetes Secret for this integration; the
secret is therefore still sensitive at rest in etcd. CSI delivery is not a
substitute here because Argo CD repository credentials are consumed as a
Kubernetes Secret. Encrypt Kubernetes API data at rest, restrict namespace
RBAC, and rotate the GitHub App key through Vault and VSO reconciliation.

## Explicit exclusions

- No Argo CD `Application`, `ApplicationSet`, `Repository`, or `repo-creds`
  Secret is created by this contract.
- No Vault engine, policy, auth role, secret, or VSO custom resource is
  created by this contract.
- No PAT, deploy key, static AWS credential, or public-network exception is
  permitted.

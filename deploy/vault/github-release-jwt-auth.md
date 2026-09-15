# GitHub Release JWT authentication contract

This is a configuration template, not a deployment command. Apply it only
from the approved Vault administration boundary after the private Vault
endpoint and the self-hosted release runner are available.

GitHub-hosted runners must not connect to a private Vault endpoint. The
release workflow therefore moves to a hardened self-hosted runner inside the
approved private network before this role is enabled. A public Vault listener,
static fallback credential, or an exception for pull-request execution is not
an acceptable substitute.

## Role boundary

[`github-release-jwt-role.json`](auth/github-release-jwt-role.json) permits a
token only when all of these GitHub OIDC claims match:

- audience: `https://vault.node-operator.internal`
- repository and owner: `s1ns3nz0/node-operator` and `s1ns3nz0`
- ref type and ref: a `v*` tag under `refs/tags/`
- workflow reference: `.github/workflows/release-bundle.yml` at that same tag

The Vault token is a non-renewable batch token with one use, no default policy,
a 15-minute TTL, and only the `release-runner-dynamic-aws` policy. It cannot
access Transit; the CodeBuild signer retains the separate
[`release-signer`](policies/release-signer.hcl) Transit policy and
authenticates through AWS auth.

## Approved administrative configuration

The security operator configures the JWT verifier, with the pinned GitHub
issuer and an explicit supported-signing-key source, then writes the reviewed
role document:

```sh
vault auth enable jwt
vault write auth/jwt/config \
  oidc_discovery_url="https://token.actions.githubusercontent.com" \
  bound_issuer="https://token.actions.githubusercontent.com"
vault write auth/jwt/role/release-runner @deploy/vault/auth/github-release-jwt-role.json
vault policy write release-runner-dynamic-aws deploy/vault/policies/release-runner-dynamic-aws.hcl
```

The release job requests an OIDC token with the exact audience above, sends it
to `auth/jwt/login`, and reads `aws/creds/release-runner`. It must fail closed
if login or lease issuance fails. It must never write a GitHub OIDC JWT or a
Vault token to logs, artifacts, Git, Terraform state, or a Kubernetes Secret.

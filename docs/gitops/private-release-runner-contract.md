# Private release runner contract

This contract prepares the private execution boundary required before
`release-bundle.yml` is allowed to exchange a GitHub OIDC token for a Vault token. It
is not authorization to register a runner, change a GitHub environment, open
network paths, or deploy Vault.

## Runner selection and identity

The approved runner is the dedicated CodeBuild project
`node-operator-baseline-private-release`, restricted to this repository and
configured for GitHub `WORKFLOW_JOB_QUEUED` events only. It contains only
ephemeral runners. A release job must select the exact project and workflow-run
identity label:

```yaml
runs-on: codebuild-node-operator-baseline-private-release-${{ github.run_id }}-${{ github.run_attempt }}
```

The CodeBuild GitHub connection is operator-managed and is never placed in this
repository, Vault KV, job logs, or evidence. The runner has no access to a
shared Docker socket and is destroyed after one job. It must not be made
organization-wide, accept untrusted pull-request jobs, or be reused as a
general CI runner.

## Vault network and TLS boundary

The runner resolves only the private DNS name
`vault.node-operator.internal` for release authentication. Its network policy
permits TCP 8200 only to the private Vault endpoint; Vault has no public
listener, public load balancer, public ingress, or Internet DNS record.

Before a credential is requested, the runner verifies the Vault certificate
chain, hostname/SNI, and current certificate validity using the approved
private CA. A TLS, DNS, route, or certificate verification failure fails the
release. There is no HTTP, `-k`, public endpoint, or static-credential
fallback.

## GitHub OIDC JWKS availability

Vault, rather than the release runner, needs controlled outbound HTTPS access
to GitHub's OIDC discovery and JWKS endpoints:

- `https://token.actions.githubusercontent.com/.well-known/openid-configuration`
- the `jwks_uri` declared by that discovery document

The egress firewall or proxy allows only these endpoints and records the
destination. Vault caches validated JWKS keys for normal availability, but an
operator must test refresh before each key-cache expiry window and after a
GitHub signing-key rotation announcement. A stale cache or failed JWKS refresh
blocks new release authentication rather than accepting an unverified token.

## Human approval and claim boundary

The `release` GitHub Environment requires an approval from an authorized
release maintainer before the private runner receives a job. Self-approval is
disabled, the environment is limited to protected `v*` tags, and deployment
branch/tag rules are reviewed with the runner-group repository restriction.

Environment approval does not replace Vault policy. Vault continues to enforce
the versioned `release-runner` JWT role: repository, owner, `refs/tags/v*`,
`release-bundle.yml` workflow reference, and
`https://vault.node-operator.internal` audience. PRs, forks, branches,
`workflow_run`, and a job whose labels differ from the exact set above are not
release credential paths.

`operations-verification.yml` with the `private-runner` target uses the separate `private-runner-smoke`
Environment, restricted to `main` and containing no release variables or
secrets. It may verify the ephemeral runner, private AWS read paths, and the
reviewed build-image pull, but it cannot obtain the release Environment or
Vault release-authentication path.

## Audit correlation and fail-closed operation

For every approved release, retain this non-secret correlation tuple in the
release record: GitHub repository ID, run ID, run attempt, workflow ref,
source revision, Vault login request ID, Vault AWS lease ID, AWS request ID,
and CodeBuild build ID. Vault audit logs, GitHub environment approval records,
CloudTrail, and CodeBuild logs must be searchable by this tuple or by their
linked identifiers.

Do not log the OIDC JWT, Vault token, AWS access key, AWS secret key, session
token, Transit signature, recovery material, or unseal material. Failure to
record approval or any required correlation identifier, a runner identity
mismatch, or a Vault/JWKS/TLS failure is fail-closed for the release.

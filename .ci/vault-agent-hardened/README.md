# Hardened Vault Agent image

This build supplies only the `vault agent` command required by Vault Kubernetes
Injector. Every other Vault subcommand, including `vault server`, exits with
code 64. `vault version` and the conventional version flags are the only
read-only exceptions.

This least-capability dispatcher is intentional. It calls the upstream exported
`command.AgentCommand` with Vault's own shutdown, SIGHUP, and SIGUSR2 channels,
but never initializes the general CLI command map that makes server and secrets
commands reachable.

The build consumes the official Vault 2.1.0 GitHub archive for commit
`cb6a54face072e372480d7cc2e64a3110b84756f`. GitHub-generated archives are not
an independent signature format, so the build pins both the commit URL and the
observed archive SHA-256. Any upstream archive regeneration fails the build and
requires explicit review of `upstream.lock.json`.

The binary is built with Go 1.26.6 and the minimal upstream build tag. The only
source dependency changes are `golang.org/x/crypto` 0.56.0, Apache Thrift
0.24.0 and gRPC 1.83.2. The build applies exactly those three requirements,
then checks the final
`go.mod` and `go.sum` hashes against `upstream.lock.json`; `go mod verify` runs
before compilation.

The existing frozen Agent digest
`sha256:33458e87c790b140717f2f4c688d31327292f67677ba004d32838deed8b8f30a`
predates this gRPC patch. Hosted run34325393574 reports
GHSA-2v4p-qf9q-27wj High on its gRPC1.83.1 dependency, so it is not eligible
for promotion. The updated recipe requires a new image, scan and exact-binary
dependency proof; the old applicability record is not transferable.

The runtime is the pinned linux/amd64 Alpine 3.24.1 manifest with OpenSSL
3.5.8-r0. APK metadata remains present for scanner completeness. The image runs
as UID 100 and GID 1000, drops no privileges internally, and expects the
orchestrator to provide a read-only root filesystem, `allowPrivilegeEscalation:
false`, and `capabilities.drop: [ALL]`. `/home/vault` is owned by that identity
for the Injector's ephemeral volume. `/bin/sh`, `base64`, and
`/usr/local/bin/vault` are retained for the generated Injector command.

Build, exercise the Injector-style argv and auto-auth/template contract, and
require zero Critical/High Grype findings with:

```sh
scripts/ci/test-vault-agent-runtime.sh
```

Set `VAULT_AGENT_SKIP_BUILD=true` only to retest an already-built local image
by immutable image ID without invalidating the source-build cache.

The offline runtime check proves that the generated Kubernetes auto-auth and
template configuration parses, retries safely, and never logs the synthetic
JWT. It validates authentication, sink and template output, `exit_after_auth`,
and SIGTERM against a minimal mock. A separate check validates authentication,
sink and template output and `exit_after_auth` against the pinned official
Vault 1.20.4 linux/amd64 server at the same version as the deployed
ECR mirror. The 1.20.4 test uses the real
Kubernetes auth plugin with a synthetic TokenReview endpoint and ephemeral
policy, role, token, and KV data on an internal Docker network.
Its JWT has parseable service-account claims but a deliberately fake signature;
only the fixture TokenReview endpoint accepts it. This exercises Vault's real
Kubernetes auth plugin, not Kubernetes signature verification or live identity.

This proves the Agent/server API subset used by the fixture; it does not prove
the exact live role, policy, TLS, CA, audit, network-policy, or Injector-rendered
pod configuration. Before changing the live Injector image, read-only checks
should confirm the deployed server and injector versions, ECR digest, rendered
UID/GID and volume mounts, auth mount/role/policy names, CA path, and expected
audit correlation fields. A separately authorized non-sensitive canary is still
required for end-to-end live authentication and template output. Do not upgrade
or mutate the Vault server or Raft state as part of this Agent-only change.

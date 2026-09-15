# Vault server candidate

Full Vault 2.1.0 source build pinned to commit and archive checksum, using Go
1.26.6, x/crypto 0.56.0, thrift 0.24.0 and gRPC 1.83.2. Final module files are hash checked.
This is separate from the agent-only dispatcher. Upstream generate-root and
snapshot-inspection command tests run during the build. Module/dependency
inventories and license are retained in `/usr/share/vault/`.

The local candidate `sha256:5463f9d70fe71b897b165e019dbc1e85aeaa8271130572bd060729dc124ff51f`
scanned Critical=0, High=0, Medium=3 and Unknown=1 with no ignored findings.
See the task evidence for the raw scan hash and build log. This is not a
trusted release, and no live Vault server has been changed.

The same frozen candidate is now available in private ECR as
`123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-vault-runtime-server@sha256:5463f9d70fe71b897b165e019dbc1e85aeaa8271130572bd060729dc124ff51f`.
Registry digest equality and a fresh full C/H=0 scan passed on2026-09-09.
This is manually reviewed candidate delivery, not CI-attested promotion or
deployment approval. Keep `enable_node_runtime_ecr=true` and
`enable_vault_runtime_ecr=true` in subsequent reviewed infrastructure inputs.

The frozen image above predates the gRPC 1.83.2 patch. Hosted run34325393574
now reports GHSA-2v4p-qf9q-27wj High on its gRPC1.83.1 dependency; it is not
eligible for promotion. The updated Dockerfile requires a newly scanned
candidate and a fresh exact-binary/closure assessment, not reuse of its old
pass. `VAULT_RAFT_TEST_NEW_IMAGE=sha256:...` selects an immutable local
candidate for the isolated Raft rehearsal while preserving the old default.

Before rollout, require isolated Raft backup/restore and auth/audit tests,
assessment of GO-2026-5932, and a reviewed recovery ceremony transition.
Vault 2.x generate-root/rekey authentication requirements differ from the
existing recovery-share-only workflow; do not bypass them or assume that
holding recovery shares alone preserves operational access. Never copy live
Raft data, tokens or recovery shares into a Docker build context.

`python3 scripts/ci/test-vault-raft-upgrade.py` reuses the two frozen images
without rebuilding. The synthetic single-node Shamir rehearsal verifies data
retention and snapshot restore, plus a short-lived exact-endpoint token minted
before upgrade. On 2.1, no/invalid tokens fail; the scoped token cannot read KV
or create tokens, but it and the synthetic share can complete root generation.
The generated root is revoked and rejection verified.

Restoring a Raft snapshot also restores its token state: the test proves the
pre-snapshot ceremony token becomes valid again and revokes it again. The
post-snapshot generated root remains absent. All task-owned containers and the
synthetic volume are removed. This is not a live HA/KMS recovery-key test.

Before upgrading the real server, establish and test the operator's repeatable
authentication path while the old server is still available. Recovery wrappers
now run `scripts/ops/lib/vault-recovery-auth.sh` before requesting shares. They
check that the server is initialized and unsealed, reject unsupported versions,
and verify read-only access to the ceremony endpoint. On 1.x the legacy flow is
retained. On 2.x, an existing process `VAULT_TOKEN` is used; otherwise a silent
terminal prompt requests a valid ceremony token. Recovery shares are still
requested separately. The token is not saved through `vault login` or written
to a token-helper file. An invalid existing token fails without starting a
ceremony; clear it in the terminal and retry with the correct credential.

The prompt is not authentication provisioning: a one-off expiring token does
not solve future recovery access. A reviewed identity-authentication method
must issue fresh short-lived tokens to the authorized human operator. Its
policy needs only the exact ceremony endpoints and self-revocation shown in
the synthetic fixture, not KV access or token creation. Test the real login,
permissions, expiry and cancellation before any server upgrade. This operator
authentication setup is still pending. Do not enable unauthenticated endpoint
access or retain a long-lived root token to avoid this migration prerequisite.

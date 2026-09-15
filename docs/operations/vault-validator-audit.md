# Vault validator audit ceremony

Enable `server.auditStorage` in the private GitOps Vault values before the
**first Vault StatefulSet installation**. It creates a separate encrypted
ReadWriteOnce audit PVC for each Vault StatefulSet Pod at `/vault/audit`; it
is not a Raft data volume. Kubernetes does not permit adding a
`volumeClaimTemplate` to an existing StatefulSet, so this setting cannot be
retrofitted with `helm upgrade`.

For an already-running Vault without the `audit` claim template, stop at the
storage gate. Plan and review a separate Raft snapshot/restore migration to a
new release that includes `auditStorage`; do not enable the file audit device
on the Raft data volume or an `emptyDir` as a shortcut.

After the Vault cluster is initialized, an approved administrator configures
two devices, never with `log_raw=true`:

```sh
vault audit enable -path=validator-file file \
  file_path=/vault/audit/validator-audit.json \
  log_raw=false hmac_accessor=false elide_list_responses=true

vault audit enable -path=validator-socket socket \
  address=/vault/audit/validator-audit.sock socket_type=unix \
  log_raw=false hmac_accessor=false elide_list_responses=true
```

The Unix socket must be bound by the separately reviewed local collector before
the second command. TCP/UDP audit sockets are prohibited because interruption
can lose records. Vault audit records are request/response pairs; downstream
deduplication joins them by `request.id`.

The collector is `vault-validator-audit-relay`: a non-root, read-only-root
sidecar which mounts only the `audit` PVC, binds the local Unix socket, and
forwards newline-delimited JSON from the socket and from newly appended file
records to stdout. The existing private Fluent Bit DaemonSet then delivers the
Pod stdout to the `validator-security` CloudWatch group and immutable archive.
Its image is built from this repository and published only by the protected
`vault-audit-relay-ecr-publish` GitHub environment to the dedicated private
ECR repository. Do not use a public image, a mutable tag, or an `emptyDir`.

Deploy the relay on all Vault members and verify every Pod has a ready relay
container before enabling `validator-socket`. Since the Vault StatefulSet is
`OnDelete`, restart standby Pods first and use the recovery-key leader
step-down ceremony before replacing the active Pod. A socket listener that is
not ready is a hard stop: enable the durable file device only after the relay
rollout, then enable the socket device and run the verifier.

Vault2.x recovery ceremonies also require an authenticated operator token,
separately from recovery shares. The scripts check this before starting a
ceremony and prompt silently when needed. Establish a repeatable operator
login before upgrading; see the [server migration prerequisites](../../.ci/vault-server-hardened/README.md).

Run `verify-vault-validator-audit.sh` through the private Vault connection
afterward. A missing per-Pod audit PVC or mount, missing device, raw logging
enabled, missing list-response elision, or altered path is fail-closed for
signer onboarding and validator duties.

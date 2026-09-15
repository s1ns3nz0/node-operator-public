# Vault v2 secret inventory

This is the authoritative inventory for Hoodi runtime custody. New workloads
must use the isolated mounts below; the historical `kv/` mount is rollback
only and must not receive new runtime records.

## `node-operator-runtime/` (KV v2)

| Path | Fields | Reader |
|---|---|---|
| `nodes/hoodi/engine-api-jwt` | `jwt` | Nethermind and Prysm Beacon only |
| `validators/hoodi/<set>/runtime/keystore` | `keystore` | Web3Signer only |
| `validators/hoodi/<set>/runtime/password` | `password` | Web3Signer only |
| `validators/hoodi/<set>/runtime/slashing-db-password` | `password` | Web3Signer and its PostgreSQL database only |
| `validators/hoodi/<set>/runtime/signer-tls` | `pkcs12_b64`, `password` | Web3Signer only |
| `validators/hoodi/<set>/runtime/client-tls` | `tls_crt_b64`, `tls_key_b64`, `ca_crt_b64` | Prysm validator client only |

No role may list metadata, read another validator set, or write at runtime.

## Existing validator deployment

For an already active validator, preserve the BLS keystore, its password, and
the PostgreSQL password exactly. The slashing DB PVC and signing history must
survive the deployment. Fresh onboarding generates a database password and
must not be used to replace the existing validator's records.

`scripts/ops/copy-hoodi-custody-to-runtime-v2.sh --validator-set hoodi-example`
is the administrator-only data preparation step. It detects the legacy mount
version, validates all three source records before writing, uses CAS=0, checks
read-back equality, and refuses conflicting destination values. It leaves
legacy records, policies, workloads, and PVCs unchanged. Re-running after a
partial copy is supported when already-created values match.

For the active validator, use the recovery coordinator with
`--validator-set hoodi-example --prepare-existing --output-dir <new-absolute-dir>`.
It preserves the three existing custody records, stages and verifies the Engine
JWT, and issues or validates the signer/client transport records. It does not
install workload policies, update Kubernetes trust configuration, or restart
workloads. A new Engine JWT requires a coordinated execution/beacon cutover;
preparation alone does not connect the running clients.

The output contains only public CA/fingerprint material and `preparation.json`.
The success evidence is written only after generated root revocation succeeds.
It is preparation evidence, not proof of migration, runtime health, or duty.

After the signing-proxy fence ceremony, the same recovery coordinator accepts
`--activate-existing --preparation-evidence <absolute-preparation.json>
--output-dir <new-absolute-dir>` alongside `--validator-set hoodi-example`.
It checks live quiescence, revalidates custody/TLS/JWT, installs the dedicated
workload roles, and updates only the public known-client ConfigMap. The
`activation.json` is emitted after root revocation and is accepted by the
Engine/validator cutover scripts through their existing `--migration-evidence`
input. The operation is explicitly distinct from historical migration evidence;
preparation alone is rejected. No client or fence replica is started by this
ceremony. Partial activation failure leaves them stopped and requires retry;
it must not be treated as permission to resume signing.

`assert-hoodi-validator-quiesced.sh` is a read-only live gate for authorization
and manifest cutover: both controllers must have observed zero replicas and
all client/fence Pods, including terminating Pods, must be absent. Historical
fence evidence is still required by the deployment workflow, but is not a
substitute for this live check. The manifest cutover also rejects a client
manifest that would start a replica before runtime verification.

The cutover accepts only complete output from the checked-out runtime/client
renderers, including the client fence resources. Before Kubernetes apply,
`verify-validator-cutover-rendering.py` compares every byte outside the bounded
renderer substitutions with the repository templates. This binds network rules,
service accounts, Vault injection, volume definitions, and container commands
to those templates. A changed policy or DB volume requires a reviewed template
change and re-render, not a hand-edited deployment manifest. Server dry-run
additionally verifies the expected 21 resource identities and zero replicas for
signer, client, and fence. This does not itself prove live DB preservation or
successful Engine/signing traffic; those remain runtime acceptance checks.
Signer, PostgreSQL, and fence images must retain the exact digests read from
the live workload templates. This migration cannot also upgrade those images;
an image replacement requires a separate reviewed deployment. The Prysm client
must additionally remain an exact stage-approved artifact in the repository.

For existing workloads, client-side canonical validation precedes a narrowly
derived apply payload: the live signing Lease and slashing DB claim templates
are omitted to preserve their current ownership and state. Desired/live claim
configuration must match and retention must be `Retain`. Only the remaining
canonical fields transfer server-side ownership. Server dry-run must pass, and
the bound slashing PVC UID and backing volume must remain unchanged after apply
before the signer can start. No StatefulSet/PVC delete-and-recreate is used.

Remaining live acceptance requirements:

- Complete the user-controlled recovery ceremony and confirm root revocation.
- Prepare all six runtime records, issuing transport certificates from PKI.
- Fence the existing validator before changing workload authentication.
- Apply the immutable Engine chart and validator manifests; retain the DB PVC.
- Verify Vault Agent initialization, Engine authentication, signer mTLS and
  successful DB authentication before resuming the client.
- Verify a subsequent canonical validator duty and collect non-secret evidence.
- Remove superseded Kubernetes credential Secrets only after these checks.

## `node-operator-pki/` (PKI)

The issuer private key remains inside the PKI secrets engine. Workloads never
receive it. Only a reviewed rotation ceremony may issue signer/client mTLS
leaf certificates. The issuer is stable across normal leaf rotation; root or
issuer rotation is a separate recovery exercise. The client trust bundle and
known-client fingerprint are public configuration, not KV secrets.

## Never store in Vault

- validator mnemonic, withdrawal seed, Vault root/recovery/unseal material;
- Vault server TLS private key, bootstrap GitOps credential, or static AWS and
  GitHub credentials;
- projected Kubernetes, SSM, OIDC, or Vault child tokens;
- public validator key, withdrawal address, deposit hash, CA certificate, or
  known-client fingerprint.

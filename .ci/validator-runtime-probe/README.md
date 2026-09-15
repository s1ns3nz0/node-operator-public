# Temporary runtime diagnostics

This is not a signing client or a general Vault CLI. The binary has four fixed
diagnostic modes: mTLS GET of one validator's public key and a workload-specific
Vault GET/LIST status matrix, Engine `eth_chainId` JWT authentication, and a
bounded Engine TCP network-denial observation.
It never calls a signing endpoint or writes KV data.
In the Vault boundary mode, successful secret response bodies are closed without decoding or retaining them.
Transport memory can still contain response bytes; this is not a zero-memory claim.

Build and test locally:

```sh
go test -race ./cmd/validator-runtime-probe
go vet ./cmd/validator-runtime-probe
python3 scripts/ci/test-validator-runtime-probe-renderer.py
docker build --platform linux/amd64 -f .ci/validator-runtime-probe/Dockerfile \
  -t node-operator-validator-runtime-probe:local .
```

Publication and live diagnostics require explicit task authorization. Scan the
exact image and use its registry digest, never a mutable tag, in probe Pods.
Do not weaken admission or NetworkPolicy to admit a probe.

The renderer only prints manifests. **Do not apply the entire List together.**
TLS pre-positive, negative cases, and post-positive must run sequentially in a
reviewed maintenance window with the real client and Fence at zero. TLS Pods
need the Fence network label, which can match the public signer Service; the
never-ready gate is defense in depth, not a substitute for quiescence. Confirm
cleanup of each owned Pod by UID before recovery. No probe may remain at restart.

Vault probes authenticate as their actual workload ServiceAccounts. Each token
is process-local, never renewed, and at most ten minutes. A self-revocation 204
is reported as revoked. If denied, expiry remains pending and must be accounted
for before closing the maintenance evidence; policy must not be widened. An
unbounded lease or lost login response is unresolved, not successful cleanup.

Only explicit TLS authentication failures count as negative TLS proof. HTTP
401/403, timeouts, DNS failures, and connection resets are inconclusive. The
positive probe verifies server CA/SNI and the exact public key, not a server leaf
fingerprint. GET/LIST results do not establish effective write/delete denial.

The renderer's default List includes client, signer, and DB Vault probes.
The `engine_vault()` and `engine_auth()` helpers provide separately invoked
Engine placements. Their labels match running Services: require every matching
Service to have `publishNotReadyAddresses=false`, preserve both the never-ready
gate and failing readiness probe, and declare no ports. Engine controls need no
validator maintenance window and must never become Ready Service backends.

Engine positive controls inject only the Engine JWT through Vault Agent and
issue fixed POST `eth_chainId` to `nethermind-engine.node-operator.svc:8551`.
The expected chain is decimal 560048 (`0x88bb0`). Missing/wrong controls have
no Vault injection or secret volumes. They accept only HTTP 401/403 as proof
of authentication rejection; timeout or transport errors are inconclusive.
These test the Prysm consumer path, not every possible network source.

The separate `engine_network_deny()` helper removes the Prysm allow label and
all Vault injection. It attempts only TCP port 8551, without HTTP or JWT. Only
a bounded connection timeout is a denial observation; refused connections,
DNS failures, cancellation, and successful connections are inconclusive.
Attribute that observation to the intended network boundary only when fresh
positive controls on the same node/image bracket it, the destination matches
the ready Engine endpoint, and observed policy selectors exclude the source.

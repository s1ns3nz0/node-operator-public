# Vault GO-2026-5932 applicability assessment

Scope: the three immutable subjects in `.ci/vault-runtime-candidates.json`,
and only the Unknown finding `GO-2026-5932` on `golang.org/x/crypto v0.56.0`.
Review expires **2026-10-09T00:00:00Z**. This is package non-applicability,
not acceptance of a reachable vulnerability or an OS/Vault blanket exception.

## Basis

The [official Go advisory](https://vuln.go.dev/ID/GO-2026-5932.json), checked
2026-09-09, names the unmaintained `golang.org/x/crypto/openpgp` package and
six subpackages, not every package in the module. Hosted Grype 0.118.0 run
[34314957185](https://github.com/s1ns3nz0/node-operator/actions/runs/34314957185)
reported module-level matching because the stripped binaries lack function
symbols. That warning alone is **not** evidence of non-applicability.

The reviewed build dependency closures exclude the affected package tree:
Server 2,635 packages, Agent 1,973, Injector 786. Server and Injector carry
their build inventory inside their pinned images. Agent's existing public
build export is retained once in
`.ci/vault-runtime-applicability/agent-dependencies.txt`; its exact SHA-256
and the runtime binary SHA-256 match the previously reviewed evidence export.
No private Vault state, token, key, or runtime secret is part of this inventory.

The Server/Agent candidates now use the gRPC 1.83.2 patch from PR144.
Their binary hashes changed and were re-bound to new exact OCI subjects;
their complete package-name inventories did not change. Old gRPC 1.83.1
candidates are not eligible under the current manifest. The new build and
publication evidence is in `plans/2026-09-09-vault-grpc-security-patch/`
and `plans/2026-09-09-vault-grpc-candidate-publication/`. Injector is unchanged.
The assessment scope and expiry were not widened for the new candidates.

## Controls and limitations

- Bind registry subject, runtime identity, SBOM, raw scan, binary hash and the
  full dependency-list hash to one reviewed candidate. Never use a mutable tag.
- Require the pinned advisory's hash and live advisory content to match; fail
  on content drift or unavailability. Verify the affected tree remains absent.
- Keep the raw scan and its blocked summary byte-for-byte. Produce a separate
  `applicability-decision.json` with the retained raw counts and proof bindings.
- Never allow Critical/High, additional Unknown findings, changed module
  versions or missing/expired evidence through this path.
- Upload hashes, public dependency inventory, current advisory and both scan
  and decision documents. No change to the general release attestation verifier.

Hashes bind reviewed evidence to the frozen bytes; they do not independently
prove the historical compiler/build environment. The dependency exports are
manually reviewed build evidence, **not** GitHub-built/SLSA provenance. A
separate honest signing/provenance review and live HA/KMS/auth/admission gates
remain required before any deployment. Medium BusyBox findings stay visible
and are outside this assessment.

## Reassessment triggers

At expiry, or on any image/source/dependency/advisory change, re-evaluate the
actual package reachability and run fresh scans. If the affected package is
present, remove/replace it and review a new candidate; do not extend this
assessment merely to make CI green. A new build is not required just because
an observation job failed or timed out.

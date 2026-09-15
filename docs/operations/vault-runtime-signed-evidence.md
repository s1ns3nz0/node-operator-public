# Vault runtime signed verification evidence

This is a detached signature over the exact Server, Agent and Injector image
subjects and their verified evidence. It is **not** an OCI registry signature,
SLSA build provenance, or authorization to deploy. These images were built
locally. GitHub can honestly attest that its workflow verified their frozen
bytes, not that it built them.

## Producer

After this implementation is merged and its source checks pass, explicitly
request a signing run:

```sh
gh workflow run operations-verification.yml --ref main -f target=vault-runtime -f sign_evidence=true
```

The default remains `sign_evidence=false`. The three jobs pull and rescan
existing candidates; no image rebuild or ECR write is needed. The separate
signing job requires all three to succeed and rechecks the source revision's
trusted CI decisions and merged PR. It downloads only the same run's artifacts
and rejects mismatching run attempts. Re-run **all jobs**, not only failed jobs,
if an attempt mismatch is reported; do not relabel old evidence.

The signing job never requests AWS credentials. It uses GitHub OIDC and
Cosign 3.1.2 to sign `verification-statement.json` into a Sigstore bundle.
Default certificate and transparency-log verification are retained. Public
workflow identity and signing metadata are recorded by Sigstore; no private
Vault tokens, keys or state are inputs. GitHub's OIDC permission is job-wide;
this isolation is not a claim that IAM prevents all main jobs assuming the
existing branch-bound read-only ECR role.

Only a successfully verified output is uploaded as
`vault-runtime-signed-evidence-<attempt>`, with complete public evidence and
30-day retention. Archive it in the separately approved release/evidence
store before expiry if longer retention is needed. Artifact retention does
not extend scan freshness or applicability expiry.

## Consumer / GitOps ownership

Use the verifier and policy manifests from a reviewed, immutable checkout,
not executable code extracted from the downloaded evidence. Install the
repository-pinned Cosign tool using the checksum-verifying installer on
Linux/amd64. Obtain expected revision, run ID and attempt from the reviewed
release record, **not from the statement being verified**.

```sh
gh run download APPROVED_RUN_ID --repo s1ns3nz0/node-operator \
  --name vault-runtime-signed-evidence-APPROVED_ATTEMPT --dir evidence
bash scripts/ci/verify-vault-runtime-signed-evidence.sh \
  evidence APPROVED_40_HEX_REVISION APPROVED_RUN_ID APPROVED_ATTEMPT
```

The verifier accepts either exact workflow identity used for the historical
manual verifier (`vault-runtime-candidate-verification.yml`) or its replacement
(`operations-verification.yml`); it requires the same issuer, source SHA, repository,
main ref and manual trigger for either identity. It then regenerates the statement from all three
evidence sets and trusted policy files. It rejects modified/missing/symlinked
evidence, wrong subjects/runs/attempts, unresolved findings, stale scans over
24 hours, databases over 48 hours old, and expired applicability decisions.
The raw Unknown count remains visible; only the existing narrow reviewed
non-applicability decision can resolve it.

The GitOps repository must separately enforce this verifier before promotion,
compare **every proposed manifest image** against the approved statement's
subjects, and retain its own decision evidence. That integration is not
implemented by this source-repository step. Never replace the general release
scan-attestation verifier with this specialized exception path. Vault HA/KMS,
live authentication/admission, rollback and validator/PVC protection remain
mandatory operational gates.

## Verification basis

The bundle mechanism and explicit identity checks follow the
[Sigstore CI quickstart](https://docs.sigstore.dev/quickstart/quickstart-ci/)
and the pinned [Cosign 3.1.2 verification interface](https://github.com/sigstore/cosign/blob/v3.1.2/doc/cosign_verify-blob.md).
Offline synthetic-key tests exercise cryptographic tamper rejection only;
they do not establish a successful GitHub OIDC/Fulcio/Rekor run. Hosted signing
must be observed after merge before reporting the signing step complete.

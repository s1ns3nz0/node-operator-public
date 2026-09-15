# Release scan-summary attestation v1

Relay and signing-fence producers and consumers use this exact predicate URI:

`https://github.com/s1ns3nz0/node-operator/attestations/scan-summary/v1`

The predicate is the unmodified JSON output of `scan-release-sbom.sh`: schema
version, Grype/version/database metadata, image digest, SBOM hash, scan time,
all severity counts and decision. Cosign's built-in `vuln` type has a different
typed schema; supplying our summary to it drops fields. Do not switch to
`custom` either, since that alias wraps the data instead of preserving this
object. The explicit versioned URI preserves the JSON object.

Verification order:

1. Cosign verifies the exact image's signature and attestations against the
   workflow identity, GitHub issuer, source revision and transparency log.
2. `verify-release-scan-attestation.sh` validates the already verified payload,
   exact URI, subject digest and complete summary contract. Critical, High and
   Unknown must be zero; this repair introduces no risk exception.
3. Relay additionally requires structural equality with its raw registry scan
   summary. Fence verifies the signed summary and then performs its existing
   fresh registry scan. Missing or incompatible older evidence is rejected.

The content helper does not verify signatures on its own. Never call it on
untrusted raw attestations and describe the result as authenticated evidence.

`test-release-scan-cosign-roundtrip.sh` runs the pinned CLI with disposable
synthetic keys, reproduces the old lossy conversion, checks exact JSON
preservation, and rejects a modified blob. Its local bundles deliberately omit
transparency logging, and its verification flag is test-only. Neither release
workflow changes the real artifact's keyless or transparency-log verification.
The fixture executes before AWS credentials are acquired; all test keys are
removed on exit. This test is not a substitute for the actual GitHub release.

Source: [Cosign3.1.2 statement generation](https://github.com/sigstore/cosign/blob/v3.1.2/pkg/cosign/attestation/attestation.go).

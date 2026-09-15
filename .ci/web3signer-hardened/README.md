# Pinned Web3Signer runtime

Build with `scripts/ci/build-validator-images.sh web3signer`. The build pins the
upstream commit, builder and runtime images, verifies each patch hash, and runs
the core/signing/keystorage/slashing-protection tests as a non-root user. Build
success is not deployment approval or scan evidence: scan the exact output and
bind its registry digest before a reviewed single-signer rollout.

## Signing audit contract

The metadata patch emits `signing_audit` INFO events for the Ethereum consensus
signing handler. Each handled request receives a server-generated
`audit_request_id`; no caller request-ID header is copied into the event.

Validated requests record the normalized BLS public key, artifact type,
**computed** signing root, applicable slot and attestation source/target epochs,
and a fixed result (`SUCCESS`, `REJECTED_SLASHING`, or `NOT_FOUND`). Invalid
requests record only the generated ID and `INVALID_REQUEST`. No request body,
signature, exception, password, private key or caller header is an event field.

`SUCCESS` means the handler authorized returning the signature after its
existing checks. It does not prove the client received it or the duty was
included on chain. Join the computed root and duty fields with the slashing DB,
client submission and canonical finalized inclusion evidence. Join the audit
event's timestamp/container identity with its archived copy separately.

The patch does not change signature computation, slashing protection decisions,
key custody or transport authentication. Audit emission precedes the original
response/failure action but a runtime audit failure does not replace that HTTP
outcome. Logging is best-effort: missing events remain a possible evidence gap,
not proof that no signing request occurred. It is not a
router-wide log sanitizer: upstream error handlers and unrelated APIs have
their own logging behavior. Keep optional request-body/access logging disabled
and do not infer end-to-end completeness from one event.

Before rollout, stop the single client/Fence through existing maintenance
gates, preserve the slashing PVC, fingerprint the allowlisted DB tables, and
replace only the stopped signer with the reviewed immutable image. Compare DB
fingerprints while signing remains quiesced, verify mTLS/public-key identity,
then restore through existing activation gates. Do not run parallel signers or
submit conflicting production-key requests to test logging.

# CI image signature boundary

The scanner and six toolchain publication jobs in `image-publish.yml` share
`scripts/release/sign-ci-image-evidence.sh`. Build jobs have no registry-write
or OIDC permission. Main-branch publication jobs receive those permissions.

## Publication checks

1. Verify the original archive, SBOM and build receipt, then require OPA's
   publication decision to unify with true. Denial occurs before registry login.
2. Push the source-SHA tag, hash its raw registry manifest, fetch that digest
   again and require byte equality. Require its config digest to match the
   local image checked against the receipt. Multi-platform indexes are rejected.
3. Sign the exact registry digest with Cosign. Attach the original CycloneDX
   SBOM and the custom `image-build-receipt/v1` predicate to that digest.
4. Verify the image signature and both attestations against the exact
   `image-publish.yml@refs/heads/main` identity, GitHub OIDC issuer and source SHA.
   Parse the verified payloads and require the exact image subject and local
   predicate contents, not merely successful command exit.
5. Only then promote the `main` tag. A failed signature operation may leave the
   candidate SHA tag in the registry, but must not update `main`.

The SBOM retains its original Docker archive hash as its source version. The
signed receipt connects that archive and SBOM to the image config; the checked
manifest connects the config to the registry digest. Do not replace the SBOM's
source version with a new digest after scanning.

The build receipt's `signature`, `registry_manifest_digest` and `sca` claims
remain false: it describes build-stage evidence, not later verification. The
surrounding verified attestations add signature evidence without rewriting
history. This custom receipt is not a SLSA provenance claim or an SCA result.

## Evidence and outstanding integration

Successful jobs retain the manifest, original predicates and verification
outputs as separate 90-day GitHub artifacts. Registry signatures remain
attached to the immutable subject. GitHub artifacts alone are not the requested
immutable S3 completion archive; that integration remains outstanding.

Local tests exercise real publisher ordering with traced registry/signing
doubles, and helper subject/predicate rejection with Cosign output fixtures.
These are not GitHub OIDC, transparency-log or registry cryptographic E2E
proof. Every downstream image consumer must independently verify the approved
digest and signing identity before execution; producer self-verification does
not establish that consumer gate. Existing released images are not retroactively
signed by this change.

The private-runner smoke consumer requires three reviewed variables in the
`private-runner-smoke` environment: `RELEASE_BUILD_IMAGE` (digest reference),
`RELEASE_BUILD_SOURCE_SHA` and `RELEASE_BUILD_PUBLICATION_RUN_ID`. It downloads
`toolchain-sbom-release-build-<source SHA>` from that run, then verifies the
signature, original SBOM and receipt before Docker access or registry login.
Missing approval values or expired artifacts fail closed. Do not derive an
approved source SHA from the candidate image. Other image consumers still need
equivalent integration; this path does not establish complete consumer coverage.

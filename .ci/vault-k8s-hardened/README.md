# Hardened Vault Kubernetes injector candidate

Source is official v1.7.6 commit
`fbc5b1f0cd4d1c7dd5a8830e32c8ed636d7318d7`. The application source is unchanged;
Go is upgraded to1.26.6, x/crypto to0.56.0, and runtime OpenSSL to a patched
repository version. Every image rebuild requires a new exact-image scan.

The Docker build executes all upstream Go tests, including certificate tests
that require the builder-only OpenSSL executable. It preserves the final module
files, their diff, build information, dependency closure and upstream license.
The reviewed module diff upgrades x/crypto0.54→0.56, x/text0.40→0.41 and
transitive tools/mod checksums. Exact final go.mod/go.sum hashes are enforced
in the build and runtime verifier; upstream changes fail closed. This is not
a live admission-webhook test. The affected OpenPGP package closure is absent
and guarded against future inclusion; retain the original Unknown scan finding.

Build with Docker Buildx using this Dockerfile and linux/amd64, then pass the
immutable local image ID and a new scan path to
`scripts/ci/verify-vault-k8s-image.sh`. That verifier executes offline version,
help, ownership and module checks, then requires a valid unfiltered Grype scan
with no Critical/High or ignored findings. It does not waive Unknown findings.

Before live rollout, verify generated admission patches against existing Vault
Agent image/CA/auth/volume settings and observe a non-sensitive scoped canary.
Do not change the Vault server, credentials or existing custody policies as
part of an injector-only rollout. No publication/deployment is performed here.

Candidate delivery checkpoint2026-09-09: the reviewed frozen index is published
at `123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-vault-runtime-injector@sha256:2937fbc5d368430d089b9b94f82b44baab71524d166358bb8ea48f7b395152d4`.
Exact registry identity and full C/H=0 scan passed. This is manual candidate
delivery only; CI attestation, admission canary and live rollout remain open.

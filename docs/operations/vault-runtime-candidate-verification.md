# Frozen Vault runtime verification

This manual CI job verifies the three reviewed immutable ECR subjects in
`.ci/vault-runtime-candidates.json`. It never builds, pushes, signs, deploys,
reads Vault data or runs Terraform. A passing scan is **not** a trusted build
provenance statement or a live deployment authorization.

The optional `sign_evidence=true` input adds a separate job that signs a
digest-bound verification statement after all three checks pass. The default
is still read-only verification without signing. See
[signed evidence and consumer verification](vault-runtime-signed-evidence.md).

## One-time setup after the change is merged

1. Keep existing node/runtime ECR inputs enabled. Set
   `enable_vault_runtime_ci_verifier=true` in the complete reviewed Terraform
   inputs. Inspect a saved plan: only the verifier role and its inline policy
   should be added for this setup. Do not apply incomplete state-reconciliation
   inputs or a broad plan as a shortcut.
2. Set repository variable `VAULT_RUNTIME_VERIFIER_ROLE_ARN` to the Terraform
   output `github_vault_runtime_ci_verifier_role_arn`. This job intentionally
   has no GitHub environment: the IAM subject binds directly to
   `${github_oidc_subject_prefix}:ref:refs/heads/main`, including the existing
   immutable owner/repository IDs. This needs no paid environment protection.
   Adding an environment changes the token subject and must fail authentication.
   Other workflows on main with OIDC permission can assume this read-only role;
   it is branch-bound, not an exact-workflow identity or code-review guarantee.
3. Dispatch `CI Operations` with the `vault-runtime` target from `main`. The workflow
   itself also rejects every other branch. Its role can pull only these three
   repositories; it cannot publish images, access EKS or read secrets.

## Evidence and blocked outcomes

Each component retains runtime image identity, version output, CycloneDX SBOM,
unfiltered raw Grype JSON and a digest-bound summary for 30 days. Images run
only for a bounded version probe, without network, credentials, mounts or
privileges. The workflow does not claim an auth, Raft, admission or duty test.

The raw scan summary still blocks on Critical, High and Unknown findings and
is never rewritten. A **separate applicability decision** can recognize only
GO-2026-5932 on `golang.org/x/crypto v0.56.0` as `not_affected` for the three
exact reviewed candidates. CI then gates on that separate decision, retains
the raw Unknown count, and uploads both documents. No Grype exclusion or
generic release scan-attestation behavior is changed.

The decision requires every binary and dependency-list SHA-256 in
`.ci/vault-runtime-applicability.json` to match, exact raw/SBOM/runtime subject
binding, no affected `golang.org/x/crypto/openpgp` package or subpackage, and
the current official advisory to match the pinned reviewed record. The
assessment expires at **2026-10-09 00:00 UTC**. New Unknown findings, a raised
Critical/High severity, changed images/metadata/advisory, missing proof or an
expired review fail closed. See [the assessment](vault-runtime-applicability.md).

Only after this observation step and exact-candidate assessments may a
separately reviewed signing/promotion step establish its own honest provenance
(verification of an existing candidate, not a fictitious GitHub build).
Server HA/KMS recovery, Agent live authentication, Injector admission and
GitOps rollout gates remain separate. Existing validator identities and PVCs
must be preserved.

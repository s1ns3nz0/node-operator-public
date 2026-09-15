# Long-term CI evidence archive

The `CI Evidence Archive` workflow archives only a successful, exact-head `CI
Evidence Gate` artifact. It never uploads a workspace, raw scanner output,
credentials, Vault material, or recovery shares.

Terraform creates the following resources when
`enable_ci_evidence_archive = true` (the default):

- a versioned S3 bucket with Compliance Object Lock and SSE-KMS;
- a dedicated KMS key with automatic rotation;
- an exact GitHub OIDC role scoped to the `ci-evidence-archive` environment;
- an IAM policy limited to `s3:PutObject` and `s3:GetObject` below `ci/*` for
  upload and byte-level read-back verification.

After applying Terraform, configure these two repository/environment variables
on the protected GitHub environment named `ci-evidence-archive`:

```text
CI_EVIDENCE_ARCHIVE_BUCKET=<terraform output ci_evidence_archive_bucket_name>
CI_EVIDENCE_ARCHIVE_ROLE_ARN=<terraform output ci_evidence_archive_role_arn>
```

Before upload, `scripts/ci/archive-ci-evidence.sh` accepts only the four
allowlisted redacted files: `evidence.json`, `decision.json`, and the optional
`cache-context.json` and `baseline-summary.json`. It verifies that the gate
decision permits archival, binds the manifest to the exact commit SHA and
workflow run, then signs and verifies that manifest with the pinned keyless
Cosign identity and workflow claims.

After upload, the script retrieves the manifest, its Sigstore bundle, and each
member named by the retrieved allowlisted manifest into a fresh private
directory. It verifies the retrieved signature with the same identity and
workflow restrictions, checks the subject/run binding, and compares every
retrieved member's SHA-256 to the signed manifest. Missing, changed, unsafe, or
unallowlisted objects fail the archive step. A successful local run therefore
establishes read-after-write integrity for that execution; it is not a claim
that any particular historical archive has been retrieved or verified.

The S3 bucket retains objects with Object Lock and SSE-KMS. Those storage
controls complement, but do not replace, signature and hash verification on
retrieval.

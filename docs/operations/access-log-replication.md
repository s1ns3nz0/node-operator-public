# Access-log replication

This configuration provides live, one-way S3 cross-region replication from
the Seoul access-log buckets to the existing Tokyo DR access-log buckets:

| Source | Included object prefixes | Destination |
| --- | --- | --- |
| `audit_access_logs` | `audit/`, `validator-audit/`, `vault-snapshot/` | `audit_replica_access_logs` |
| `release_artifacts_access_logs` (when `enable_release_signer=true`) | `release-artifacts/` | `release_artifacts_replica_access_logs` |

The Terraform addresses are
`aws_s3_bucket_replication_configuration.audit_access_logs` and
`aws_s3_bucket_replication_configuration.release_artifacts_access_logs[0]`,
with their corresponding dedicated `aws_iam_role` and `aws_iam_role_policy`
resources in `access-log-replication.tf`.

S3 replication preserves object keys. The destination writes therefore use
those same prefixes; they do not write to `audit-replica/` or
`release-artifacts-replica/`. Those latter prefixes are reserved for the Tokyo
source buckets' own server-access-log delivery and remain non-colliding.

Each configuration has a dedicated role with the documented `s3.amazonaws.com`
service trust. Its separate identity policy limits source reads and destination
writes to the listed bucket and prefix ARNs; the trust policy does not rely on
`aws:SourceArn` or `aws:SourceAccount`, because the S3 replication
AssumeRole request does not document those context keys. It does not grant
deletion, ownership override, KMS, batch replication, replica-modification
synchronization, or reciprocal-replication permissions. Both destination
buckets keep their existing AES256 (SSE-S3) default encryption; the replication
rules deliberately do not set a destination KMS encryption configuration.

S3 live replication applies to objects created after its configuration is
added; it is not a backfill mechanism. S3 also does not automatically
re-replicate replicas, so the absence of a reciprocal rule is intentional.
See [What does Amazon S3 replicate?](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-what-is-isnot-replicated.html)
and [Setting up permissions for live replication](https://docs.aws.amazon.com/AmazonS3/latest/userguide/setting-repl-config-perm-overview.html).

## Activation evidence and future changes

On 2026-09-08, the explicitly reviewed saved plan created only the two
replication configurations, two dedicated IAM roles, and two inline policies;
it contained no update, replacement, or deletion. Both configurations read
back enabled with delete-marker replication disabled. One retained, zero-byte,
non-secret canary per source reached `COMPLETED` and appeared at the same key in
the corresponding Tokyo bucket as an AES256-encrypted `REPLICA`. A targeted
post-activation plan reported no managed change. The durable evidence and
remaining boundaries are in
`reports/2026-09-08-security-remaining-status.md`.

Any future rule, role, prefix, region, backfill, delete replication, ownership,
or encryption change requires a new saved plan and approval. Do not use S3
Batch Replication or another backfill process without separate authorization.

The existing Seoul-to-Tokyo DR pattern incurs inter-region replication transfer,
destination S3 request, and destination storage/lifecycle charges. Estimate
the observed access-log volume and retention before activation; lifecycle
policies retain the current 90-day Standard-IA and 365-day Glacier transition
pattern, with 365-day expiry for these log buckets.

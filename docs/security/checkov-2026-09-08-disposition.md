# Checkov disposition, 2026-09-08

This register reconciles the complete Checkov 3.2.522 result, not just the
delta from the base branch. `filter-pr-baseline-findings.sh` must pass every
Checkov finding to OPA. No finding is exempt merely because it already exists.
The existing nine KMS/EKS entries remain in
`checkov-kms-eks-exception-register.md`.

New entries in `policy/data/exceptions.json` match an exact Checkov ID and
resource address. Owner: `fjybjinsu`. All expire on **2026-10-03T00:00:00Z**.
An unmatched finding, changed resource address/check ID, or expired exception
must block. These are explicit policy deviations, not claims that the scanner
reported zero findings. No infrastructure apply is implied by this register.

## Fixed controls

- Bootstrap state and lock table use a dedicated rotating CMK with a key policy.
- Foundation VPC has encrypted ALL-traffic flow logs and a deny-all default SG.
- Operations-host rules have descriptions; instance monitoring/EBS optimization
  are enabled. Newly created endpoint SG attachment is explicit in the graph.
- Workload CloudWatch retention is 365 days.
- Firehose buffering uses a dedicated CMK, distinct from S3 encryption. The
  CloudWatch subscription producer has `GenerateDataKey`/`Decrypt` on that key;
  its key policy names that producer. Destination encryption remains enabled.
- State, validator audit, and Vault snapshot buckets have access logging and
  EventBridge notifications. State/snapshot lifecycle aborts incomplete uploads
  only; completed states/snapshots are not expired by that rule.
- Mirror OIDC trust uses the exact observed owner/repository IDs and environment
  with `StringEquals`. Wildcard repository IDs and legacy subjects are removed.

## KMS-EBS

`CKV_AWS_111` and `CKV_AWS_356`, resource
`aws_iam_policy_document.ebs_key`: `Resource: "*"` is the key-policy form for
the containing key. Named Auto Scaling and EBS CSI roles are the only workload
principals; grants require `kms:GrantIsForAWSResource`. This is not an IAM
identity policy granting use of every account key. Any principal/action/grant
condition change requires review. See [AWS key policies](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html).

## KMS-BUFFER

`CKV_AWS_111` and `CKV_AWS_356`, resource
`aws_iam_policy_document.validator_firehose_buffer`: the wildcard denotes this
dedicated CMK, and only the named CloudWatch subscription producer receives
`GenerateDataKey` and `Decrypt` in addition to the existing key-administrator
policy. It does not widen access to the archive CMK. Review on any principal or
action change. [Firehose CMK caller requirements](https://docs.aws.amazon.com/firehose/latest/dev/encryption.html)
also require `kms:CreateGrant` for the infrastructure identity enabling SSE;
verify that identity before apply. Do not guess a Firehose encryption-context
format; AWS documents it as system-generated.

## OIDC-IDS

`CKV_AWS_358`, resource
`aws_iam_policy_document.github_gitops_oci_mirror_assume_role`: the pinned
scanner still reports the ID-bearing GitHub subject form. The GitHub OIDC
configuration was read directly and reported
`repo:s1ns3nz0@258690008/node-operator@1353388960`. Terraform now requires a
non-wildcard ID-bearing prefix and appends exactly
`:environment:gitops-oci-mirror`, with `aud = sts.amazonaws.com` and exact
repository claim. A subject-template, repository ID, owner ID, or environment
change invalidates this exception; migrate the trust explicitly.

## ECR-LEGACY

`CKV_AWS_136`, the seven exact `aws_ecr_repository.private_gitops` instances:
`argocd`, `cert_manager`, `cert_manager_chart`, `charts`, `nodes`, `vault`,
`vault_chart`. A live `DescribeRepositories` check confirmed **AES256** and
**IMMUTABLE** on each on 2026-09-08. These are encrypted mirrors of deployment
artifacts, not stores for credentials, keystores, or user data. Digest-reviewed
inputs and `prevent_destroy` remain enforced. AWS does not support changing
an existing repository's encryption configuration in place; replacing these
repositories would disrupt retained deployment inputs. The limited deviation
is the absence of a customer-managed key, not absence of encryption.

No additional ECR repository is covered. Secret/private-data publication,
mutable tags, removed deletion protection, or a new repository requires a new
decision. Before expiry either renew with fresh evidence or migrate artifacts
to separately created KMS repositories and verify consumers before retiring the
old repositories. [AWS ECR encryption immutability](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html)

## REGIONAL-DR

`CKV_AWS_144`, the exact buckets `aws_s3_bucket.state`,
`aws_s3_bucket.state_access_logs`, `aws_s3_bucket.validator_audit`, and
`aws_s3_bucket.vault_snapshot`: this environment's state/backup/validator
archive is regional. Versioning, encryption, restricted access, and logs are
configured; validator audit and Vault snapshots additionally use Object Lock.
Cross-region recovery has **not** been established for these four buckets.
Automatically selecting a second region would create a new recovery and data
placement contract. Regional failure remains an explicitly accepted limitation
for this Hoodi test environment until the expiry date. This exception does not
cover production or the separate replicated CloudTrail archive. Before a
production claim or expiry, establish and test cross-region restore or reject
the promotion; never infer cross-region durability from S3 versioning.

## S3-LOG-ENCRYPTION

`CKV_AWS_145`, exact resources `aws_s3_bucket.state_access_logs`,
`aws_s3_bucket.audit_access_logs`, `aws_s3_bucket.audit_replica_access_logs`,
`aws_s3_bucket.release_artifacts_access_logs`, and
`aws_s3_bucket.release_artifacts_replica_access_logs`: these dedicated S3
server-access-log destinations use SSE-S3 because server log delivery does not
support SSE-KMS as an interchangeable destination setting. Its bucket policy
restricts delivery to `logging.s3.amazonaws.com`, the exact source bucket and
account, denies insecure transport, and blocks public access. State content
itself uses a CMK. A destination-purpose, principal, or encryption change
requires review. [AWS server access log encryption guidance](https://repost.aws/knowledge-center/s3-server-access-log-not-delivered)

## TERMINAL-REPLICA

`CKV_AWS_144`, exact resources `aws_s3_bucket.audit_replica_access_logs` and
`aws_s3_bucket.release_artifacts_replica_access_logs`: these Tokyo buckets are
the terminal destinations for the corresponding Seoul access-log replication
rules. The two primary access-log buckets now have live, prefix-scoped CRR;
both zero-byte canaries reached `COMPLETED` and arrived as `REPLICA` objects.
S3 does not replicate replica objects again by default. Adding another CRR hop
only to satisfy the same bucket-level rule would create a third-region data
placement contract and repeat the terminal-destination obligation.

This exception does not cover either primary access-log bucket, deletion
replication, reciprocal replication, or production DR. Revisit it before
expiry, or immediately if the recovery topology, region, bucket purpose, or
environment classification changes. The distinct validator-audit and Vault
snapshot regional-DR findings remain governed by `REGIONAL-DR`; this exception
does not claim they were remediated.

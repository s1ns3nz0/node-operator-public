# Checkov KMS and EKS exception register

## Scope and decision

This register records the nine remaining Checkov 3.2.522 findings observed
against `infra/terraform` on 2026-09-03. It is **not** a blanket Checkov
suppression. Each row is limited to one Checkov ID and one Terraform resource.
Any resource rename, policy-statement change, EKS version below 1.28, new KMS
principal, or expansion of a permitted action requires a new review rather
than reuse of this record.

The review owner is the security owner recorded in CODEOWNERS. The tracking
reference is this versioned register because no external issue was authorized
for this review. Re-review is required before 2026-10-03, and immediately on
any of the triggers listed per row. An expired record must block the gate.

## Registered findings

| Register ID | Checkov ID | Terraform resource | Why it is structurally reported | Compensating controls | Re-review trigger |
| --- | --- | --- | --- | --- | --- |
| KMS-001 | `CKV_AWS_109` | `aws_iam_policy_document.kms_key_administrator` | KMS key policies use `Resource: "*"` to identify the key being governed; AWS KMS key policy syntax does not accept the key ARN as a replacement in this context. The dedicated administrator requires lifecycle and policy-management permissions. | Only `aws_iam_role.kms_administrator` is the principal; it has a separate assume-role boundary. The statement is embedded only in purpose-specific KMS key policies. | Administrator principal, assume-role policy, `kms:*`, or policy attachment changes. |
| KMS-002 | `CKV_AWS_111` | `aws_iam_policy_document.kms_key_administrator` | Same required KMS-key resource form; Checkov treats the administrator's KMS write permissions as unconstrained. | Dedicated administrator principal and isolated KMS key-policy use as in KMS-001. | Same as KMS-001. |
| KMS-003 | `CKV_AWS_356` | `aws_iam_policy_document.kms_key_administrator` | The wildcard names the current KMS key inside a key policy, not every key in the account. | Dedicated administrator principal; no account-root `kms:*` grant. | Same as KMS-001. |
| KMS-004 | `CKV_AWS_109` | `aws_iam_policy_document.audit_replica_key` | The replica KMS key policy contains the same required key-policy resource form and its inherited dedicated administrator statement. | Administrator statement is limited to the dedicated role; replication permissions use named source role, S3 service path, account, region, and S3 encryption-context constraints. | Any replica principal, KMS action, `kms:ViaService`, or encryption-context change. |
| KMS-005 | `CKV_AWS_111` | `aws_iam_policy_document.audit_replica_key` | Checkov cannot infer the KMS key-policy semantic of `Resource: "*"` and reports write-capable KMS statements. | Named replication role and scoped service/context conditions as in KMS-004; key rotation and 30-day deletion window are enabled. | Same as KMS-004. |
| KMS-006 | `CKV_AWS_356` | `aws_iam_policy_document.audit_replica_key` | The wildcard is required to refer to the replica KMS key within its own key policy. | Named principals and service/encryption-context conditions; no wildcard principal. | Same as KMS-004. |
| KMS-007 | `CKV_AWS_111` | `aws_iam_policy_document.audit_notifications_key` | SNS KMS key policy grants the regional CloudTrail service encryption operations, which Checkov classifies as unconstrained write access because its resource is the key-policy wildcard. | Principal is `cloudtrail.amazonaws.com`; condition constrains `aws:SourceAccount`; encryption context constrains the CloudTrail trail ARN. | CloudTrail principal, source account, trail ARN, KMS actions, or notification topic change. |
| KMS-008 | `CKV_AWS_356` | `aws_iam_policy_document.audit_notifications_key` | The wildcard is the AWS-required resource value for the KMS key governed by this policy. | Named CloudTrail service principal plus source-account and encryption-context conditions. | Same as KMS-007. |
| EKS-001 | `CKV_AWS_58` | `aws_eks_cluster.private` | Checkov expects an explicit customer-managed `encryption_config`; EKS 1.28+ instead encrypts Kubernetes API data by default with an AWS-owned KMS key. | Terraform lifecycle precondition rejects Kubernetes versions below 1.28; public endpoint is disabled; workload secrets are assigned to Vault, not to a new EKS CMK. | EKS version, removal/change of the lifecycle precondition, or a decision to use a customer-managed EKS encryption key. |

## Guardrails for an executable exception

When this register is represented in `policy/data/exceptions.json`, the policy
entry must contain all of the following fields:

```json
{
  "rule": "iac.checkov",
  "check_id": "CKV_AWS_356",
  "subject": "aws_iam_policy_document.kms_key_administrator",
  "owner": "fjybjinsu",
  "rationale": "KMS-003",
  "issue": "docs/security/checkov-kms-eks-exception-register.md#kms-003",
  "expires_at": "2026-10-03T00:00:00Z"
}
```

The OPA matcher must require equality on both `check_id` and `subject`; it
must not match by Checkov family, Terraform file, wildcard resource, or a
missing `check_id`. Tests must prove that the registered resource with a
different Checkov ID, and the registered Checkov ID on a different resource,
both remain blocking findings.

## AWS semantic sources

- [AWS KMS key policies](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html): a key policy is the primary access control for a KMS key.
- [AWS KMS default key policy](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html): examples use `"Resource": "*"` to mean the KMS key to which the policy is attached.
- [Amazon EKS envelope encryption](https://docs.aws.amazon.com/eks/latest/userguide/envelope-encryption.html): EKS 1.28 and later provides default envelope encryption using an AWS-owned KMS key.

This register does not authorize AWS apply, KMS policy changes, deployment, or
an extension of the exception past its review date.

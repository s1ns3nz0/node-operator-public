# Private CD evidence retention and access control

This contract applies to the private, disposable CD target. It keeps
non-sensitive, digest-bound summaries while preventing raw sensitive material
from entering GitHub, repository history, or a release asset.

| Data class | Retention | Authorized access | Prohibited handling |
| --- | --- | --- | --- |
| Raw DAST request/response captures | Do not persist; delete with the disposable job workspace. | The ephemeral runner process only. | GitHub artifacts, workflow logs, release assets, and evidence archives. |
| Certificate private keys, CSRs, and full certificate chains | Do not retain in CI; lifecycle remains in the approved secret boundary. | Scoped workload identity and the designated secret operator. | Kubernetes manifests, CI variables, artifact uploads, and logs. |
| Raw scanner output and secret candidates | Do not retain. | The ephemeral scanner process only. | Artifact uploads, issue comments, release assets, and evidence archives. |
| Normalized scanner/DAST/certificate summaries | 90 days, keyed by source SHA or artifact digest. | Repository security reviewers and the release approval path. | Credentials, payloads, endpoint URLs, kubeconfig data, or secret values. |
| Runtime telemetry raw events | No collection is authorized until an owned telemetry service and retention setting are approved. | None before that approval. | CI artifacts or release evidence. |
| Telemetry and alert summaries | 90 days once a telemetry service is approved. | Runtime operators and release reviewers. | Raw events, tokens, client IPs, or request payloads. |

## Enforcement

GitHub workflow artifacts may contain only normalized summaries. The private
runner must run with ephemeral storage, `persist-credentials: false`, and no
upload step for raw evidence. A later archive implementation must use a private
versioned SSE-KMS bucket, TLS-only policy, append-only object keys, and audited
role-based retrieval; it is not authorized by this document alone.

An absent collector, unavailable secret boundary, or unavailable telemetry
owner is a failed prerequisite, not an approval to retain less-controlled raw
data or to claim the associated control passed.

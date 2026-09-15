# Argo CD installation runbook

Run only after the approved Terraform apply and private-cluster access check.

1. Pin an approved Argo CD release and install it from the approved runner.
2. Verify all Argo CD control-plane pods are Ready.
3. Review `application.example.yaml`; replace every `REPLACE_WITH_*` value in
   the runner workspace only.
4. Apply the reviewed Application manifest.
5. Require `Synced` and `Healthy` status before recording deployment evidence.
6. If sync fails, stop promotion and fix Git source manifests; do not manually
   patch live workload resources.

The example intentionally has automated prune and self-heal disabled until the
GitOps repository, rollback policy, and operator ownership are approved.

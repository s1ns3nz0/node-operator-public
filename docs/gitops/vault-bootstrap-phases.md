# Vault bootstrap phases

The Vault bootstrap is three separately approved operations. It never combines
an EKS access-policy grant, Helm deployment, and revocation into one apply.

1. **Prepare:** apply with `enable_vault_bootstrap_runner=true` and
   `enable_vault_bootstrap_cluster_admin=false`. This creates private runner
   infrastructure but cannot call Kubernetes APIs with administrative access.
2. **Deploy:** after the chart and all images are verified in private ECR and
   the approved chart tag resolves to the reviewed OCI manifest digest, apply
   only the temporary EKS access-policy association with
   `enable_vault_bootstrap_cluster_admin=true`; run the one-purpose CodeBuild
   project, which deploys only sealed Vault and never initializes or unseals it.
3. **Revoke:** immediately apply with `enable_vault_bootstrap_cluster_admin=false`.
   Then run `scripts/ci/verify-vault-bootstrap-revocation.sh` with the dedicated
   role ARN. Its exact cluster-admin association must be absent before the task
   can be completed.

The `vault` namespace and `vault-tls` Secret are externally provisioned. The
runner checks only the Secret's existence and never reads its data.

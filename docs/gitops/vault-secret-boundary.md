# Vault secret boundary

Vault is the only runtime secret store for node-operator workloads. Terraform
must not receive or render secret values, and Argo CD Git repositories contain
only Vault policies, non-sensitive `SecretStore`/role configuration, and
workload references.

## Ownership

- Terraform creates only approved AWS prerequisites, including a dedicated KMS
  key for Vault auto-unseal and the narrowly scoped Pod Identity/IAM role.
- Argo CD installs and upgrades the pinned Vault chart after EKS readiness.
- Vault owns secret storage, policies, leases, and rotation.
- Workloads consume secrets through Vault Agent Injector or the CSI provider at
  runtime; Kubernetes Secret manifests containing values are prohibited.

## Bootstrap order

1. Apply and verify EKS infrastructure.
2. Install Vault through Argo CD with auto-unseal backed by the dedicated KMS key.
3. Configure Vault auth, policies, and roles using non-secret manifests.
4. Store secret values through an approved operator workflow, never Git or CI logs.
5. Deploy workloads and require Vault-backed injection plus Argo CD `Synced`/`Healthy`.

Vault tokens, recovery keys, unseal material, secret values, and kubeconfigs are
never committed to Git, Terraform state, CI artifacts, or compliance evidence.

## Decisions for the first deployment

- Run Vault as a three-replica HA StatefulSet using integrated Raft storage.
- Give each replica a dedicated encrypted gp3 PVC (20 GiB to start); resize by
  reviewed change, never by editing live PVCs.
- Expose Vault only as an internal Kubernetes service. Do not create a public
  LoadBalancer or Internet-facing ingress. Enable TLS for all client and Raft
  traffic.
- Use the dedicated Terraform KMS key for AWS KMS auto-unseal. The Vault
  service identity receives only the KMS permissions needed for seal/unseal.
- Schedule encrypted Raft snapshots to the approved private audit bucket with a
  retention policy; restore tests are required before production use.
- Use Kubernetes auth plus per-workload Vault roles. Root tokens and recovery
  keys are operator-held and never injected into workloads.

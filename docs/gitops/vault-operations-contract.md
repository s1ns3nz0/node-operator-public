# Vault GitOps operations contract

This is a deployment contract, not an authorization to create AWS resources,
install a Helm release, or configure a live Vault. The approved GitOps
repository copies `vault-values.example.yaml` as `platform/vault/vault-values.yaml`
and pins both the HashiCorp Vault chart version and the Git revision in its
Argo CD Application.

## Preconditions

- Terraform has created the `vault` namespace Pod Identity association for the
  `vault` service account and its dedicated auto-unseal KMS key.
- The TLS secret named `vault-tls` exists in the `vault` namespace. It contains
  only `tls.crt`, `tls.key`, and `ca.crt`; it is provisioned outside Git and
  is never rendered into Argo CD values, Terraform state, CI logs, or evidence.
- The release job runs only on a hardened self-hosted runner with private DNS
  and network access to Vault. GitHub-hosted runners, public listeners, and
  direct Internet access to the Vault service are prohibited.
- Namespace NetworkPolicies are reviewed to restrict Vault API and Raft traffic
  to the required in-cluster clients and approved private release paths.

## Runtime boundary

The chart runs three Vault server replicas with integrated Raft on encrypted
gp3 PVCs. Its user-facing service is `ClusterIP` and ingress is disabled.
TLS is mandatory for API and Raft traffic. AWS KMS auto-unseal refers only to
the Terraform output `vault_unseal_key_arn`; the service account receives KMS
access through EKS Pod Identity, never static AWS credentials.

## Audit, backup, and recovery

After initialization, an approved Vault operator enables an audit device that
writes structured records to the approved private audit destination. Raft
snapshots are encrypted and copied to the approved backup location under a
retention policy. Both destination names, retention, and the snapshot transport
are environment-owned configuration and therefore intentionally absent here.

No release credential is issued until all of the following evidence exists:

1. the Argo CD Application is `Synced` and `Healthy`;
2. all three Vault pods are Ready and sealed-state/leader health is reviewed;
3. TLS verification succeeds from the self-hosted runner path;
4. audit delivery and an encrypted snapshot restore test are recorded; and
5. the GitHub JWT and CodeBuild signer contracts pass their deny-path tests.

Vault unavailability, failed audit delivery, failed backup/restore evidence,
or a TLS/network failure is fail-closed for release signing. There is no static credential or public-endpoint fallback.

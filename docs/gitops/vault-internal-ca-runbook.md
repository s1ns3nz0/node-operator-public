# Vault internal CA and TLS delivery runbook

This portfolio configuration avoids AWS Private CA cost by using a
**Vault-namespace-only** CA. It is not an organization trust anchor and must
not be reused for public endpoints, other clusters, or unrelated namespaces.

## What is created, and what is not

The [TLS manifest](vault-tls-internal-ca.example.yaml) declares two
cert-manager `Certificate` objects. After a separately approved private-cluster
apply, cert-manager creates these Secret names internally:

- `vault-internal-ca`: the internal CA keypair, usable only by the namespaced
  `vault-internal-ca` Issuer;
- `vault-tls`: the leaf certificate consumed by the Vault Helm release. It has
  `tls.crt`, `tls.key`, and `ca.crt`.

Neither Secret is represented in Git as a `Secret` manifest. No operator,
CI job, Terraform state, or evidence collection may read or print their data.
The release gate verifies only the object name and certificate readiness.

## Required sequence for the separate live task

1. Mirror the four allowlisted cert-manager images with `GitOps OCI Mirror`
   and the signed chart with `cert-manager Chart Mirror`; verify the ECR digest
   reported by each workflow before any cluster installation.
2. Through the existing private EKS path, install
   `oci://ACCOUNT.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-cert-manager/cert-manager`
   at chart version `v1.21.1`, with
   [cert-manager-values.example.yaml](cert-manager-values.example.yaml), and
   wait for the controller, webhook, and cainjector deployments to become
   available. There is no public-registry or Internet-egress fallback.
3. Apply the TLS manifest, wait for `Certificate/vault-internal-ca` and
   `Certificate/vault-server-tls` to be `Ready=True`, and check only that
   `secret/vault-tls` exists. Do not use `kubectl get secret -o yaml`,
   `describe secret`, or a template that prints data.
4. Render the Vault Helm chart and verify its actual server Pod labels match
   [vault-network-policy.example.yaml](vault-network-policy.example.yaml).
   Apply the policy before labeling a client namespace/workload. The policy is
   intentionally ingress-only until a reviewed egress dependency map covers
   DNS, the Kubernetes API, and private KMS endpoint.
5. Install Vault only after these checks. Before the 90-day leaf renewal,
   conduct a separately approved HA-safe rolling reload/restart test: Secret
   projection refresh alone must not be assumed to reload Vault TLS files.

## Access and trust boundary

The CA Issuer is namespaced, so it cannot issue into another namespace. That
does not replace Kubernetes RBAC: restrict `create`, `update`, and `delete`
on cert-manager `Certificate`, `CertificateRequest`, and `Issuer` resources in
the `vault` namespace to the platform release identity. Grant the explicit
Vault-client labels only to reviewed workloads. Distributing `ca.crt` to a
client is a trust decision; keep it in the same private delivery boundary and
do not treat this CA as browser or organization-wide trust.

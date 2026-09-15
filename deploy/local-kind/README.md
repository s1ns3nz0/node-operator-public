# Local Kind render overlay

This Kustomize overlay composes static, unmodified copies of the T-3 base with
the T-4 Prysm and T-5 Nethermind manifests for local, offline rendering. It
changes only each StatefulSet's `spec.replicas` to `0` through JSON patches.
The source manifests under `deploy/base`, `deploy/prysm`, and
`deploy/nethermind` remain unchanged; the complete pod specifications are
retained here so rendered objects can still be evaluated by server-side
admission without causing a Hoodi sync or client image workload to start.

This overlay is deliberately not an EKS or infrastructure validation. Rendering
does **not** validate AWS EBS CSI provisioning, gp3 performance, KMS alias or
key access, node labels, availability zones, actual NetworkPolicy enforcement,
or any other EKS behavior. It does not create a cluster, contact AWS, apply
resources, or test connectivity.

Render offline with:

```sh
kubectl kustomize deploy/local-kind
```

Run the focused renderer check with:

```sh
scripts/ci/test-local-kind-overlay.sh
```

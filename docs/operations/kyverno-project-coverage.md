# Kyverno project coverage

Scope: `node-operator`, `validator-operations`, `vault`, `argocd`,
`cert-manager`, and `validator-observability`. The retired
`node-operator-dast` namespace must not be recreated by deployment manifests.

The existing node policy remains Enforce. The separate project policy covers
the other five namespaces. Both enable background reporting. These are
admission controls for private digest-pinned images, host access, effective
non-root/seccomp context, container restrictions, and resource budgets; they
are **not** image signature/provenance verification policies.

The only workload-specific privilege allowance is the exact reviewed Fluent
Bit image in the collector service account. It may run as root and mount the
single `/var/log` Directory hostPath read-only in `fluent-bit`. Other regular
containers and all init containers cannot mount that hostPath. Seccomp,
capability restrictions, no privilege escalation, read-only root filesystem,
image pinning and resource requirements still apply.

`kube-system` and `kyverno` retain their existing controller/webhook exclusions.
This change is not cluster-wide enforcement over EKS-managed networking,
storage, or the policy engine itself. `default`, `kube-public`, and
`kube-node-lease` are outside this project's workload namespace inventory.

## Deployment gates

1. Install the existing pinned Kyverno controller release. Review all policy
   diffs and confirm the control-plane webhook remains available.
2. Stage `scripts/ops/apply-kyverno-project-coverage.sh --phase audit
   --evidence-output <new-absolute-json> --execute`. The existing node policy
   stays Enforce; the new project policy is Audit only at this stage.
3. Resolve reported violations in workload sources and deployed templates.
   Reviewed platform values are under `docs/gitops/`; they are not proof that
   live Helm releases were upgraded. Preserve live Vault configuration, public
   trust, PVCs, and credentials. Do not apply placeholder example values
   directly to an existing release. Vault's OnDelete strategy requires a
   separate healthy-member restart procedure; template readiness is not Pod
   convergence. Its chart's unconfigured `helm test` hook is not exempted from
   admission and must be hardened separately before using that hook.
4. Revalidate current Pods with the pinned Kyverno CLI and promote with the
   same script using `--phase enforce`. A Kubernetes List is split into real
   Pod documents; empty input, failed checks, or no matching passes refuse
   promotion. Do not accept Audit as completion.
5. Run server-only dry-run negative tests in all six namespaces: unpinned
   image, privileged container, unsafe hostPath, missing limits, and inherited
   security-context overrides. Include positive controls and collector
   exception boundary cases. Check current controller readiness and policy
   reports; existing Pods are not retroactively restarted by Kyverno.

Policy sources and the explicit deployment command are included in the release
bundle. Merely downloading a release does not change a live cluster's policy.

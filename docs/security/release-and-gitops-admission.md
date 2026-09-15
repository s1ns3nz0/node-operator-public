# Release and GitOps admission requirements

No tag, GitHub Release, or GitOps promotion is eligible until the exact source
revision has passing required checks for quality, scanners, policy, Terraform,
and the trusted OPA evidence gate. Tags require a protected-ruleset workflow;
GitHub Actions cannot reliably reconstruct a merged PR's review and check state
after the fact.

Every published OCI subject must have a digest-bound CycloneDX SBOM, vulnerability
scan, provenance, and signature. The GitOps repository then promotes that exact
digest. A private CD runner must prove Argo observed the same revision and is
`Synced` and `Healthy` before it runs the bounded private DAST contract.

The environment/ruleset configuration is external repository state. It must
require independent review, signed commits, protected tags, and the named
checks above; the current GitHub plan does not expose branch protection for the
private GitOps repository, so this must be verified by an administrator before
promotion is enabled.

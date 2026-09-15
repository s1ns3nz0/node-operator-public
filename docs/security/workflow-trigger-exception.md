# Trusted workflow trigger disposition

## CI-EVIDENCE-GATE

`workflow.unsafe` / `dangerous-triggers` is accepted only for
`.github/workflows/evidence-gate.yml` through 2026-10-03. This is not a false-positive
claim: the trigger still starts a privileged follow-on workflow. The diagnostic
after removing its old inline suppression reports High severity and Medium
confidence. The finding must remain visible in scanner evidence.

The resolver and control-plane scripts come from the default-branch workflow
SHA, not the pull-request checkout. The resolver validates the upstream CI
workflow (`CI` / `continuous-integration.yml`) name/path/repository/event, exactly one PR, the 40-hex subject
and its equality to the API current PR head. Checkouts do not persist credentials.
PR/base source is passed as read-only input to scanners. Scanner/Terraform
containers receive no GitHub token; Terraform also has no network. Only trusted
host steps receive scoped tokens and publish the exact-head evidence check.

Residual risk remains: scanner parsing has network access, checks-write jobs
process attacker-derived evidence, and this path/rule disposition is not a
cryptographic binding to the current workflow body. Later edits at this path
therefore require fresh trust-boundary review even before expiry. The required
exact-head sensitive-path approval and existing boundary regression checks
remain enabled; temporarily disabled CODEOWNER/minimum-review branch settings
are not claimed as active protection. Wrong paths/checks/rules and expired
entries fail closed. Re-review or remove this disposition before expiry.

This policy-only prerequisite does not remove the legacy inline comment itself.
PR135 must remove it after this policy is trusted on main, without weakening
the collector rule that rejects untrusted inline suppressions. Scanner promotion
and the SSM runtime/state changes remain separate from this disposition.

## CI-REVIEW-REFRESH

The standalone handler has been removed along with its path-specific exception.
Review processing now belongs to `evidence-gate.yml` and remains within the existing
CI-EVIDENCE-GATE disposition above, with no extension of its expiry or rule scope.

The review signal has no permissions and executes no repository code. Its gate
job checks out only the trusted default-branch revision and has Actions read,
PR read and Checks write permissions, not Actions write. It validates the signal
identity, live PR head/base, producing gate run and successful source security
run before reading two exact JSON members from the gate's own evidence artifact.
Evidence must match head, base and trusted revision and be at most 24 hours old.
No PR-controlled scanner artifact is used. Current SCM posture is recollected
before policy evaluation; missing or stale cache cannot produce approval.

Residual risks include processing attacker-derived JSON and races with new
reviews. Gate runs are serialized per PR; current head/base are checked before
publishing the exact-SHA result. No scanner or Terraform process is started by
the review-only job. Changes to this boundary require renewed review under the
existing gate disposition; this consolidation is not a claim that workflow_run
has become an unprivileged trigger.

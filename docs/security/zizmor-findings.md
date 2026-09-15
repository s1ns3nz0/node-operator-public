# Zizmor findings register

This register records the Zizmor findings observed on 2026-09-03 while
introducing trusted scanner-evidence consumption. It is intentionally a
decision record, not a suppression list: every entry identifies whether the
code was changed or an exception is narrowly justified.

| Rule | Affected workflow(s) | Finding | Resolution |
| --- | --- | --- | --- |
| `template-injection` | `continuous-integration.yml`, `release-bundle.yml`, `image-publish.yml`, `evidence-gate.yml` (current consolidated paths) | `github.actor` was interpolated directly into a shell `run:` block during GHCR login. | Resolved by mapping `github.actor` and `github.token` to step-scoped environment variables, then expanding shell variables only. |
| `dangerous-triggers` | `evidence-gate.yml` | `workflow_run` can become privileged if it checks out or executes PR-controlled code. | Narrow documented exception. The workflow resolves control-plane code from the exact default-branch workflow SHA, verifies the trigger identity/current PR head, and reruns the immutable trusted scanner instead of consuming the PR workflow's artifact. PR and base trees are read-only inputs; Terraform has no network. Only publisher jobs receive job-scoped `checks: write`, and no PR executable receives the token. |

The evidence collector accepts both current `given_path` and legacy
`verbatim_path` Zizmor locations and normalizes them to repository-relative
workflow paths. This prevents distinct findings from collapsing into the same
`unknown` baseline identity.

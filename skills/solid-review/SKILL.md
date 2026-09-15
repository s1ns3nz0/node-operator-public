---
name: solid-review
description: Review a non-trivial object-oriented code design before implementation or after boundary drift; do not apply it to documentation, scripts, or designs where SOLID is not relevant.
metadata:
  short-description: Review object-oriented design boundaries
---

Use this repository-local skill when a non-trivial task introduces or changes
object-oriented production code, public interfaces, dependency direction, or
module boundaries. Read `AGENTS.md`, `harness.config.json`, the task contract,
plan, approved product specifications, and relevant existing code first.

Terra performs an independent review; Luna may return bounded dependency and
interface evidence. Sol decides whether a material finding blocks the affected
node or needs `$ambiguity-gate`. Run before implementation. Re-run at
integration only when a public interface, dependency direction, or module
boundary changed.

Write `plans/<task-id>/solid-review.md`. State the boundaries reviewed, each
applicable SOLID principle, evidence, the smallest corrective design for every
material violation, required tests, and principles that are non-applicable.
Do not emit a generic five-principle checklist.

Material findings block the affected work until the plan changes. A local,
non-material issue may receive one reversible correction and re-review. Link
the verdict and recheck from `evidence.json`, and update `plan.md` when scope,
ownership, or dependencies change. This review does not
replace `$admissibility-gate` or configured verification.

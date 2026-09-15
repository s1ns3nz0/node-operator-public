---
name: ambiguity-gate
description: Resolve task ambiguity with minimal evidence first, escalating to a Sol-owned user interview only for surviving material forks.
metadata:
  short-description: Evidence-first ambiguity escalation
---

Use this repository-local skill when a task has an ambiguous requirement,
competing interpretation, or failure whose correction could choose a material
product direction. Read `AGENTS.md`, `harness.config.json`,
`docs/ambiguity-escalation.md`, `docs/task-contract.md`, and
`docs/plan-graph-report.md` first.

This skill is intentionally thin. It routes to external pinned skills and does
not vendor, rename, or claim their provenance:

- Paperthin is pinned in `harness/paperthin.lock`; use its documented `readchk`,
  risk-adjacent `autobahn`, acceptance-time `ssotize`, and explicitly
  authorized major-decision `feynman` interfaces. Its `hate` capability is
  user-invoked only.
- `$grill-me` is separately pinned in `harness/grill-me.lock` from
  `https://github.com/mattpocock/skills.git` at
  `eebfb3c99aa955d4928192fab5de247d36633502`. It is not a Paperthin skill.

Follow this exact route: for a data drop with a thin ask, Paperthin `aim` to
propose the likely intent; Paperthin `readchk`; Paperthin `autobahn` for
risk-adjacent work; one safe evidence-based correction and revalidation for a
failure; and `$grill-me` only for a surviving material fork.
The primary Sol agent owns the interview and obtains explicit user approval.
Write/update `docs/decisions/<id>.md` first, then invoke `ssotize` and update
product specifications plus task contract/plan. Update the plan when scope or
ownership changes. Block only the affected work if unresolved.

Run Paperthin `hate` only when explicitly invoked by the user, after a
non-trivial plan exists and before an irreversible/high-cost stage, or on direct
user request. Return exactly one root objection and its first-nail test; never
run it automatically at every stage. Record all observed results in task
evidence, excluding private conversation content.

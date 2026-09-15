---
name: requirements-steward
description: Explicitly turn a raw service idea into an approved repository-local product requirement, decision record, and task contract without filing a GitHub issue.
metadata:
  short-description: Turn service ideas into approved requirements
---

Use this repository-local skill only when the user explicitly invokes
`$requirements-steward` to turn a raw service idea into a requirement. It is
the repository adaptation of `write-a-prd`; do not invoke that workflow to
file a GitHub issue and never create an issue under this skill.

Read `AGENTS.md`, `harness.config.json`,
[the requirements-steward guide](../../docs/requirements-steward.md),
`docs/task-contract.md`, `docs/ambiguity-escalation.md`, and relevant product
specifications and decision records first.

Terra owns synthesis. Luna may conduct only bounded evidence gathering and must
return findings rather than select product direction. Sol owns every material
ambiguity, runs any surviving `$grill-me` interview, and determines whether
the acceptance evidence is sufficient. Do not treat plausible agreement or
chat context as approval.

Follow the documented route: Paperthin `aim` for a thin idea; `readchk` against
repository and authorized evidence; `autobahn` when risk-adjacent; then draft
`docs/product-specs/<area>.md` from the product-spec requirement template. Keep
questions open when the available evidence does not answer them. For a
surviving material fork only, create the proposed decision record and have Sol
conduct `$grill-me`.

Before calling a requirement canonical, obtain explicit user approval and
record it in the linked decision record. Then reconcile canonical sources with
the pinned Paperthin `ssotize` interface and mark the specification approved.
An unapproved proposal does not authorize implementation.

After approval, create a task contract that links to the approved product spec.
Classify the follow-up and create any required plan before implementation. Run
`$admissibility-gate` after every durable artifact change,
record evidence, and route material or repeated findings through
`$ambiguity-gate`. Do not open a GitHub issue, contact third parties, publish,
or start implementation unless separately authorized.

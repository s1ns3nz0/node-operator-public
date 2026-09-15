---
name: knowledge-steward
description: Explicitly orient a user to the current repository after onboarding or a gap, using live evidence only; it does not edit by default.
metadata:
  short-description: Explain the current repository state
---

Use this repository-local skill only when the user explicitly invokes
`$knowledge-steward` for onboarding or re-entry after a gap. It is not an
automatic completion or documentation-editing workflow.

Read `AGENTS.md` and [the knowledge-steward guide](../../docs/knowledge-steward.md).
Build the orientation solely from live repository evidence: relevant `docs/`,
current plans/evidence/reports, decision records and product specs,
relevant Git log/diff/status, and affected file state. Do not use earlier chat
memory or an external wiki as a source of fact. `docs/` remains the canonical
wiki.

If the user instead needs a raw service idea synthesized into a requirement,
direct them to the explicit `$requirements-steward` skill. Do not promote a
proposal or infer approval while providing orientation.

Terra owns the synthesis. Luna may gather narrowly bounded Git or file evidence
when useful. If authoritative documents materially conflict, do not choose an
interpretation: identify the conflict and have Sol route it through
`$ambiguity-gate`.

Return the normal result in chat, always in this order:

1. What is needed from the user.
2. Product purpose and current behavior.
3. Architecture map and sources of truth.
4. What changed.
5. Active work, validation state, blockers, and risks.
6. New or unfamiliar terms, with links to canonical repository sources.

Clearly separate observed evidence from inference, and name missing or
inconsistent artifacts instead of reconstructing facts from conversational
context.

Stay read-only by default. Persist a point-in-time handoff only when the user
explicitly asks; identify the Git state and source artifacts reflected, and use
the repository's regular reporting conventions. After an accepted product spec
or decision, or at a user's explicit request, you may invoke the pinned
Paperthin `ssotize` only in read-only audit mode and propose a drift
reconciliation plan. Never apply that plan under this skill: approved changes
must follow the normal task-contract and planning process.

---
name: show-dont-tell
description: Require task-appropriate, independently reviewed proof of observable behavior before completion, while recording a justified no-observable-change exception for internal refactors.
metadata:
  short-description: Prove observable behavior before completion
---

Use this model-invoked, repository-local skill before completion whenever a
task changes observable behavior. Apply it after the implementer's local proof
exists and before Sol integration. This skill complements configured checks and
`$admissibility-gate`; it neither replaces them nor grants authority to expose
private data, publish a demo, or contact anyone.

Read `AGENTS.md`, `harness.config.json`, the task contract, approved product
specification, and `docs/validation-and-autonomy.md` first. The task contract
defines whether a user-facing demonstration is acceptance-gated.

## Proof route

1. Terra creates compact local proof while implementing. Select the proof
   medium from the changed boundary:
   - UI: a screenshot or short video of the primary journey and relevant edge.
   - API or CLI: a command transcript showing request/input, outcome, and
     relevant status or exit result.
   - Library: a runnable example that a reviewer can execute.
   - Service: health and relevant log evidence that demonstrates the outcome.
2. A bug fix must include a reproducible pre-change failure and a successful
   post-change result using comparable inputs. A feature must show its primary
   journey and a key edge condition. Redact secrets and personal data; do not
   use production systems merely to obtain proof.
3. Give an independent reviewer only the acceptance criteria and the proof
   artifacts—not an implementation narrative. The reviewer returns plain
   language explaining what the evidence proves, what it does not prove, and
   any gaps. Terra and the reviewer record their distinct roles; Sol decides
   integration and cannot substitute the implementer's explanation for the
   independent assessment.
4. Store a compact proof report plus small screenshots or text transcripts in
   the task's committed evidence/report artifacts. Keep larger videos, logs,
   recordings, and generated outputs local unless the user explicitly approves
   committing them. Record local-only artifact location, retention limits, and
   any redaction in evidence without committing sensitive content.
5. Present a user-visible demo when one is practical. It blocks approval only
   if the task contract explicitly marks the task `user_acceptance_gated`; a
   normal demo does not silently create a new approval gate.

## Internal-refactor exception

An internal refactor may omit behavioral proof only when the task evidence has
an evidence-backed `no_observable_change` record. It identifies the observable
surfaces considered, the comparison/checks performed, their results, and why
they establish no intended observable change. An assertion that the change is
internal is not enough. The independent reviewer must assess the record.

Record the selected proof type, artifact references, acceptance criteria,
reviewer's plain-language assessment, gaps, and Sol integration verdict in the
task evidence and completion report using `docs/plan-graph-report.md`. Missing
required proof, review, or a justified exception blocks completion of the
affected task. Route material uncertainty through `$ambiguity-gate` and
run `$admissibility-gate` after changing the resulting durable artifacts.

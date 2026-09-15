---
name: admissibility-gate
description: After any durable artifact change, invoke the pinned Paperthin sip and decide whether the result is admissible before completion or handoff.
metadata:
  short-description: Gate durable artifacts with Paperthin sip
---

Use this model-invoked, repository-local skill immediately after creating or
changing a durable artifact, and before declaring its node or task complete,
committing it, or handing it off. A durable artifact is a versioned source of
truth or execution record: product behavior, policy, task contracts, plans,
evidence, decisions, reports, learning memos, source, tests, or a
repository-local skill. Do not use it for transient scratch output.

This skill is intentionally thin. Read `harness/paperthin.lock` and the pinned
Paperthin release's own instructions before invoking its `sip`; do not infer
syntax or vendor a substitute. `sip` owns the checks and returns findings to
this session. This skill owns only harness routing, completion status, and
evidence.

## Required route

1. The primary Sol agent assigns the required checks by the role matrix in
   `docs/admissibility-protocol.md` and records the assignments in the task
   contract before implementation. Workers may perform only their assigned
   checks and cannot waive a required check, change its applicability, or mark
   an artifact admissible.
2. Terra invokes the pinned `sip` for the changed artifact set during
   implementation and records its route. Preserve its route:
   `shower` always; `factchk` for each reality-grounded claim; `mandela` for
   each evaluation, metric, or experiment; an audit-mode `ssotize` consistency
   review; `detool` only for portability, tool-neutrality, stack-agnostic, or
   cross-agent-reuse claims; and `re0` for every changed documentation
   artifact. Luna supplies bounded evidence for applicable `factchk` and
   `mandela`; Sol performs the required fresh-context `shower` at integration.
   Record every skipped conditional check and its reason. `ssotize` remains
   read-only unless its consolidation plan receives the required approval.
3. Classify each finding without weakening the underlying Paperthin result:
   - **Unexplainable**: `shower` says the artifact does not stand on its own,
     or a fresh reader had to guess a load-bearing meaning. It blocks
     completion by default.
   - **Unreasonable**: a claim, evaluation, metric, experiment, or requirement
     lacks support. It blocks completion only when the relevant factual,
     evaluation, or authoritative-requirement evidence is falsified. A missing
     optional check, non-falsified uncertainty, or style concern is not by
     itself a completion block.
   - **Unacceptable**: scope is outside the task's authority or guardrails.
     Invoke the pinned `autobahn` route. Descope the unacceptable part, retain
     a safe alternative and descope ledger, and continue the safe remainder at
     full strength. Follow `autobahn`'s approval stop for a gray-zone carve;
     bright-line exclusions do not block the safe remainder.
4. For a non-material, in-scope finding, make at most one reversible,
   evidence-based correction. Re-run the affected check(s), then re-run `sip`
   for the changed artifact set. Do not try a second speculative correction.
5. Route a material finding, a failed recheck, or a repeated finding through
   `$ambiguity-gate`. It determines the affected node, decision record, and
   any required Sol-owned user decision. Do not mark the affected work
   complete while an unexplainable or evidence-falsified unreasonable finding
   remains.
6. Sol integration rejects missing required evidence and cannot waive it by
   inference. It owns `autobahn`, ambiguity routing, and any user-invoked
   `hate` decision; workers may surface a trigger but must escalate it.
7. Record the initial `sip` run, every routed or skipped check and reason,
   every finding and classification, correction, `autobahn` descope ledger,
   and recheck in the task evidence using the schema in
   `docs/plan-graph-report.md`. A skill that is unavailable is a recorded
   skipped result, never an assumed pass. Keep private prompt or conversation
   content out of evidence.

`admissibility-gate` never commits, publishes, deploys, or expands authority.
It does not replace configured project validation; run the verification ladder
in `docs/validation-and-autonomy.md` as well.

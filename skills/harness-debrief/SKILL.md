---
name: harness-debrief
description: Persist a clean-room summary of a completed node-operator task.
---

Ask a fresh agent to read only `plans/<task-id>/`, relevant diffs, and recorded
checks. It must not receive the implementation conversation or edit production
files. Save `reports/<task-id>-debrief.md` with: what changed, current status,
evidence, unresolved risks, and next decision. Distinguish observed evidence
from inference.

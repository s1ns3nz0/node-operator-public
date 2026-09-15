# Node Operator Harness

This repository uses the local Codex harness. Its machine-readable policy is
`harness.config.json`; this file is the entry-point map.

## Boundary

Work only inside this repository and its assigned Git worktree. Do not inspect
personal directories, credentials, `.env` files, browser data, customer data,
or production systems. Network access is limited to declared dependency
bootstrap and explicitly authorized task integration. Do not publish, deploy,
merge, alter secrets, or contact third parties without task-level authorization.

## Start here

1. Build the smallest testable slice that satisfies the request before adding
   abstractions, extensions, automation, or polish.
2. Classify requests as `lightweight` by default. Use the full workflow for
   product design, security or external integration, data or irreversible
   changes, and external state changes. Product-design work runs `$grill-me`
   one question at a time before work begins.
3. Lightweight work uses at most three tool calls, one relevant validation
   command, no delegation, and no durable task artifacts. Required tests are
   Linux-first, vendor-neutral, and not local-only.
4. Read `harness.config.json` and the relevant document in `docs/harness/`.
5. Full-workflow work follows `docs/harness/task-contract.md`: create a task
   contract before code changes, assign bounded roles/worktrees, and record
   evidence. Sol owns integration and final sign-off; Terra implements or
   independently reviews; Luna performs bounded reconnaissance.
6. Run `npm run harness:workflow -- --stage prompt-intake --prompt <prompt>`
   only when project-configured skill execution is enabled. Use the
   artifact-review stage after durable changes in full-workflow tasks.
7. Run `npm run harness:check` for structural validation; run
   `npm run harness:verify` to execute configured adapters.

## Optional Graft context

`graft` is installed locally, but this project does not yet contain a tracked
`graft/` context graph. Do not depend on Graft until that graph is generated
and committed. Until then, use `search_files` and bounded source reads.

## Safety

No agent may deploy, publish, merge, alter secrets, or access production
without explicit task-level authorization. CI evidence must remain non-sensitive.
Do not stop an active task or withhold job details except when user approval is
required; report external job status without exposing sensitive logs or credentials.

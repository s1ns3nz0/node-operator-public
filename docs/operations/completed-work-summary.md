# Completed work summary

This is the consolidation boundary for completed task material before cleanup.
It describes repository state at pre-cleanup integration commit
`d81567d`; landed main was `3e9cc37`.
Source, tests, current runbooks, and Git history remain authoritative. Historical
live observations are not claims about current health.

## Completed foundations

- CI and release work established trusted evidence collection, scanner and
  promotion controls, permission boundaries, and hardened CodeBuild signing
  inputs. The scanner-evidence task retained environmental validation limits.
- Terraform backend ownership and credentials were diagnosed. Backend and
  provider identities are explicitly separated for safe read verification;
  unattended apply and a new dedicated least-privilege provider role are not
  proven.
- Private ECR connectivity, Argo CD bootstrap, source/Vault separation, Vault
  bootstrap/readiness/connectivity, and TLS foundations were completed in their
  historical scopes. Recheck live health before mutation.
- Node storage classes, isolated image-publisher configuration, and the
  temporary SSM-host task completed. Canonical implementation remains under
  `infra/`, `deploy/`, `scripts/`, and `docs/operations/`.

## Hoodi restoration and UC results

No new deposit is required or authorized. The deposit-validation portion of UC-1 passes:
the successful receipt, exact DepositEvent fields, SSZ roots, BLS proof, and
public/private pending record agree. The original explorer-specific
corroboration requirement remains incomplete; this is not a full UC-1 pass.
No custody material was read or copied during this verification.

- UC-2 is partial: the signer returned exactly the intended public key and the
  slashing database is retained, but the old CN-only TLS certificate fails Go
  hostname verification. Perform TLS-only SAN rotation and live authenticated
  verification without changing BLS material or slashing history.
- UC-3 awaits current chain state. Private Prysm was synced, non-optimistic, and
  execution-online when recorded; the validator was pending and not registered.
- UC-4 is not passed. Correct observers exist, but no signed duty is proven.
  Activation requires exactly one client and correlated client, signer, Beacon
  inclusion, assignment, and archived request evidence.
- UC-5 is limited only. Role revocation and archived Vault request/response
  correlation passed, but cached-key fencing, slashing continuity, and a later
  post-recovery duty remain unproven. Recovery requires stopped controllers,
  absent Pods, exact Lease/PVC identity, guarded CAS handover, and readback.

The signing fence, recovery guards, archive adapter, and release attestation
collector are tested local checkpoints, not published or deployed runtime
proof. Live client-to-Vault, CI-to-signer, and cross-set denial evidence remains
required.

## Native Prysm mTLS build

The patch targets Prysm v7.1.8 commit
`51b5a75ebbadf05af22bd2601b5baf7a9e99b66d`, patch SHA-256
`05fd3fa777abc99d5f0f66c192dfcca64922f1f1b0b2c35aa337dcb0c60970be`.
Targeted tests prove dedicated all-or-none HTTP mTLS flags, HTTPS/TLS 1.2+,
normal hostname verification, rejection of wrong CA, untrusted client,
hostname mismatch and redirects, and body-free error logging. After disk
cleanup, the full source verifier passed on Go 1.26.5, Darwin/arm64, including
the actual validator build and presence of all three mTLS CLI flags. Binary
SHA-256: `0e1f059fd3edd81a4775f179f76026da825671a9caeeadf6aaf8f3766fc529f3`.
The Linux deployment image, publication and deployment remain unverified.

The user's revised goal authorizes in-scope build, publication and deployment
to enable UC1-5 with a real current exact-image scan showing Critical=0 and
High=0. Medium/Low findings must be recorded; missing or failed scans never
pass. Preserve source/patch/digest records and actual scan evidence; additional
attestation machinery need not block this portfolio delivery. This does not
authorize fabricated reviewer identities, BLS disclosure, slashing resets,
duplicate validators or new deposits. Live deployment is not yet claimed.

## Local cleanup already completed

- Docker builder prune reported 46.91 GB reclaimed while retaining 117 images,
  6 containers, and 23 volumes.
- Thirty duplicate Terraform AWS provider v5.100.0 Darwin/arm64 binaries were
  removed only from explicitly old worktrees. `terraform init` restores them;
  no state, configuration, or lock file was touched.
- Canonical SSM, zero-to-Hoodi, and active integration worktrees were excluded.
  Free space afterward was approximately 56 GiB.
- Completed PR138 worktrees
  `/private/tmp/node-operator-pr138-clean-history` and
  `/private/tmp/node-operator-pr138-gitleaks-fix` were removed with `git
  worktree remove`; their branches and commits remain.

## Required retained material

Keep `plans/2026-09-05-always-on-gitops-client/` because the operator
handoff links to it; keep the lifecycle, active recovery, and native Prysm
bundles. Keep `reports/2026-09-08-security-remaining-status.md`, referenced by
the access-log runbook. Keep every task whose evidence status is missing,
unknown, active, partial, or blocked until reconciled.

## Consolidated and removed historical files

The 160 tracked historical files represented below were consolidated into
this document and removed from the working tree. Restore originals with
`git restore --source=d81567d -- <exact-path>` if necessary. Each directory's
evidence status is `complete`, `completed`, or a
`completed_*` variant; none is directly referenced outside `plans/` or
`reports/`. The completed operator-handoff bundle is excluded because a current
handoff document links to it.

```text
plans/2026-09-03-ci-foundation-repair/
plans/2026-09-03-codebuild-release-activation-code/
plans/2026-09-03-codebuild-signer-plan-review/
plans/2026-09-03-codebuild-signing-input-contract/
plans/2026-09-03-ecr-foundation-live-plan/
plans/2026-09-03-ecr-signer-mirror-connectivity/
plans/2026-09-03-osv-not-applicable/
plans/2026-09-03-scanner-evidence-workflow/
plans/2026-09-03-scanner-image-promotion/
plans/2026-09-03-security-evidence-permissions/
plans/2026-09-03-terraform-backend-state-diagnosis/
plans/2026-09-03-vault-bootstrap-recovery/
plans/2026-09-03-vault-codebuild-signer/
plans/2026-09-03-vault-private-connectivity/
plans/2026-09-03-vault-rollout-readiness/
plans/2026-09-03-vault-signer-ghcr-publish/
plans/2026-09-04-argocd-private-bootstrap/
plans/2026-09-04-ci-gate-repair/
plans/2026-09-04-gitops-source-vault-boundary/
plans/2026-09-04-temporary-ssm-ops-host/
plans/2026-09-04-vault-prepare-apply/
plans/2026-09-04-vault-prepare-live-plan-retry/
plans/2026-09-04-vault-zero-cost-tls-foundation/
plans/2026-09-04-vault-zero-cost-tls-live-execution/
plans/2026-09-05-isolate-image-publishers/
plans/2026-09-05-node-storage-classes/
plans/2026-09-08-credentials-validator-status/
reports/2026-09-03-ci-foundation-repair-debrief.md
reports/2026-09-03-codebuild-release-activation-code-debrief.md
reports/2026-09-03-codebuild-signer-plan-review-debrief.md
reports/2026-09-03-codebuild-signing-input-contract-debrief.md
reports/2026-09-03-ecr-foundation-live-plan-debrief.md
reports/2026-09-03-ecr-signer-mirror-connectivity-debrief.md
reports/2026-09-03-osv-not-applicable-debrief.md
reports/2026-09-03-scanner-evidence-workflow-debrief.md
reports/2026-09-03-scanner-image-promotion-debrief.md
reports/2026-09-03-security-evidence-permissions-debrief.md
reports/2026-09-03-terraform-backend-state-diagnosis-debrief.md
reports/2026-09-03-vault-bootstrap-recovery-debrief.md
reports/2026-09-03-vault-codebuild-signer-debrief.md
reports/2026-09-03-vault-private-connectivity-debrief.md
reports/2026-09-03-vault-rollout-readiness-debrief.md
reports/2026-09-03-vault-signer-ghcr-publish-debrief.md
reports/2026-09-04-argocd-private-bootstrap-debrief.md
reports/2026-09-04-ci-gate-repair-debrief.md
reports/2026-09-04-gitops-source-vault-boundary-debrief.md
reports/2026-09-04-temporary-ssm-ops-host-debrief.md
reports/2026-09-04-vault-prepare-apply-debrief.md
reports/2026-09-04-vault-prepare-live-plan-retry-debrief.md
reports/2026-09-04-vault-zero-cost-tls-foundation-debrief.md
reports/2026-09-04-vault-zero-cost-tls-live-execution-debrief.md
```

All other plan/report material is blocked from deletion until its status is
reconciled or unresolved content is migrated into a current canonical document.

# CI execution contract

Workflow YAML owns triggers, job dependencies, permissions, environments,
action pins, inputs and artifact upload configuration. Scripts own program
logic. A one-command invocation need not become another wrapper; a conditional,
loop or multi-stage release program belongs in a named script.

## Reading the execution roles

Each workflow starts with an English `Purpose` comment; job and step `Role`
comments explain why that stage exists without changing GitHub check names.
Workflow execution scripts document `Purpose`, `Inputs`, `Outputs` and
`Side effects`. These describe implemented behavior, not a claim that a live
run has passed. Focused tests retain their `Check objective` headers.

An offline contract test for a live-operation script does not run that live
operation. A build can write local images without publishing them. A mirror
copies artifacts to a registry but does not deploy workloads. A signature
authenticates a statement; it does not by itself authorize deployment.
Inputs listing GitHub tokens or OIDC variables mean runner-provided credentials,
not values to paste into Git, documentation or shell history.

The signer and Fluent Bit mirrors require the ECR digest to equal the pinned
source digest before emitting verified outputs. The signer also rejects a
`SOURCE_DIGEST` that disagrees with `SOURCE` before registry access. Both copy
the source manifest/index with `--prefer-index=false`, avoiding automatic
single-manifest wrapping or runner-platform selection. A failed copy or digest
check fails the job without success outputs; it does not delete an image that
may already have reached ECR. These boundaries are exercised with mocked CLIs
by `test-mirror-digest-integrity.py`; no live registry validation is implied.

## Local checks

From the repository root:

```sh
npm run harness:bootstrap-policy-tools
export PATH="$PWD/.ci-tools/bin:$PATH"
bash scripts/ci/run-suite.sh policy
bash scripts/ci/run-suite.sh policy-contracts
bash scripts/ci/run-suite.sh uc5-offline
bash scripts/ci/run-suite.sh vault-runtime
bash scripts/ci/run-suite.sh vault-v2
bash scripts/ci/run-suite.sh isolated-recovery
bash scripts/ci/run-suite.sh operator-auth
```

Use `--list` after a suite name to inspect its ordered members without running
them. These manifests are the CI and local source of truth, not a second copy
of the workflow. Each member is reported and a failure immediately stops the
suite. UC-5 here means **offline regression tests**, not a live ceremony or a
claim that UC-5 validation is complete. Python 3, Bash and the suite's pinned
tools are prerequisites; this entrypoint never installs them implicitly.

Terraform requires Docker and the approved image (Docker may need registry
authentication to pull it). It uses the same wrapper locally and in CI:

```sh
bash scripts/ci/run-terraform-ci.sh all
# Optional subsets: root, runtime, modules, foundation, monitoring.
```

Every validation container uses a digest-pinned image, a read-only repository
mount, an output-only mount and `--network none`. Set `CI_OUTPUT_DIR` to choose
the evidence directory; otherwise CI uses `RUNNER_TEMP`, and local runs create
a temporary output directory. No production credentials are needed for these
offline checks. Authentication for a private image pull is separate from AWS
infrastructure access.

## Script organization

- `scripts/ci/test-*`: focused tests, each documenting its check objective.
- `scripts/ci/suites/*.txt`: ordered test groups shared by local and CI runs.
- `scripts/ci/workflows/`: workflow adapters and trusted evidence collection.
- `scripts/release/`: authenticated artifact build, mirror and publication
  programs. These are not part of a local test suite and must not be run as
  tests; they require explicit release authority and their workflow inputs.
- `scripts/ci/normalize-scorecard-evidence.sh`: normalize official OpenSSF
  Scorecard SARIF into bounded posture evidence.
- `scripts/ci/test-repository-posture-contract.sh`: enforce the pinned
  Scorecard workflow and SLSA release-attestation contract.

Publishing adapters consume the workflow's explicit environment contract,
including GitHub OIDC/output channels. Do not pretend those external operations
are offline. Keep ordinary validation in independently executable test scripts.

## Workflow and job identities

`continuous-integration.yml` contains independent quality, policy, Terraform and scanner jobs for
pull requests and main pushes. Package read is scoped to scanner and Terraform
jobs; no CI job gets write permissions. The `quality` and `scanners` compatibility
checks remain separate. Fence Security remains reusable by CI and image release.
Release Integrity is now an ordinary job inside `release-bundle.yml`.

The nine entrypoints are `continuous-integration.yml`, `fence-security.yml`, `evidence-gate.yml`,
`review-signal.yml`, `release-bundle.yml`, `image-publish.yml`,
`private-ecr-mirror.yml`, `operations-verification.yml`, and `evidence-archive.yml`.

Manual release dispatch defaults to `mode=verify-only`: integrity and SCA run,
but source publication eligibility and the privileged publisher do not. Select
`mode=publish` explicitly to require eligibility plus integrity before publishing.
Version-tag pushes retain the full publication path. Verification outputs keep
their digest binding to the later publisher; no reusable-workflow output is lost.

Operations dispatch selects `target=private-runner` or `target=vault-runtime`.
Runner diagnostics retain their private runner/environment without OIDC signing
permission. Vault verification retains its own roles and component matrix;
`sign_evidence` defaults to false. Neither target deploys running workloads.

`image-publish.yml` owns the scanner, toolchain, signing-fence and audit-relay
publisher jobs. Signing-fence evidence recognizes the two exact historical and
current workflow identities so already signed fence images remain verifiable;
new publications use only the `image-publish.yml` identity. `private-ecr-mirror.yml` and
`release-bundle.yml` remain separate authority boundaries. `evidence-gate.yml` and
the unprivileged review signal retain trusted/untrusted execution separation.
Do not merge privileged publication into PR-controlled CI to reduce file count.

On push, a read-only selector compares the push baseline with the checked-out
commit. Only affected image families run; toolchains use a selected matrix rather
than rebuilding all six images. Missing baselines conservatively select all.
Publication requires main and successful prerequisites. Fence changes now also
trigger automatic security checks and protected publication on main, replacing
the previous manual-only Fence entrypoint. Existing protected environments remain.
Manual dispatch accepts `target=all`, `scanner`, `toolchains`, `fence`, `relay`,
or an individual toolchain name. The signed deployment bundle still uses
`release-bundle.yml`; combining image publishers does not publish a deployment bundle
or update running workloads.

`private-ecr-mirror.yml` consolidates eight manual mirror entrypoints. Dispatch
from main with exactly one `target`: `signer`, `gitops`, `private-dast`,
`validator-client`, `validator-log-collector`, `validator-runtime`, `vault-chart`
or `cert-manager-chart`. The first, second, fourth and fifth targets require
`source` with an immutable digest (formerly `source_image` for client/collector).
Only `gitops` accepts and requires `destination`; leave it as `none` otherwise.
Targets without a source input use their existing reviewed repository inputs.
A read-only preflight rejects invalid combinations and non-main dispatches.
Each selected job retains its own environment and IAM role; only signer gets
`packages: read`. Target-specific source checks remain in the existing scripts.
This workflow copies artifacts into ECR; it does not deploy them or run DAST.

Review events now enter a dedicated job in `evidence-gate.yml`; the separate
refresh handler and its Actions rerun permission are removed. The signal
workflow still has no permissions and runs no repository code. The trusted gate
reuses only its own evidence artifact bound to the current head, base, trusted
control revision and successful originating `CI` run, within 24 hours.
It collects current SCM posture and reevaluates OPA without scanner or Terraform
execution. Missing, expired or mismatched evidence fails closed: rerun CI
for the current revision to trigger a fresh full CI Evidence Gate and cache. The first run
after rollout must create this new cache metadata before review-only reuse works.

Main branch protection currently requires `quality`, `scanners`, and
`CI Evidence Decision`. `Code Quality` and `Security Scans` are the readable
implementation jobs; always-run compatibility gates preserve those first two
required contexts and reject failed, cancelled or skipped dependencies. Release
eligibility additionally checks exact-SHA `Policy Rules`, `Terraform Validation`
and `Evidence Contracts` from the exact `continuous-integration.yml` main-push workflow. The trusted
gate is triggered when the entire CI run completes, not just the scanner job;
an unsuccessful CI run cannot create a successful evidence decision. Previously
cached artifacts naming the old scanner workflow are intentionally not reused.

Remote rollout requires a consumer-first transition: before enabling the renamed
`CI` producer in PRs, land a reviewed temporary gate/resolver change on the
default branch accepting the exact old and new producer name/path pairs. Then
land the consolidated producer and remove the temporary legacy pair. Otherwise
the default-branch `workflow_run` consumer can miss the renamed producer and
leave required checks pending. Do not bypass branch protection to hide that gap.
This local refactor does not perform those remote rollout steps.

## Refactor verification

`test-ci-entrypoints.py` exercises suite ordering, failure propagation and
container isolation without Docker or cloud access. `test-ci-suite-ownership.py`
checks ownership after expanding suite manifests. Presentation checks protect
target-oriented labels and event identities. Source-contract tests may use
`lib/workflow-source.py` to inspect only scripts literally invoked by a workflow;
this static view complements tests and is not proof of live execution.

# CI/CD security control implementation details

Companion to [CI/CD security controls](ci-cd-security-controls.md). This document maps implemented controls to concrete workflow/script paths and representative code. It describes repository source, not unverified live GitHub or AWS state.

## 1. Least privilege and token containment

**Threat:** CI tokens or AWS identities are reused outside their approved task.

**Implementation:** `continuous-integration.yml` starts with read-only access:

```yaml
permissions:
  contents: read
```

`security-scans` adds only `packages: read`; the evidence-gate job alone gets `checks: write`; publishing jobs are the limited exception. Each checkout sets:

```yaml
with:
  persist-credentials: false
```

**Enforcement:** `scripts/ci/test-devsecops-redteam.sh`, `scripts/ci/test-repository-posture-contract.sh`.

## 2. Immutable CI dependencies

**Threat:** a mutable action/container changes after review.

**Implementation:** workflow actions use full Git commit SHAs; scanner/Terraform/release tools use OCI digests, for example:

```yaml
uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
SCANNER_IMAGE: ghcr.io/s1ns3nz0/node-operator/security-scanners@sha256:b224...
```

`install-validator-signing-fence-release-tools.sh` checksum-verifies the Cosign binary before use.

**Enforcement:** scanner/toolchain release and CI-security-evidence contracts.

## 3. Untrusted PR isolation

**Threat:** contributor-controlled PR code executes in a workflow that writes required checks.

**Implementation:** `.github/workflows/evidence-gate.yml` checks out trusted gate code and PR source separately:

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
  with:
    ref: ${{ steps.context.outputs.trusted_sha }}
    persist-credentials: false
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
  with:
    ref: ${{ env.SUBJECT_SHA }}
    path: .pr-source
    persist-credentials: false
```

The trusted workflow invokes `scripts/ci/workflows/reject-scanner-policy-replacement.sh` before collection. `collect-head-security.sh` and `collect-trusted-terraform.sh` run from the trusted checkout.

**Residual risk:** `workflow_run` remains a recorded risk (TM-008 in `THREAT-MODEL.md`); this is not claimed as fully eliminated.

## 4. Exact-SHA policy gate

**Threat:** decisions are published against an old commit, wrong PR, or a failed upstream run.

**Implementation:** event context resolution binds the current PR head, base, and trusted workflow revision. The check publisher receives the exact subject:

```bash
scripts/ci/publish-pr-evidence-check.sh \
  "$SUBJECT_SHA" "$EVIDENCE_ROOT/published/decision.json" "$DETAILS_URL"
```

OPA may complete to publish denial evidence, then `verify-policy-decision.sh` fails the gate for blocking decisions. Review refresh revalidates evidence age, head/base, and provenance.

## 5. Scanner and Terraform containment

**Threat:** scanning alters source, reaches arbitrary network targets, or applies infrastructure.

**Implementation:** a recovery-boundary scan runs with no network and read-only mounts:

```yaml
docker run --rm --network none --read-only
  --tmpfs /tmp:rw,noexec,nosuid,nodev
  --volume "$GITHUB_WORKSPACE:/workspace:ro"
```

Terraform validation uses a digest-pinned container and validation/contract commands, not a live `terraform apply`. Scanner output is written only to `EVIDENCE_ROOT`, which is the sole uploaded path.

## 6. Build/publish separation and image evidence

**Threat:** unreviewed or substituted image archives are published.

**Implementation:** `image-publish.yml` separates read-only build jobs from main-only publisher jobs:

```yaml
if: github.ref == 'refs/heads/main' &&
    needs.select.outputs.scanner == 'true' &&
    needs.scanner-build.result == 'success'
permissions:
  contents: read
  packages: write
  id-token: write
```

Build jobs upload named archives with input hashes and SBOMs. Publishers download the same-run named artifact, validate inputs, sign/publish it, and upload signature evidence. Fence publishing additionally requires the reusable SAST/DAST workflow.

## 7. Signing-fence security checks

**Threat:** signing-fence code is published without static and behavioral testing.

**Implementation:** `fence-security.yml` has `contents: read` only and runs:

```yaml
go test ./cmd/validator-signing-fence
bash scripts/ci/test-fence-security-sast.sh
scripts/ci/run-fence-security-sast.sh "$RUNNER_TEMP/fence-security/sast"
scripts/ci/run-fence-security-dast.sh "$RUNNER_TEMP/fence-security/dast"
```

DAST runs against a local process, not EKS. Report artifacts use `if: always()` to preserve failure evidence and have 30-day retention.

## 8. OIDC and private-ECR role separation

**Threat:** a broadly trusted workflow mirrors arbitrary artifacts.

**Implementation:** `private-ecr-mirror.yml` validates inputs in `preflight` before AWS credentials are acquired. Each artifact family requires `main`, a dedicated Environment, and OIDC:

```yaml
if: github.ref == 'refs/heads/main' && inputs.target == 'validator-runtime' &&
    needs.preflight.result == 'success'
environment: validator-runtime-ecr-mirror
permissions:
  contents: read
  id-token: write
```

Target validators constrain immutable source/destination shapes. Separate role variables exist for GitOps, validator-client/runtime, log collector, DAST, charts, and signer images.

## 9. Deterministic secret-excluding release bundles

**Threat:** releases contain local credentials/state or mutable workspace data.

**Implementation:** `scripts/ci/build-release-bundle.sh` materializes a strict allowlist from the selected Git revision. It excludes sensitive operational patterns:

```bash
*/.env|*/env|*/.env.*|*/keystore-*.json|*/deposit_data-*.json|
*/terraform.tfstate*|*/terraform.tfvars|*.tfplan|*.p12|*.pfx|*.key)
  return 1
```

`.github/workflows/release-bundle.yml` validates main ancestry/CI provenance, creates reproducibility evidence, freezes publication records, and rebuilds the release through the dedicated private runner.

## 10. SBOM, provenance, and vulnerability gates

**Threat:** a release has unknown composition/provenance or unacceptable vulnerability findings.

**Implementation:** Release Bundle generates GitHub provenance for the exact tarball and rejects failed or critical/high/unknown SBOM scans:

```yaml
- uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8
  with:
    subject-path: ${{ runner.temp }}/current/node-operator-release-bundle.tar

- run: jq -e '.status == "passed" and .findings.critical == 0 and
    .findings.high == 0 and .findings.unknown == 0' \
    "$RUNNER_TEMP/current/sbom-sca.json"
```

The scan-exported artifact digest is the publisher’s required expected digest.

## 11. Signed and bounded evidence archives

**Threat:** evidence from another/ambiguous workflow run or altered unsigned files are archived.

**Implementation:** `evidence-archive.yml` starts only after successful Evidence Gate completion, resolves one exact gate/review source, acquires a short-lived archive role, and signs then verifies evidence:

```yaml
- name: Short-lived archive identity
  run: scripts/ci/assume-ci-evidence-archive-role.sh
- name: Cosign sign, verify, and archive
  run: scripts/ci/archive-ci-evidence.sh ...
```

Security scan evidence is retained for 30 days. Exact-head policy evidence and Scorecard evidence are configured for 90 days. Live S3 Object Lock/IAM enforcement requires AWS-side verification.

## 12. Continuous posture and stale-run controls

**Threat:** posture regression is missed or obsolete CI results race new source.

**Implementation:** `repository-posture.yml` runs on `main`, weekly, and manual dispatch with minimal permissions and pinned Scorecard/SARIF upload actions. CI cancels superseded ref runs:

```yaml
concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

Evidence/archive workflows preserve exact-run attribution instead. Fence Security sets `timeout-minutes: 20`.

## Workflow mapping

| Workflow | Controls |
| --- | --- |
| `continuous-integration.yml` | token minimization, pinned dependencies, scanner/terraform isolation, policy contracts, aggregate fail-closed gates |
| `evidence-gate.yml` | trusted/untrusted split, exact-SHA PR decision, normalized evidence, OPA policy |
| `review-signal.yml` | review-triggered policy refresh |
| `fence-security.yml` | Fence unit/SAST/DAST and retained failure reports |
| `image-publish.yml` | build/publish separation, SBOM/signature evidence |
| `private-ecr-mirror.yml` | preflight, OIDC, role/environment-specific mirroring |
| `release-bundle.yml` | release eligibility, deterministic bundle, SBOM/SLSA/reproducibility |
| `evidence-archive.yml` | exact-run evidence resolution, Cosign, archive role |
| `repository-posture.yml` | OpenSSF Scorecard/SARIF posture tracking |

## External controls to verify separately

Repository source cannot prove GitHub branch protection, Environment reviewer rules, secret scope, AWS OIDC trust, IAM/SCP permissions, private runner hardening, actual ECR/S3/KMS policy, Object Lock state, or live signature validity. Verify those in GitHub/AWS before asserting production assurance.

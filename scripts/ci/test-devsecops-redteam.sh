#!/usr/bin/env bash
# Check objective: Enforce the CI/CD red-team baseline for pinned actions, least privilege, fail-closed security gates, and supply-chain evidence.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

workflow_count=0
while IFS= read -r workflow; do
  workflow_count=$((workflow_count + 1))
  grep -Eq '^permissions:' "$root/$workflow" || fail "$workflow lacks an explicit top-level permissions block"
  # Every third-party action must be immutable. Local reusable workflows are
  # intentionally excluded because their source is this reviewed repository.
  while IFS= read -r reference; do
    case "$reference" in
      ./.github/*) continue ;;
      *@????????????????????????????????????????) continue ;;
      *) fail "$workflow contains an unpinned action: $reference" ;;
    esac
  done < <(sed -nE 's/^[[:space:]]*uses:[[:space:]]*([^[:space:]#]+).*$/\1/p' "$root/$workflow")
done < <(cd "$root" && find .github/workflows -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) -print | sort | sed 's#^./##')
[ "$workflow_count" -gt 0 ] || fail 'no GitHub Actions workflows were found'

if grep -REn 'curl[^\n]*\|[[:space:]]*(bash|sh|tar|unzip|install)' "$root/.github/workflows" "$root/scripts/ci" "$root/scripts/release" >/dev/null; then
  fail 'unverified curl-to-shell or curl-to-extractor pipeline detected'
fi

ci="$root/.github/workflows/continuous-integration.yml"
opa="$root/.github/workflows/evidence-gate.yml"
release="$root/.github/workflows/release-bundle.yml"
grep -Fq 'gitleaks' "$root/scripts/ci/collect-pr-evidence.sh" || fail 'secret scanning is absent'
grep -Fq 'osv-scanner' "$root/scripts/ci/collect-pr-evidence.sh" || fail 'dependency scanning is absent'
grep -Fq 'semgrep scan' "$root/scripts/ci/collect-pr-evidence.sh" || fail 'SAST is absent'
grep -Fq 'checkov' "$root/scripts/ci/collect-pr-evidence.sh" || fail 'IaC scanning is absent'
grep -Fq 'run-fence-security-dast.sh' "$root/.github/workflows/fence-security.yml" || fail 'DAST is absent from the required security workflow'
grep -Fq 'sbom.cyclonedx.json' "$root/.github/workflows/release-bundle.yml" || fail 'release SBOM is absent'
grep -Fq 'cosign attest' "$root/scripts/release/publish-fence-image.sh" || fail 'artifact attestation is absent'
grep -Fq 'needs: [eligibility, reproducibility]' "$release" || fail 'release publication is not gated on eligibility and reproducibility'
grep -Fq "needs.eligibility.result == 'success'" "$release" || fail 'release publication lacks an explicit eligibility success gate'

# OPA must retain rejected evidence for diagnosis, but its exact-SHA check is
# the required status and fails closed. Keep both halves coupled.
grep -Fq 'continue-on-error: true' "$opa" || fail 'OPA evidence retention contract changed unexpectedly'
grep -Fq 'publish-pr-evidence-check.sh "$SUBJECT_SHA"' "$opa" || fail 'OPA exact-SHA fail-closed check is absent'
grep -Fq 'if: always()' "$opa" || fail 'OPA evidence publication is not failure-safe'

# No security job may be allowed to pass through a blanket continue-on-error.
if grep -REn '(^|[[:space:]])continue-on-error:[[:space:]]*true' "$ci" "$root/.github/workflows/fence-security.yml" "$release" >/dev/null; then
  fail 'security or release workflow uses unreviewed continue-on-error'
fi

printf 'PASS: DevSecOps red-team contract covers %s workflows; no HIGH/CRITICAL static pattern detected.\n' "$workflow_count"

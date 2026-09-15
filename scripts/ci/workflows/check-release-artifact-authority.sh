#!/usr/bin/env bash
# Check objective: Verify release artifact authority and fail-closed custody inputs without cloud mutations.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
bash scripts/ci/test-build-release-bundle.sh
python3 scripts/ci/test-vault-artifact-authority.py
python3 scripts/ci/test-installer-vault-inputs.py
python3 scripts/ci/test-kyverno-cli-publication-record.py
python3 scripts/ci/test-kyverno-cli-risk-acceptance.py
python3 scripts/ci/test-generate-kyverno-cli-manifest-approval.py
python3 scripts/ci/test-apply-kyverno-bootstrap.py
bash scripts/ci/test-vault-audit-relay-publication-record.sh
bash scripts/ci/test-toolchain-publication-record.sh
python3 scripts/ci/test-prysm-publication-record.py
python3 scripts/ci/test-prysm-release-authorization.py
python3 scripts/ci/test-fence-release-authorization.py
python3 scripts/ci/test-fence-release-bundle-inputs.py
python3 scripts/ci/test-fetch-fence-publication-record.py
python3 scripts/ci/test-client-chart-release-authorization.py
python3 scripts/ci/test-fetch-client-chart-publication-records.py
python3 scripts/ci/test-client-chart-release-bundle-inputs.py
python3 scripts/ci/test-fetch-prysm-mtls-publication-record.py
python3 scripts/ci/test-prysm-release-bundle-inputs.py
python3 scripts/ci/test-publish-prysm-mtls-image.py
python3 scripts/ci/test-fetch-release-publication-records.py
bash scripts/ci/test-prepare-release-publication-records.sh
python3 scripts/ci/test-vault-audit-relay-repository.py
python3 scripts/ci/test-installer-artifact-receipt.py
python3 scripts/ci/test-installer-vault-platform.py
python3 scripts/ci/test-interactive-deploy.py
python3 scripts/ci/test-verify-platform-private-eks-session.py
python3 scripts/ci/test-platform-bootstrap-build.py
python3 scripts/ci/test-platform-bootstrap-replay.py
bash scripts/ci/test-legacy-vault-authority-handoff.sh

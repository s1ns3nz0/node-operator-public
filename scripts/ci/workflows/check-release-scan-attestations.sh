#!/usr/bin/env bash
# Check objective: Verify Fence and signer probe publication bindings and scan-attestation rejection.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
python3 scripts/ci/test-fence-build-inputs.py
python3 scripts/ci/test-signer-probe-build-inputs.py
python3 scripts/ci/test-signer-probe-publication-record.py
python3 scripts/ci/test-signer-probe-release-authorization.py
python3 scripts/ci/test-fetch-signer-probe-publication-record.py
python3 scripts/ci/test-signer-probe-release-bundle-inputs.py
python3 scripts/ci/test-signer-evidence-authorized-image.py
python3 scripts/ci/test-publish-signer-identity-probe.py
bash scripts/ci/test-validator-signing-fence-image-contract.sh
bash scripts/ci/test-release-scan-attestation.sh
bash scripts/ci/test-validator-signing-fence-release-evidence.sh

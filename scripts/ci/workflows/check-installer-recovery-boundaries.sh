#!/usr/bin/env bash
# Check objective: Verify installer recovery, artifact-first ordering and validator preparation without live cloud calls.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
python3 scripts/ci/test-installer-startup-guidance.py
python3 scripts/ci/test-private-release-runner-contract.py
python3 scripts/ci/test-release-project-selection.py
python3 scripts/ci/test-interactive-hoodi-resume.py
python3 scripts/ci/test-installer-generated-inputs.py
python3 scripts/ci/test-zero-input-zone-discovery.py
python3 scripts/ci/test-installer-network-profile.py
python3 scripts/ci/test-interactive-artifact-authority-gate.py
python3 scripts/ci/test-interactive-authorized-artifacts.py
# Check canonical finalized inclusion, real log-envelope parsing and
# clone-only recovery rendering using synthetic local evidence.
python3 scripts/ci/test-observe-hoodi-finalized-attestations.py
python3 scripts/ci/test-collect-hoodi-finalized-attestation-evidence.py
python3 scripts/ci/test-validator-audit-pod-transport.py
python3 scripts/ci/test-validator-audit-reader-pod.py
python3 scripts/ci/test-validator-observation-context.py
python3 scripts/ci/test-run-hoodi-validator-observation.py
python3 scripts/ci/test-operational-log-delivery.py
python3 scripts/ci/test-operational-log-delivery-terraform.py
bash scripts/ci/test-slashing-db-rehearsal.sh
# Check release custody tooling and fail-closed runtime preparation without live Vault access.
python3 scripts/ci/test-custody-release-bundle-inputs.py
python3 scripts/ci/test-custody-verifier-runtime.py
python3 scripts/ci/test-prepare-custody-verifier-test-env.py
python3 scripts/ci/test-render-authorized-validator-client.py
python3 scripts/ci/test-release-infrastructure-resume.py
bash scripts/ci/test-release-infrastructure-resume.sh
bash scripts/ci/test-zero-resource-release-contract.sh
python3 scripts/ci/test-bootstrap-local-state.py
python3 scripts/ci/test-bootstrap-local-installer-artifacts.py
python3 scripts/ci/test-local-artifact-bootstrap.py
python3 scripts/ci/test-backend-role-retry.py
bash scripts/ci/test-zero-prepare-artifacts.sh
python3 scripts/ci/test-installer-artifact-prerequisites.py
python3 scripts/ci/test-mirror-installer-vault-artifacts.py
python3 scripts/ci/test-installer-artifact-mirror.py
python3 scripts/ci/test-installer-registry-auth.py
python3 scripts/ci/test-installer-artifact-inventory.py
python3 scripts/ci/test-installer-oci-selection.py
python3 scripts/ci/test-installer-oci-payload.py
python3 scripts/ci/test-installer-oci-binding.py
python3 scripts/ci/test-installer-release-signature.py
python3 scripts/ci/test-installer-release-download.py
python3 scripts/ci/test-release-bundle-oci-payload-binding.py
python3 scripts/ci/test-release-oci-assets.py
python3 scripts/ci/test-release-oci-staging.py
python3 scripts/ci/test-release-oci-fetch-wrapper.py
bash scripts/ci/test-oci-payload-release-wrapper-forwarding.sh
python3 scripts/ci/test-installer-full-artifact-mirror.py
python3 scripts/ci/test-hoodi-artifact-first.py
bash scripts/ci/test-interactive-hoodi-config-recorder-contract.sh
python3 scripts/ci/test-verify-existing-hoodi-validator.py
# Check offline archive correlation and immutable deployment-chart input boundaries.
python3 scripts/ci/test-vault-audit-archive-matcher.py
python3 scripts/ci/test-vault-audit-archive-reader.py
python3 scripts/ci/test-recover-and-configure-private-vault-validator-audit.py
python3 scripts/ci/test-build-deployment-bound-chart-values-input.py
python3 scripts/ci/test-verify-client-chart-deployment-capability.py
python3 scripts/ci/test-render-deployment-bound-chart-values.py

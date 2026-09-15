#!/usr/bin/env bash
# Check objective: Verify private validator monitoring contracts and collection boundaries.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
python3 scripts/ci/test-validator-monitoring-terraform.py
python3 scripts/ci/test-validator-monitoring-network.py --plan-json "$RUNNER_TEMP/plan.json"
python3 scripts/ci/test-validator-monitoring-config.py
python3 scripts/ci/test-validator-monitoring-dashboard.py
python3 scripts/ci/test-validator-monitoring-collector.py
python3 scripts/ci/test-apply-validator-log-collector.py
python3 scripts/ci/test-validator-log-collector-policy.py
python3 scripts/ci/test-validator-monitoring-listeners.py
python3 scripts/ci/test-validator-log-collector.py
python3 scripts/ci/test-validator-monitoring-chain.py

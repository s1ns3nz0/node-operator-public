#!/usr/bin/env bash
# Check objective: Verify the pinned Kyverno CLI checksum and test project admission policy boundaries.
set -euo pipefail

mkdir -p "$RUNNER_TEMP/kyverno-policy-tools"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  https://github.com/kyverno/kyverno/releases/download/v1.18.1/kyverno-cli_v1.18.1_linux_x86_64.tar.gz \
  -o "$RUNNER_TEMP/kyverno-policy-tools/kyverno.tar.gz"
printf '%s  %s\n' 5e6bba9ca85beec6c93e94ca7fb0972a66df3b2e67636a08bef090cd3fc6535c \
  "$RUNNER_TEMP/kyverno-policy-tools/kyverno.tar.gz" | sha256sum -c -
tar -xzf "$RUNNER_TEMP/kyverno-policy-tools/kyverno.tar.gz" -C "$RUNNER_TEMP/kyverno-policy-tools" kyverno
bash scripts/ci/test-kyverno-workload-baseline.sh
bash scripts/ci/test-kyverno-project-coverage.sh
bash scripts/ci/test-apply-kyverno-project-coverage.sh

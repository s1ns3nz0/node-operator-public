#!/usr/bin/env bash
# Check objective: Run the same locked Terraform validation and plan-boundary suites in a network-isolated container locally and in CI.
# Purpose: Run one allowlisted Terraform validation group in the pinned, network-isolated container.
# Inputs: Optional suite selector, digest-pinned TERRAFORM_IMAGE, repository checkout, and optional output directory.
# Outputs: Suite status and local validation artifacts beneath CI_OUTPUT_DIR or a temporary directory.
# Side effects: Runs local Docker containers with read-only source and --network none; no Terraform apply or cloud mutation.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
suite="${1:-all}"
[ "$#" -le 1 ] || exit 64
case "$suite" in all|root|runtime|modules|foundation|monitoring|dashboard) ;; *) printf 'unknown Terraform suite\n' >&2; exit 64 ;; esac
image="${TERRAFORM_IMAGE:-ghcr.io/s1ns3nz0/node-operator/terraform-validation@sha256:1f2ac75ec09b43b4a79eaaae94eca8f8f1655315a5aa81e7c80d3a8a14ac189a}"
[[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] || { printf 'Terraform image must be digest-pinned\n' >&2; exit 64; }
output="${CI_OUTPUT_DIR:-${RUNNER_TEMP:-}}"
if [ -z "$output" ]; then output="$(mktemp -d "${TMPDIR:-/tmp}/node-operator-terraform.XXXXXX")"; fi
mkdir -p "$output"; output="$(cd "$output" && pwd -P)"
run() {
  local script="$1"; shift
  docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" --network none \
    --volume "$root:/workspace:ro" --volume "$output:/output" \
    "$image" bash "/workspace/scripts/ci/$script" "$@"
}
run_suite() {
  case "$1" in
    root)
      run validate-terraform-offline.sh /workspace/infra/terraform /output
      run test-selected-terraform-apply-role-plan.sh
      ;;
    runtime)
      run test-validator-runtime-mirror-enabled-plan.sh
      run test-argocd-bootstrap-enabled-plan.sh /output/deployment-tags-plan.json
      run test-argocd-bootstrap-destination-contract.sh
      run test-pre-eks-artifact-plan.sh --plan-output /output/pre-eks-plan.json
      python3 "$root/scripts/release/installer_artifact_prerequisites.py" plan \
        --plan "$output/pre-eks-plan.json" --account 123456789012 --region ap-northeast-2 --name node-operator
      # The pinned Terraform image intentionally has no Python interpreter.
      python3 "$root/scripts/ci/test-deployment-tags.py" "$output/deployment-tags-plan.json" ;;
    modules)
      for module in bootstrap-state foundation-network ops-access vault-recovery; do
        run validate-terraform-module-offline.sh "/workspace/infra/$module" "/output/$module"
      done
      # Real Terraform empty-state behavior plus mocked AWS ownership checks.
      run test-bootstrap-state-cli.sh ;;
    foundation) run test-foundation-backend-contract.sh ;;
    monitoring)
      run test-ops-access-basic-monitoring.sh
      run test-ops-access-ebs-binding.sh ;;
    dashboard)
      VALIDATOR_DASHBOARD_TERRAFORM_MODE=container TERRAFORM_IMAGE="$image" \
        python3 "$root/scripts/ci/test-validator-monitoring-dashboard-terraform.py" ;;
  esac
}
if [ "$suite" = all ]; then
  for item in root runtime modules foundation monitoring dashboard; do run_suite "$item"; done
else run_suite "$suite"; fi
printf 'PASS Terraform suite %s; output: %s\n' "$suite" "$output"

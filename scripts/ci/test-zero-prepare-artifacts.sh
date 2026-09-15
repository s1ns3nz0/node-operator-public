#!/usr/bin/env bash
# Check objective: Validate zero-input artifact preparation.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
release="$root/scripts/release/node-operator-release.sh"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
fail() { printf 'FAIL zero prepare-artifacts: %s\n' "$*" >&2; exit 1; }

bundle="$scratch/bundle"; inputs="$scratch/inputs"; work="$scratch/work"; trace="$scratch/trace"
mkdir -p "$bundle/source/release" "$bundle/source/infra/bootstrap-state" "$bundle/source/infra/terraform" "$bundle/source/scripts/release" "$bundle/source/docs/gitops" "$inputs" "$scratch/bin"
printf '%s\n' '{"schema_version":"v1","network":"hoodi","client_chart":{"name":"node-operator-client","version_pattern":"^0\\.1\\.[0-9]+$","immutable_digest_required":true},"bootstrap":{"forbidden_inputs":["credentials"]}}' > "$bundle/source/release/hoodi-release-contract.json"
contract_sha="$(shasum -a 256 "$bundle/source/release/hoodi-release-contract.json" | awk '{print $1}')"
jq -n --arg sha "$contract_sha" '{entries:[{path:"source/release/hoodi-release-contract.json",sha256:$sha}]}' > "$bundle/bundle-manifest.json"

cat > "$bundle/source/scripts/release/installer_artifact_prerequisites.py" <<'PY'
import json, os, pathlib, sys
trace = pathlib.Path(os.environ["MOCK_TRACE"])
with trace.open("a") as handle: handle.write("helper " + " ".join(sys.argv[1:]) + "\n")
if sys.argv[1] == "plan":
    try:
        value = json.loads(pathlib.Path(sys.argv[sys.argv.index("--plan") + 1]).read_text())
        assert value["format_version"] == "1.0"
    except (AssertionError, IndexError, OSError, json.JSONDecodeError, KeyError):
        raise SystemExit(71)
    raise SystemExit(70 if os.environ.get("MOCK_HELPER_FAIL_PLAN") == "1" else 0)
if sys.argv[1] == "state":
    output = pathlib.Path(sys.argv[sys.argv.index("--output") + 1])
    output.write_text(json.dumps({"schema_version": 1, "projection": "fixture"}))
    output.chmod(0o600)
    raise SystemExit(0)
raise SystemExit(64)
PY
cat > "$bundle/source/scripts/release/reconcile-bootstrap-state.py" <<'PY'
#!/usr/bin/env python3
# Fresh-bootstrap fixture: there are no existing resources to import.
PY

cat > "$scratch/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  'sts get-caller-identity --output json') printf '%s\n' '{"Account":"123456789012"}' ;;
  's3api list-buckets --output json') printf '%s\n' '{"Buckets":[]}' ;;
  *) printf 'unexpected aws: %s\n' "$*" >&2; exit 64 ;;
esac
EOF
chmod +x "$scratch/bin/aws"

cat > "$scratch/bin/terraform" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
trace="${MOCK_TRACE:?}"; module=''
if [[ "${1:-}" == -chdir=* ]]; then module="${1#-chdir=}"; shift; fi
command="${1:-}"; shift || true
printf 'terraform module=%s command=%s args=%s\n' "$module" "$command" "$*" >> "$trace"
for arg in "$@"; do case "$arg" in -backend-config=*) cat "${arg#-backend-config=}" >> "$trace" ;; esac; done
case "$module" in *foundation-network*) exit 99 ;; esac
case "$command" in
  init|apply) exit 0 ;;
  plan) for arg in "$@"; do case "$arg" in -out=*) : > "${arg#-out=}" ;; esac; done ;;
  show)
    if [[ " $* " == *'.tfplan'* ]]; then printf '%s\n' '{"format_version":"1.0","configuration":{"root_module":{"resources":[]}},"resource_changes":[]}'
    else printf '%s\n' '{"format_version":"1.0","values":{"root_module":{"resources":[]}}}'; fi ;;
  output) printf '%s\n' '{"bucket":"node-operator-tfstate-123456789012-apnortheast2","region":"ap-northeast-2","dynamodb_table":"node-operator-terraform-lock","kms_key_id":"arn:aws:kms:ap-northeast-2:123456789012:key/11111111-2222-3333-4444-555555555555"}' ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$scratch/bin/terraform"

for values in argocd-private-values.example.yaml cert-manager-values.example.yaml vault-tls-internal-ca.example.yaml; do
  printf '# reviewed fixture %s\n' "$values" > "$bundle/source/docs/gitops/$values"
done

printf '%s\n' '{"aws_account_id":"123456789012","aws_region":"ap-northeast-2","name":"node-operator"}' > "$inputs/bootstrap-state.tfvars.json"
printf '%s\n' '{"aws_region":"ap-northeast-2","name":"node-operator"}' > "$inputs/foundation-network.tfvars.json"
printf '%s\n' '{"aws_account_id":"123456789012","aws_region":"ap-northeast-2","name":"node-operator","enable_private_gitops_foundation":true,"enable_gitops_client_ecr_publisher":true,"enable_validator_runtime_ecr_mirror":true,"enable_validator_client_ecr_mirror":true,"enable_validator_log_collector_ecr_mirror":true,"enable_vault_audit_relay_repository":true}' > "$inputs/baseline.tfvars.json"
jq -n --arg dir "$inputs" '{schema_version:1,aws_account_id:"123456789012",aws_region:"ap-northeast-2",bootstrap_config:($dir+"/bootstrap-state.tfvars.json"),foundation_config:($dir+"/foundation-network.tfvars.json"),baseline_config:($dir+"/baseline.tfvars.json")}' > "$inputs/zero-resource-inputs.json"

PATH="$scratch/bin:$PATH" MOCK_TRACE="$trace" bash "$release" zero prepare-artifacts --bundle-root "$bundle" --inputs "$inputs/zero-resource-inputs.json" --work-dir "$work" > "$scratch/output"

grep -Fq 'PASS zero-resource artifact prerequisites completed.' "$scratch/output" || fail 'pre-EKS phase did not report completion'
test -f "$work/artifact-prerequisites.json" || fail 'helper projection was not retained'
test ! -e "$work/baseline-artifacts-state.json" || fail 'transient Terraform state JSON was retained'
test ! -e "$work/baseline-artifacts-plan.json" || fail 'transient Terraform plan JSON was retained'
test -d "$work/baseline-artifacts" || fail 'separate baseline-artifacts module was not used'
test ! -e "$work/foundation-network" || fail 'foundation module was touched'
for values in argocd-private-values.example.yaml cert-manager-values.example.yaml vault-tls-internal-ca.example.yaml; do
  cmp "$bundle/source/docs/gitops/$values" "$work/baseline-artifacts/$values" >/dev/null || fail "reviewed artifact module value was not staged: $values"
done
grep -Fq 'key = "node-operator/baseline/terraform.tfstate"' "$trace" || fail 'artifact phase did not use the baseline remote state key'
grep -Fq 'helper plan --plan ' "$trace" || fail 'artifact plan validator was not invoked'
grep -Fq 'helper state --state ' "$trace" || fail 'artifact state projection validator was not invoked'
grep -Eq 'helper state .*--fingerprint [0-9a-f]{64} .*--output ' "$trace" || fail 'state projection did not bind the zero input fingerprint'
for target in aws_iam_role.kms_administrator aws_ecr_repository.private_gitops aws_ecr_lifecycle_policy.private_gitops aws_ecr_repository.gitops_client aws_ecr_repository.gitops_client_chart aws_ecr_lifecycle_policy.gitops_client aws_ecr_lifecycle_policy.gitops_client_chart aws_kms_key.validator_runtime_ecr aws_ecr_repository.validator_runtime aws_kms_key.validator_client_ecr aws_ecr_repository.validator_client aws_ecr_repository.validator_signing_fence aws_ecr_repository.validator_signer_identity_probe aws_kms_key.validator_log_collector_ecr aws_ecr_repository.validator_log_collector aws_kms_key.vault_audit_relay_ecr aws_ecr_repository.vault_audit_relay; do
  grep -Fq -- "-target=$target" "$trace" || fail "required target missing: $target"
done
if grep -Eq -- '-target=aws_(vpc|eks_|iam_role\.github_)' "$trace"; then fail 'network, EKS, or publisher role target was requested'; fi

failed_work="$scratch/work-helper-failure"; failed_trace="$scratch/trace-helper-failure"
if PATH="$scratch/bin:$PATH" MOCK_TRACE="$failed_trace" MOCK_HELPER_FAIL_PLAN=1 bash "$release" zero prepare-artifacts --bundle-root "$bundle" --inputs "$inputs/zero-resource-inputs.json" --work-dir "$failed_work" >/dev/null 2>&1; then
  fail 'artifact validator failure unexpectedly continued'
fi
if grep -Fq "terraform module=$failed_work/baseline-artifacts command=apply" "$failed_trace"; then
  fail 'artifact apply ran after plan validator failure'
fi
test ! -e "$failed_work/foundation-network" || fail 'validator failure reached foundation work'

printf 'PASS zero prepare-artifacts uses the baseline backend, exact ECR/KMS targets, and no foundation work offline.\n'

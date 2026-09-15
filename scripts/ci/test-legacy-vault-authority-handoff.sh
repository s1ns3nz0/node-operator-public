#!/usr/bin/env bash
# Check objective: legacy platform bootstrap consumes only bound Vault authority before Terraform plans.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
fail() { printf 'FAIL legacy Vault authority handoff: %s\n' "$*" >&2; exit 1; }

scripts="$temporary/source/scripts/release"
mkdir -p "$scripts" "$temporary/source/scripts/ops" "$temporary/source/docs/gitops" "$temporary/bin" "$temporary/work/baseline" "$temporary/authority"
cp "$root/scripts/release/run-platform-bootstrap.sh" "$scripts/run-platform-bootstrap.sh"
cp "$root/scripts/release/render-private-vault-values.py" "$scripts/render-private-vault-values.py"
cp "$root/scripts/release/platform_bootstrap_build.py" "$scripts/platform_bootstrap_build.py"
cp "$root/scripts/release/platform_bootstrap_replay.py" "$scripts/platform_bootstrap_replay.py"
cp "$root/docs/gitops/vault-tls-internal-ca.example.yaml" "$temporary/source/docs/gitops/vault-tls-internal-ca.example.yaml"
cat > "$scripts/verify-platform-private-eks-session.py" <<'EOF'
#!/usr/bin/env python3
import sys
assert "--work-dir" in sys.argv and "--session" in sys.argv and "--account" in sys.argv
print("test-node\ti-0123456789abcdef0")
EOF
chmod 700 "$scripts/run-platform-bootstrap.sh" "$scripts/render-private-vault-values.py" "$scripts/platform_bootstrap_build.py" "$scripts/platform_bootstrap_replay.py" "$scripts/verify-platform-private-eks-session.py"
: > "$temporary/work/baseline.backend.hcl"
chmod 700 "$temporary/work"
printf '%s\n' '{"name":"test-node","aws_account_id":"123456789012","aws_region":"ap-northeast-2"}' > "$temporary/baseline.tfvars.json"
printf '%s\n' '{"schema_version":1,"aws_region":"ap-northeast-2","cluster_name":"test-node","ssm_ops_instance_id":"i-0123456789abcdef0"}' > "$temporary/private-eks-session.json"
# Platform bootstrap consumes an already verified, deployment-bound client
# values file. Its content is intentionally inert here; the fixture verifies
# the Vault authority handoff before the fake Argo plan, not values rendering.
printf '%s\n' '{}' > "$temporary/client-values.json"
chmod 600 "$temporary/client-values.json"

cat > "$scripts/apply-argocd-bootstrap.sh" <<'EOF'
#!/usr/bin/env bash
printf 'argocd-plan-requested\n' >> "$TEST_MARKER"
exit 77
EOF
chmod 700 "$scripts/apply-argocd-bootstrap.sh"
cat > "$temporary/bin/terraform" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *'output -json private_gitops_ecr_repository_urls'*) printf '%s\n' '{"vault":"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/test-node-baseline-gitops-vault"}' ;;
  *'output -raw vault_audit_relay_ecr_repository_url'*) printf '%s\n' '123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/test-node-baseline-vault-audit-relay' ;;
  *) printf 'unexpected terraform invocation: %s\n' "$*" >&2; exit 99 ;;
esac
EOF
cat > "$temporary/bin/aws" <<'EOF'
#!/usr/bin/env bash
printf 'AWS must not run before the authority handoff test reaches its fake plan\n' >&2
exit 99
EOF
chmod 700 "$temporary/bin/terraform" "$temporary/bin/aws"

catalog="$root/.ci/gitops/approved-oci-artifacts.json"
index="$temporary/authority/index.json"
receipt="$temporary/authority/receipt.json"
python3 - "$catalog" "$index" "$receipt" <<'PY'
import hashlib,json,sys
catalog,index_path,receipt_path=map(__import__('pathlib').Path,sys.argv[1:])
items=json.loads(catalog.read_text())['artifacts']
def digest(prefix):
    matches=[x['source'].split('@',1)[1] for x in items if x['source'].startswith(prefix)]
    assert len(matches)==1
    return matches[0]
server= digest('docker.io/hashicorp/vault@')
injector=digest('docker.io/hashicorp/vault-k8s@')
relay='sha256:'+'c'*64
chart='sha256:85cfa6b40396a198a104fbf06c7cccaf75428db7201394f9061c272441bcd0e4'
names=['cert-manager-cainjector','cert-manager-chart','cert-manager-controller','cert-manager-startupapicheck','cert-manager-webhook','gitops-oci-mirror','vault-audit-relay','vault-bootstrap','vault-chart','vault-injector','vault-server']
components={name:{} for name in names}
components['vault-server']={'manifest_digest':server}
components['vault-injector']={'manifest_digest':injector}
components['vault-audit-relay']={'manifest_digest':relay,'verification':{'method':'cosign-and-slsa','status':'passed'}}
toolchain='sha256:'+'b'*64
components['vault-bootstrap']={'manifest_digest':toolchain}
components['vault-chart']={'expected_oci_manifest_digest':chart,'version':'0.31.0'}
index={'schema_version':1,'release_revision':'a'*40,'components':components}
index_path.write_text(json.dumps(index,sort_keys=True))
vault='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/test-node-baseline-gitops-vault'
relay_repo='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/test-node-baseline-vault-audit-relay'
artifacts={name:{} for name in names if name != 'gitops-oci-mirror'}
for name,repo,value in [('vault-server',vault,server),('vault-injector',vault,injector),('vault-audit-relay',relay_repo,relay)]:
    artifacts[name]={'image_ref':repo+'@'+value,'manifest_digest':value}
artifacts['vault-bootstrap']={'image_ref':vault+'@'+toolchain,'manifest_digest':toolchain}
artifacts['vault-chart']={'manifest_digest':chart,'version':'0.31.0'}
receipt={'schema_version':1,'status':'verified','aws_account_id':'123456789012','aws_region':'ap-northeast-2','deployment_name':'test-node','release_revision':'a'*40,'index_sha256':hashlib.sha256(index_path.read_bytes()).hexdigest(),'artifacts':artifacts}
receipt_path.write_text(json.dumps(receipt,sort_keys=True))
PY

toolchain_image="123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/test-node-baseline-gitops-vault@sha256:$(printf 'b%.0s' {1..64})"
common=(--baseline-work-dir "$temporary/work" --baseline-config "$temporary/baseline.tfvars.json" --account 123456789012 --region ap-northeast-2 --argocd-image "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/test-node-baseline-gitops-argocd@sha256:$(printf 'a%.0s' {1..64})" --vault-image "$toolchain_image" --client-chart-version 0.1.37 --client-chart-digest "sha256:$(printf 'd%.0s' {1..64})" --client-values "$temporary/client-values.json" --vault-chart-version 0.31.0 --vault-chart-digest sha256:85cfa6b40396a198a104fbf06c7cccaf75428db7201394f9061c272441bcd0e4 --cert-manager-chart-digest "sha256:$(printf 'e%.0s' {1..64})" --vault-approved-catalog "$catalog" --vault-artifact-index "$index" --vault-mirror-receipt "$receipt" --private-eks-session-handoff "$temporary/private-eks-session.json" --subnet-id subnet-0123456789abcdef0)

# An ambient marker cannot bypass the inherited whole-platform kernel lock.
set +e
PATH="$temporary/bin:$PATH" TEST_MARKER="$temporary/ambient-lock" NODE_OPERATOR_AUTOMATED_CEREMONY=1 PLATFORM_REPLAY_LOCKED=1 "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null 2>&1
status=$?
set -e
[ "$status" = 65 ] || fail "ambient replay-lock marker returned $status instead of failing closed"
[ ! -e "$temporary/ambient-lock" ] || fail 'ambient replay-lock marker reached an Argo plan'

set +e
PATH="$temporary/bin:$PATH" TEST_MARKER="$temporary/marker" NODE_OPERATOR_AUTOMATED_CEREMONY=1 "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null 2>&1
status=$?
set -e
[ "$status" = 77 ] || fail "valid authority did not reach the fake Argo plan (status $status)"
[ "$(cat "$temporary/marker")" = argocd-plan-requested ] || fail 'valid authority did not request the first plan'
cp "$temporary/work/platform-bootstrap-replay/checkpoint.json" "$temporary/checkpoint-before-corruption.json"
printf '%s\n' '{"malformed":true}' > "$temporary/work/platform-bootstrap-replay/checkpoint.json"
rm -f "$temporary/corrupt-phase-marker"
set +e
PATH="$temporary/bin:$PATH" TEST_MARKER="$temporary/corrupt-phase-marker" NODE_OPERATOR_AUTOMATED_CEREMONY=1 "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null 2>&1
status=$?
set -e
[ "$status" = 65 ] || fail "corrupt phase lookup did not fail closed (status $status)"
[ ! -e "$temporary/corrupt-phase-marker" ] || fail 'corrupt phase lookup reached Terraform plan'
cp "$temporary/checkpoint-before-corruption.json" "$temporary/work/platform-bootstrap-replay/checkpoint.json"
jq -e --arg server "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/test-node-baseline-gitops-vault@$(jq -r '.artifacts[] | select(.source | startswith("docker.io/hashicorp/vault@")) | .source | split("@")[1]' "$catalog")" '
  .vault_runtime_images.server == $server and .vault_runtime_images.agent == $server and
  (.vault_runtime_images.injector | test("@sha256:[a-f0-9]{64}$")) and
  (.vault_runtime_images.audit_relay | test("test-node-baseline-vault-audit-relay@sha256:[a-f0-9]{64}$")) and
  (.vault_approved_catalog_base64 | length > 20) and (.vault_image_values_overlay_base64 | length > 20)
' "$temporary/work/platform-bootstrap-inputs/vault.tfvars.json" >/dev/null || fail 'Vault authority fields were not passed to Terraform'

missing_receipt="$temporary/authority/missing.json"
set +e
PATH="$temporary/bin:$PATH" TEST_MARKER="$temporary/missing-marker" NODE_OPERATOR_AUTOMATED_CEREMONY=1 "$scripts/run-platform-bootstrap.sh" "${common[@]/$receipt/$missing_receipt}" >/dev/null 2>&1
status=$?
set -e
[ "$status" = 65 ] || fail "missing receipt did not fail before planning (status $status)"
[ ! -e "$temporary/missing-marker" ] || fail 'missing authority reached a Terraform plan'

bad_work="$temporary/bad-work"
mkdir -p "$bad_work/baseline"
: > "$bad_work/baseline.backend.hcl"
bad_catalog="$temporary/authority/bad-catalog.json"
printf '%s\n' '{"version":1,"helm_archives":[],"artifacts":[]}' > "$bad_catalog"
bad_common=()
for argument in "${common[@]}"; do
  case "$argument" in
    "$temporary/work") bad_common+=("$bad_work") ;;
    "$catalog") bad_common+=("$bad_catalog") ;;
    *) bad_common+=("$argument") ;;
  esac
done
set +e
PATH="$temporary/bin:$PATH" TEST_MARKER="$temporary/bad-catalog-marker" NODE_OPERATOR_AUTOMATED_CEREMONY=1 "$scripts/run-platform-bootstrap.sh" "${bad_common[@]}" >/dev/null 2>&1
status=$?
set -e
[ "$status" = 65 ] || fail "wrong catalog did not fail before planning (status $status)"
[ ! -e "$temporary/bad-catalog-marker" ] || fail 'wrong catalog reached a Terraform plan'

toolchain_work="$temporary/toolchain-work"
mkdir -p "$toolchain_work/baseline"
: > "$toolchain_work/baseline.backend.hcl"
wrong_toolchain="${toolchain_image%sha256:*}sha256:$(printf 'f%.0s' {1..64})"
toolchain_common=()
for argument in "${common[@]}"; do
  case "$argument" in
    "$temporary/work") toolchain_common+=("$toolchain_work") ;;
    "$toolchain_image") toolchain_common+=("$wrong_toolchain") ;;
    *) toolchain_common+=("$argument") ;;
  esac
done
set +e
PATH="$temporary/bin:$PATH" TEST_MARKER="$temporary/toolchain-marker" NODE_OPERATOR_AUTOMATED_CEREMONY=1 "$scripts/run-platform-bootstrap.sh" "${toolchain_common[@]}" >/dev/null 2>&1
status=$?
set -e
[ "$status" = 65 ] || fail "wrong Vault toolchain did not fail before planning (status $status)"
[ ! -e "$temporary/toolchain-marker" ] || fail 'wrong Vault toolchain reached a Terraform plan'

# Execute the public helper against only local fakes.  This proves the
# observable ordering boundary, rather than merely grepping for its commands.
trace="$temporary/tls-order"
cat > "$scripts/apply-argocd-bootstrap.sh" <<'EOF'
#!/usr/bin/env bash
printf 'argocd-%s\n' "$1" >> "$TEST_TRACE"
EOF
cat > "$scripts/apply-vault-bootstrap.sh" <<'EOF'
#!/usr/bin/env bash
printf 'vault-%s\n' "$1" >> "$TEST_TRACE"
[ "${FAIL_VAULT_APPLY:-0}" = 1 ] && [ "$1" = apply ] && exit 74
exit 0
EOF
cat > "$temporary/source/scripts/ops/with-private-eks.sh" <<'EOF'
#!/usr/bin/env bash
printf 'tunnel:%s:%s:%s:%s\n' "${AWS_PROFILE:-}" "${AWS_REGION:-}" "${EKS_CLUSTER_NAME:-}" "${SSM_OPS_INSTANCE_ID:-}" >> "$TEST_TRACE"
[ "$1" = -- ]; shift
"$@"
EOF
cat > "$scripts/prepare-vault-bootstrap-tls.sh" <<'EOF'
#!/usr/bin/env bash
printf 'tls\n' >> "$TEST_TRACE"
[ "${FAIL_TLS:-0}" = 1 ] && exit 73
exit 0
EOF
cat > "$scripts/verify-platform-private-eks-session.py" <<'EOF'
#!/usr/bin/env python3
import os,sys
print('verify', file=open(os.environ['TEST_TRACE'], 'a'))
if os.environ.get('FAIL_SESSION') == '1': raise SystemExit(65)
print('test-node\ti-0123456789abcdef0')
EOF
cat > "$temporary/bin/terraform" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *'output -json private_gitops_ecr_repository_urls'*) printf '%s\n' '{"vault":"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/test-node-baseline-gitops-vault"}' ;;
  *'output -raw vault_audit_relay_ecr_repository_url'*) printf '%s\n' '123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/test-node-baseline-vault-audit-relay' ;;
  *'output -raw argocd_bootstrap_project_name'*) printf '%s\n' argocd-project ;;
  *'output -raw vault_bootstrap_project_name'*) printf '%s\n' vault-project ;;
  *' plan -input=false '*revoke.tfplan*) printf 'revoke-plan\n' >> "$TEST_TRACE"; exit 0 ;;
  *' apply -input=false '*revoke.tfplan*) printf 'revoke-apply\n' >> "$TEST_TRACE"; [ "${FAIL_REVOKE:-0}" = 1 ] && exit 75; exit 0 ;;
  *' plan -input=false '*|*' apply -input=false '*) exit 0 ;;
  *' show -json '*)
    if [ -n "${REVOKE_PLAN_JSON+x}" ]; then printf '%s\n' "$REVOKE_PLAN_JSON"; else printf '%s\n' '{"resource_changes":[]}'; fi ;;
  *) printf 'unexpected terraform invocation: %s\n' "$*" >&2; exit 99 ;;
esac
EOF
cat > "$temporary/bin/aws" <<'EOF'
#!/usr/bin/env bash
case "$*" in *'--profile chosen --region ap-northeast-2 --no-cli-pager'*) ;; *) printf 'CodeBuild monitor omitted selected profile/Region/no-pager\n' >&2; exit 99 ;; esac
case "$*" in
  *'sts get-caller-identity'*) printf '%s\n' '"123456789012"' ;;
  *'start-build'*argocd-project*) printf 'aws-start-argocd\n' >> "$TEST_TRACE"; printf '%s\n' '{"id":"argocd-project:abc123","arn":"arn:aws:codebuild:ap-northeast-2:123456789012:build/argocd-project:abc123","projectName":"argocd-project","buildStatus":"IN_PROGRESS","buildComplete":false}' ;;
  *'start-build'*vault-project*) printf 'aws-start-vault\n' >> "$TEST_TRACE"; printf '%s\n' '{"id":"vault-project:abc123","arn":"arn:aws:codebuild:ap-northeast-2:123456789012:build/vault-project:abc123","projectName":"vault-project","buildStatus":"IN_PROGRESS","buildComplete":false}' ;;
  *'batch-get-builds'*argocd-project:abc123*) printf 'aws-argocd-terminal\n' >> "$TEST_TRACE"; if [ "${FAIL_ARGO:-0}" = 1 ]; then printf '%s\n' '[{"id":"argocd-project:abc123","arn":"arn:aws:codebuild:ap-northeast-2:123456789012:build/argocd-project:abc123","projectName":"argocd-project","buildStatus":"FAILED","buildComplete":true}]'; else printf '%s\n' '[{"id":"argocd-project:abc123","arn":"arn:aws:codebuild:ap-northeast-2:123456789012:build/argocd-project:abc123","projectName":"argocd-project","buildStatus":"SUCCEEDED","buildComplete":true}]'; fi ;;
  *'batch-get-builds'*vault-project:abc123*) printf 'aws-success-vault\n' >> "$TEST_TRACE"; printf '%s\n' '[{"id":"vault-project:abc123","arn":"arn:aws:codebuild:ap-northeast-2:123456789012:build/vault-project:abc123","projectName":"vault-project","buildStatus":"SUCCEEDED","buildComplete":true}]' ;;
  *) printf 'unexpected AWS invocation: %s\n' "$*" >&2; exit 99 ;;
esac
EOF
chmod 700 "$scripts/apply-argocd-bootstrap.sh" "$scripts/apply-vault-bootstrap.sh" "$scripts/prepare-vault-bootstrap-tls.sh" "$scripts/verify-platform-private-eks-session.py" "$temporary/source/scripts/ops/with-private-eks.sh" "$temporary/bin/terraform" "$temporary/bin/aws"
rm -rf "$temporary/work/platform-bootstrap-inputs" "$temporary/work/platform-bootstrap-plans" "$temporary/work/platform-bootstrap-replay"
set +e
PATH="$temporary/bin:$PATH" TEST_TRACE="$trace" NODE_OPERATOR_AUTOMATED_CEREMONY=1 AWS_PROFILE=chosen "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null
status=$?
set -e
[ "$status" = 0 ] || fail "successful TLS fixture returned $status"
expected=$'verify\nargocd-plan\nargocd-apply\naws-start-argocd\naws-argocd-terminal\ntunnel:chosen:ap-northeast-2:test-node:i-0123456789abcdef0\ntls\nvault-plan\nvault-apply\naws-start-vault\naws-success-vault\nrevoke-plan\nrevoke-apply'
[ "$(cat "$trace")" = "$expected" ] || fail "TLS order differs from the required Argo-success -> tunnel/TLS -> Vault sequence: $(tr '\n' ' ' < "$trace")"

# Revoke cleanup may remove exactly the temporary bootstrap runners, their
# authority, and the conditional EKS/STS endpoint access.  Permanent endpoint
# and node-rule ownership must remain outside this narrow plan allowlist.
revoke_addresses=()
for address in \
  'aws_cloudwatch_log_group.argocd_bootstrap[0]' 'aws_cloudwatch_log_group.vault_bootstrap[0]' \
  'aws_codebuild_project.argocd_bootstrap[0]' 'aws_codebuild_project.vault_bootstrap[0]' \
  'aws_eks_access_entry.argocd_bootstrap[0]' 'aws_eks_access_entry.vault_bootstrap[0]' \
  'aws_eks_access_policy_association.argocd_bootstrap[0]' 'aws_eks_access_policy_association.vault_bootstrap_cluster_admin[0]' \
  'aws_iam_role.argocd_bootstrap[0]' 'aws_iam_role.vault_bootstrap[0]' \
  'aws_iam_role_policy.argocd_bootstrap[0]' 'aws_iam_role_policy.vault_bootstrap[0]' \
  'aws_security_group.argocd_bootstrap[0]' 'aws_security_group.vault_bootstrap[0]' \
  'aws_vpc_endpoint.required_interface["eks"]' 'aws_vpc_endpoint.required_interface["sts"]' \
  'aws_vpc_security_group_ingress_rule.cluster_api_from_argocd_bootstrap[0]' 'aws_vpc_security_group_ingress_rule.cluster_api_from_vault_bootstrap[0]' \
  'aws_vpc_security_group_ingress_rule.endpoints_https_from_argocd_bootstrap[0]' 'aws_vpc_security_group_ingress_rule.endpoints_https_from_vault_bootstrap[0]'; do
  revoke_addresses+=("$address")
done
valid_revoke_plan="$(printf '%s\n' "${revoke_addresses[@]}" | jq -R '{address: ., change: {actions: ["delete"]}}' | jq -sc '{resource_changes: .}')"
replacement_plan="$(jq '.resource_changes[0].change.actions = ["delete", "create"]' <<<"$valid_revoke_plan")"
: > "$trace"
rm -rf "$temporary/work/platform-bootstrap-inputs" "$temporary/work/platform-bootstrap-plans" "$temporary/work/platform-bootstrap-replay" "$temporary/work/platform-bootstrap-builds"
set +e
PATH="$temporary/bin:$PATH" TEST_TRACE="$trace" REVOKE_PLAN_JSON="$replacement_plan" NODE_OPERATOR_AUTOMATED_CEREMONY=1 AWS_PROFILE=chosen "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null 2>&1
status=$?
set -e
[ "$status" = 70 ] || fail "bootstrap replacement deletion was not refused (status $status)"
! rg -q '^revoke-apply$' "$trace" || fail 'bootstrap replacement deletion reached apply'
for unsafe_address in 'aws_vpc_endpoint.required_interface["logs"]' 'aws_vpc_security_group_ingress_rule.cluster_api_from_nodes'; do
  : > "$trace"
  rm -rf "$temporary/work/platform-bootstrap-inputs" "$temporary/work/platform-bootstrap-plans" "$temporary/work/platform-bootstrap-replay" "$temporary/work/platform-bootstrap-builds"
  set +e
  PATH="$temporary/bin:$PATH" TEST_TRACE="$trace" REVOKE_PLAN_JSON="$valid_revoke_plan" NODE_OPERATOR_AUTOMATED_CEREMONY=1 AWS_PROFILE=chosen "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null
  status=$?
  set -e
  [ "$status" = 0 ] || fail "exact 20-resource revoke allowlist rejected (status $status)"
  rg -q '^revoke-apply$' "$trace" || fail 'exact 20-resource revoke plan did not apply'
  : > "$trace"
  rm -rf "$temporary/work/platform-bootstrap-inputs" "$temporary/work/platform-bootstrap-plans" "$temporary/work/platform-bootstrap-replay" "$temporary/work/platform-bootstrap-builds"
  rejected_plan="$(jq --arg address "$unsafe_address" '.resource_changes += [{address: $address, change: {actions: ["delete"]}}]' <<<"$valid_revoke_plan")"
  set +e
  PATH="$temporary/bin:$PATH" TEST_TRACE="$trace" REVOKE_PLAN_JSON="$rejected_plan" NODE_OPERATOR_AUTOMATED_CEREMONY=1 AWS_PROFILE=chosen "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null 2>&1
  status=$?
  set -e
  [ "$status" = 70 ] || fail "unsafe revoke deletion $unsafe_address was not refused (status $status)"
  ! rg -q '^revoke-apply$' "$trace" || fail "unsafe revoke deletion $unsafe_address reached apply"
done

# A TLS failure leaves the completed Argo phases bound in the replay
# checkpoint.  The next invocation may re-read the durable build status, but
# it must not plan/apply or StartBuild Argo again.
: > "$trace"
rm -rf "$temporary/work/platform-bootstrap-inputs" "$temporary/work/platform-bootstrap-plans" "$temporary/work/platform-bootstrap-replay" "$temporary/work/platform-bootstrap-builds"
set +e
PATH="$temporary/bin:$PATH" TEST_TRACE="$trace" NODE_OPERATOR_AUTOMATED_CEREMONY=1 FAIL_TLS=1 AWS_PROFILE=chosen "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null 2>&1
status=$?
set -e
[ "$status" = 73 ] || fail "replay TLS failure returned $status"
PATH="$temporary/bin:$PATH" TEST_TRACE="$trace" NODE_OPERATOR_AUTOMATED_CEREMONY=1 AWS_PROFILE=chosen "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null
[ "$(rg -c '^argocd-apply$' "$trace")" = 1 ] || fail 'TLS replay reapplied Argo'
[ "$(rg -c '^aws-start-argocd$' "$trace")" = 1 ] || fail 'TLS replay started a second Argo build'
[ "$(rg -c '^vault-apply$' "$trace")" = 1 ] || fail 'TLS replay did not continue to Vault exactly once'
[ "$(jq -r '.phases.revoke_complete' "$temporary/work/platform-bootstrap-replay/checkpoint.json")" = complete ] || fail 'successful replay did not mark revoke complete'

# A failed Vault apply keeps only its own intent.  The same work directory
# must produce a fresh Vault plan before retrying that apply, without
# recreating completed Argo phases or their CodeBuild build.
: > "$trace"
rm -rf "$temporary/work/platform-bootstrap-inputs" "$temporary/work/platform-bootstrap-plans" "$temporary/work/platform-bootstrap-replay" "$temporary/work/platform-bootstrap-builds"
set +e
PATH="$temporary/bin:$PATH" TEST_TRACE="$trace" NODE_OPERATOR_AUTOMATED_CEREMONY=1 FAIL_VAULT_APPLY=1 AWS_PROFILE=chosen "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null 2>&1
status=$?
set -e
[ "$status" = 74 ] || fail "Vault apply failure returned $status"
PATH="$temporary/bin:$PATH" TEST_TRACE="$trace" NODE_OPERATOR_AUTOMATED_CEREMONY=1 AWS_PROFILE=chosen "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null
[ "$(rg -c '^argocd-plan$|^argocd-apply$|^aws-start-argocd$' "$trace")" = 3 ] || fail 'Vault apply replay recreated an Argo phase or build'
[ "$(rg -c '^vault-plan$' "$trace")" = 2 ] || fail 'Vault apply replay did not generate a fresh plan'
[ "$(rg -c '^vault-apply$' "$trace")" = 2 ] || fail 'Vault apply replay did not retry exactly once'
[ "$(rg '^(vault-plan|vault-apply)$' "$trace")" = $'vault-plan\nvault-apply\nvault-plan\nvault-apply' ] || fail 'Vault retry did not create its fresh plan before applying'
[ "$(rg -c '^aws-start-vault$' "$trace")" = 1 ] || fail 'Vault apply replay started a second Vault build'

# A revoke failure is replayed as a fresh revoke plan/apply only.  Completed
# Argo/Vault runners and CodeBuild phases remain untouched.
: > "$trace"
rm -rf "$temporary/work/platform-bootstrap-inputs" "$temporary/work/platform-bootstrap-plans" "$temporary/work/platform-bootstrap-replay" "$temporary/work/platform-bootstrap-builds"
set +e
PATH="$temporary/bin:$PATH" TEST_TRACE="$trace" NODE_OPERATOR_AUTOMATED_CEREMONY=1 FAIL_REVOKE=1 AWS_PROFILE=chosen "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null 2>&1
status=$?
set -e
[ "$status" = 75 ] || fail "revoke failure returned $status"
PATH="$temporary/bin:$PATH" TEST_TRACE="$trace" NODE_OPERATOR_AUTOMATED_CEREMONY=1 AWS_PROFILE=chosen "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null
[ "$(rg -c '^revoke-plan$' "$trace")" = 2 ] || fail 'revoke replay did not generate a fresh revoke plan'
[ "$(rg -c '^revoke-apply$' "$trace")" = 2 ] || fail 'revoke replay did not retry revoke exactly once'
[ "$(rg '^(revoke-plan|revoke-apply)$' "$trace")" = $'revoke-plan\nrevoke-apply\nrevoke-plan\nrevoke-apply' ] || fail 'revoke retry did not create its fresh plan before applying'
[ "$(rg -c '^(argocd-plan|argocd-apply|aws-start-argocd|vault-plan|vault-apply|aws-start-vault)$' "$trace")" = 6 ] || fail 'revoke replay recreated a completed runner or build'
: > "$trace"
PATH="$temporary/bin:$PATH" TEST_TRACE="$trace" NODE_OPERATOR_AUTOMATED_CEREMONY=1 AWS_PROFILE=chosen "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null
! rg -q '^(argocd-|aws-|tunnel:|tls|vault-|revoke-)' "$trace" || fail 'completed replay reran a platform mutation'

: > "$trace"
printf '%s\n' '{"name":"other-node","aws_account_id":"123456789012","aws_region":"ap-northeast-2"}' > "$temporary/baseline.tfvars.json"
set +e
PATH="$temporary/bin:$PATH" TEST_TRACE="$trace" NODE_OPERATOR_AUTOMATED_CEREMONY=1 AWS_PROFILE=chosen "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null 2>&1
status=$?
set -e
[ "$status" = 65 ] || fail "changed replay context returned $status instead of failing before mutation"
! rg -q '^(argocd-|aws-start-|tunnel:|tls|vault-)' "$trace" || fail 'changed replay context reached a platform mutation'
printf '%s\n' '{"name":"test-node","aws_account_id":"123456789012","aws_region":"ap-northeast-2"}' > "$temporary/baseline.tfvars.json"

: > "$trace"
rm -rf "$temporary/work/platform-bootstrap-inputs" "$temporary/work/platform-bootstrap-plans" "$temporary/work/platform-bootstrap-replay"
set +e
PATH="$temporary/bin:$PATH" TEST_TRACE="$trace" NODE_OPERATOR_AUTOMATED_CEREMONY=1 FAIL_TLS=1 AWS_PROFILE=chosen "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null 2>&1
status=$?
set -e
[ "$status" = 73 ] || fail "TLS failure returned $status instead of stopping the platform helper"
! rg -q '^vault-' "$trace" || fail 'Vault plan or apply started after TLS failure'

: > "$trace"
rm -rf "$temporary/work/platform-bootstrap-inputs" "$temporary/work/platform-bootstrap-plans" "$temporary/work/platform-bootstrap-replay"
set +e
PATH="$temporary/bin:$PATH" TEST_TRACE="$trace" NODE_OPERATOR_AUTOMATED_CEREMONY=1 FAIL_ARGO=1 AWS_PROFILE=chosen "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null 2>&1
status=$?
set -e
[ "$status" = 70 ] || fail "Argo CodeBuild failure returned $status instead of stopping the platform helper"
! rg -q '^(tunnel:|tls|vault-)' "$trace" || fail 'TLS or Vault started after Argo CodeBuild failure'

: > "$trace"
rm -rf "$temporary/work/platform-bootstrap-inputs" "$temporary/work/platform-bootstrap-plans" "$temporary/work/platform-bootstrap-replay"
set +e
PATH="$temporary/bin:$PATH" TEST_TRACE="$trace" NODE_OPERATOR_AUTOMATED_CEREMONY=1 FAIL_SESSION=1 AWS_PROFILE=chosen "$scripts/run-platform-bootstrap.sh" "${common[@]}" >/dev/null 2>&1
status=$?
set -e
[ "$status" = 65 ] || fail "invalid session returned $status instead of failing before mutation"
[ "$(cat "$trace")" = verify ] || fail 'invalid session reached a Terraform plan or platform mutation'

printf 'PASS legacy Vault authority handoff binds catalog, publication index, mirror receipt, and Terraform input before plans.\n'

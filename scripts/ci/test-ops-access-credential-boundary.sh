#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
entrypoint="$root/scripts/release/node-operator-ops-access.sh"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/ops-access-credentials.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin" "$scratch/private"
chmod 700 "$scratch/private"
: > "$scratch/config.tfvars"
: > "$scratch/backend.hcl"
: > "$scratch/private/unused-plan"

cat > "$scratch/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'aws profile=%s command=%s\n' "${AWS_PROFILE:-}" "$*" >> "$MOCK_TRACE"
case "${AWS_PROFILE:-}" in
  state-role) printf '%s\n' '{"Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/NodeOperatorTerraformApply/backend-test"}' ;;
  provider-read) printf '%s\n' '{"Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/NodeOperatorProviderRead/provider-test"}' ;;
  *) exit 1 ;;
esac
EOF
cat > "$scratch/bin/terraform" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'terraform profile=%s command=%s\n' "${AWS_PROFILE:-}" "$*" >> "$MOCK_TRACE"
EOF
chmod +x "$scratch/bin/aws" "$scratch/bin/terraform"

common=(destroy --root "$root" --config "$scratch/config.tfvars" --backend-config "$scratch/backend.hcl" --plan-file "$scratch/private/unused-plan")
separated=(
  --backend-profile state-role
  --expected-backend-principal-arn arn:aws:iam::123456789012:role/NodeOperatorTerraformApply
  --provider-profile provider-read
  --expected-provider-principal-arn arn:aws:iam::123456789012:role/NodeOperatorProviderRead
)

# Destroy remains disabled, but initialization proves the two credential paths
# are separately forwarded after both exact identities pass.
if PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" bash "$entrypoint" "${common[@]}" "${separated[@]}" >/dev/null 2>&1; then
  printf 'direct destroy unexpectedly succeeded\n' >&2
  exit 1
fi
grep -Fq 'aws profile=state-role command=sts get-caller-identity --output json' "$scratch/trace"
grep -Fq 'aws profile=provider-read command=sts get-caller-identity --output json' "$scratch/trace"
grep -Fq 'terraform profile=provider-read command=-chdir=' "$scratch/trace"
grep -Fq -- '-backend-config=profile=state-role' "$scratch/trace"
grep -Fq -- '-lockfile=readonly' "$scratch/trace"

before="$(wc -l < "$scratch/trace" | tr -d ' ')"
if PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" bash "$entrypoint" "${common[@]}" \
  "${separated[@]:0:6}" --expected-provider-principal-arn arn:aws:iam::123456789012:role/WrongRole >/dev/null 2>&1; then
  printf 'mismatched provider role unexpectedly passed\n' >&2
  exit 1
fi
after="$(wc -l < "$scratch/trace" | tr -d ' ')"
test "$after" -eq $((before + 2)) # both STS checks ran; Terraform did not.

if PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" bash "$entrypoint" "${common[@]}" \
  --backend-profile state-role >/dev/null 2>&1; then
  printf 'partial credential separation unexpectedly passed\n' >&2
  exit 1
fi
if PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" bash "$entrypoint" "${common[@]}" \
  --backend-profile state-role --expected-backend-principal-arn arn:aws:iam::123456789012:role/NodeOperatorTerraformApply \
  --provider-profile state-role --expected-provider-principal-arn arn:aws:iam::123456789012:role/NodeOperatorTerraformApply >/dev/null 2>&1; then
  printf 'identical backend and provider identity unexpectedly passed as separated\n' >&2
  exit 1
fi
if PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" AWS_ACCESS_KEY_ID=redacted bash "$entrypoint" \
  "${common[@]}" "${separated[@]}" >/dev/null 2>&1; then
  printf 'exported AWS credential unexpectedly passed\n' >&2
  exit 1
fi
if PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" bash "$entrypoint" "${common[@]}" \
  --backend-profile '../unsafe' --expected-backend-principal-arn arn:aws:iam::123456789012:role/NodeOperatorTerraformApply \
  --provider-profile provider-read --expected-provider-principal-arn arn:aws:iam::123456789012:role/NodeOperatorProviderRead >/dev/null 2>&1; then
  printf 'unsafe profile name unexpectedly passed\n' >&2
  exit 1
fi

jq -n --arg config "$scratch/config.tfvars" --arg backend "$scratch/backend.hcl" \
  '{schema_version:1,cluster_name:"node-operator",config:$config,backend_config:$backend}' > "$scratch/ops-access-inputs.json"
if PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" bash "$entrypoint" destroy --root "$root" \
  --inputs "$scratch/ops-access-inputs.json" --config "$scratch/config.tfvars" --plan-file "$scratch/private/unused-plan" >/dev/null 2>&1; then
  printf 'mixed direct and generated ops inputs unexpectedly passed\n' >&2
  exit 1
fi
if PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" bash "$entrypoint" destroy --root "$root" \
  --inputs "$scratch/ops-access-inputs.json" --plan-file "$scratch/private/unused-plan" --session-handoff "$scratch/session.json" >/dev/null 2>&1; then
  printf 'session handoff outside generated apply unexpectedly passed\n' >&2
  exit 1
fi

printf 'PASS ops-access Terraform backend and provider credentials are separately verified and fail closed.\n'

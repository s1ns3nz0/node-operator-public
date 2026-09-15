#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal source-contract fragments
# Check objective: Enforce guarded Engine API Vault cutover sequencing and evidence boundaries.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/ops/apply-live-engine-vault-cutover.sh"
test -x "$script"; bash -n "$script"
for required in \
  'jq -e -f "$dir/lib/vault-cutover-authorization.jq" "$migration"' \
  'patch application "$app"' \
  'aws ecr describe-images' \
  '$source.chart | select' \
  'approved chart digest does not match the requested ECR chart version' \
  'approved-chart-digest' \
  'agent-inject-secret-engine.jwt' \
  'legacy JWT Secret remains mounted' \
  'delete pod "${stateful}-0"' \
  'controller-revision-hash' \
  'updated OnDelete Pod did not become Ready' \
  'vault-agent-init' \
  'legacy_engine_jwt_secret_retained:true'; do grep -Fq "$required" "$script" || { printf 'missing Engine cutover control: %s\n' "$required" >&2; exit 1; }; done
if grep -Eq 'delete secret.*engine-api-jwt|kubectl.*get secret.*engine-api-jwt.*data' "$script"; then printf '%s\n' 'Engine cutover must retain and never print the legacy JWT Secret' >&2; exit 1; fi
printf '%s\n' 'PASS: Engine cutover requires migration evidence, immutable revision convergence, serialized restart, and successful Vault init.'
filter="$root/scripts/ops/lib/vault-cutover-authorization.jq"
printf '%s\n' '{"operation":"live-runtime-secret-migration","source_secrets_retained":true,"secret_values_emitted":false}' | jq -e -f "$filter" >/dev/null
if printf '%s\n' '{"operation":"live-runtime-secret-migration","source_secrets_retained":false,"secret_values_emitted":false}' | jq -e -f "$filter" >/dev/null; then
  printf '%s\n' 'cutover must reject evidence without retained source secrets' >&2; exit 1
fi

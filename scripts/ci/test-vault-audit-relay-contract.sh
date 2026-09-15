#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
python3 "$root/scripts/ci/test-vault-relay-publisher-policy.py"
for file in \
  "$root/cmd/vault-audit-relay/main.go" \
  "$root/cmd/vault-audit-relay/main_test.go" \
  "$root/.ci/vault-audit-relay/Dockerfile" \
  "$root/infra/terraform/vault-audit-relay-ecr.tf" \
  "$root/.github/workflows/image-publish.yml"; do
  test -f "$file" || { printf 'missing Vault audit relay asset: %s\n' "$file" >&2; exit 1; }
done

grep -Fq 'net.Listen("unix"' "$root/cmd/vault-audit-relay/main.go"
grep -Fq 'discarded non-JSON Vault audit record' "$root/cmd/vault-audit-relay/main.go"
grep -Fq 'golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83' "$root/.ci/vault-audit-relay/Dockerfile"
grep -Fq 'COPY cmd/vault-audit-relay/ ./cmd/vault-audit-relay/' "$root/.ci/vault-audit-relay/Dockerfile"
grep -Fq 'go test ./cmd/vault-audit-relay' "$root/.ci/vault-audit-relay/Dockerfile"
grep -Fq -- '--mount=type=cache,target=/root/.cache/go-build' "$root/.ci/vault-audit-relay/Dockerfile"
grep -Fq -- '--mount=type=cache,target=/go/pkg/mod' "$root/.ci/vault-audit-relay/Dockerfile"
grep -Fqx 'FROM scratch' "$root/.ci/vault-audit-relay/Dockerfile"
grep -Fq 'USER 100:1000' "$root/.ci/vault-audit-relay/Dockerfile"
grep -Fq 'enable_vault_audit_relay_ecr_publisher' "$root/infra/terraform/vault-audit-relay-ecr.tf"
grep -Fq 'image_tag_mutability = "IMMUTABLE"' "$root/infra/terraform/vault-audit-relay-ecr.tf"
grep -Fq 'scan_on_push = true' "$root/infra/terraform/vault-audit-relay-ecr.tf"
grep -Fq 'vault-audit-relay-ecr-publish' "$root/infra/terraform/vault-audit-relay-ecr.tf"
grep -Fq 'ecr:PutImage' "$root/infra/terraform/vault-audit-relay-ecr.tf"
workflow="$root/.github/workflows/image-publish.yml"
source "$root/scripts/ci/lib/workflow-contract.sh"
relay_source() {
  workflow_source "$workflow" | awk '
    /run: scripts\/release\/publish-vault-audit-relay\.sh$/{found=1; next}
    found && /^      - name:/{exit}
    found {sub(/^          /, ""); print}
  '
}
if ! ruby -ryaml -e '
  job = YAML.load_file(ARGV[0]).fetch("jobs").fetch("relay-publish")
  abort unless job.fetch("needs") == ["select"]
  abort unless job.fetch("if") == "github.ref == '\''refs/heads/main'\'' && needs.select.outputs.relay == '\''true'\''"
  abort unless job.fetch("environment") == "vault-audit-relay-ecr-publish"
  abort unless job.dig("permissions", "id-token") == "write"
' "$workflow"; then
  printf 'relay publication must remain main-only, selected, OIDC-enabled, and bound to its protected environment\n' >&2
  exit 1
fi
# The publisher derives its private ECR destination from this protected
# workflow input; the explicit default preserves legacy node-operator runs.
grep -Fq 'DEPLOYMENT_NAME: ${{ vars.DEPLOYMENT_NAME || '\''node-operator'\'' }}' "$workflow" || {
  printf 'relay publication does not bind the deployment-scoped repository input\n' >&2
  exit 1
}
# shellcheck disable=SC2016 # Workflow snippets intentionally contain shell variables literally.
for required in \
  'install-validator-signing-fence-release-tools.sh' \
  'docker build --pull=false --platform linux/amd64' \
  'test "$GITHUB_REF" = refs/heads/main' \
  'label_format=' \
  'cmd/vault-audit-relay/main_test.go' \
  'scan "docker:$local_image" "$local_digest" local' \
  'descriptor.db.status.valid == true' \
  '.findings.critical == 0 and .findings.high == 0 and .findings.unknown == 0' \
  'scan "registry:$subject" "$digest" registry' \
  'cosign sign --yes "$subject"' \
  'type slsaprovenance1' \
  'certificate-oidc-issuer "$issuer"' \
  'certificate-github-workflow-sha "$GITHUB_SHA"' \
  'reproducibility_input_sha256' \
  'GITHUB_RUN_ATTEMPT' \
  '.subject|any(.digest.sha256' \
  'https://github.com/s1ns3nz0/node-operator/attestations/scan-summary/v1' \
  'verify-release-scan-attestation.sh' \
  'test-release-scan-cosign-roundtrip.sh' \
  'retention-days: 30' \
  'if: always()'; do
  case "$required" in
    'retention-days: 30'|'if: always()') grep -Fq "$required" "$workflow" ;;
    *) grep -Fq "$required" <(relay_source) ;;
  esac || { printf 'missing audit relay release gate: %s\n' "$required" >&2; exit 1; }
done
# shellcheck disable=SC2016 # This grep intentionally matches workflow shell syntax.
local_scan_line="$(relay_source | grep -n 'scan "docker:\$local_image"' | cut -d: -f1)"
aws_line="$(relay_source | grep -n 'assume-role-with-web-identity' | cut -d: -f1)"
[ "$local_scan_line" -lt "$aws_line" ] || { printf '%s\n' 'AWS credentials precede local scan gate' >&2; exit 1; }
label_format="$(relay_source | grep -F 'label_format=' | sed -e "s/.*label_format='//" -e "s/'$//")"
test -n "$label_format" || { printf '%s\n' 'image label format is absent' >&2; exit 1; }
docker image inspect --format "$label_format" node-operator-vault-audit-relay:hardened-local >/dev/null
# shellcheck disable=SC2016 # jq receives $digest as a jq variable, not a shell variable.
sbom_gate='.bomFormat == "CycloneDX" and (.specVersion|type=="string" and length>0) and .metadata.component.version == $digest and (.components|type=="array" and length>0)'
jq -ne --arg digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --argjson components '[{"name":"relay"}]' '{bomFormat:"CycloneDX",specVersion:"1.6",metadata:{component:{version:$digest}},components:$components}' | jq -e --arg digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$sbom_gate" >/dev/null
if jq -ne --arg digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa '{bomFormat:"CycloneDX",specVersion:"1.6",metadata:{component:{version:$digest}},components:[]}' | jq -e --arg digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$sbom_gate" >/dev/null; then printf '%s\n' 'empty SBOM components pass gate' >&2; exit 1; fi
if jq -n '{status:"passed",findings:{critical:0,high:1,unknown:0}}' | jq -e '.status == "passed" and .findings.critical == 0 and .findings.high == 0 and .findings.unknown == 0' >/dev/null; then printf '%s\n' 'new High passes release gate' >&2; exit 1; fi
grep -Fq 'REPLACE_WITH_PRIVATE_VAULT_AUDIT_RELAY_DIGEST' "$root/docs/gitops/vault-values.example.yaml"
printf 'PASS: Vault audit relay is private, immutable, non-root, and socket-only.\n'

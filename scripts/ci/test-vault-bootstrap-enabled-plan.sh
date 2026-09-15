#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(cd "$script_dir/../.." && pwd -P)"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
fail() { printf 'FAIL Vault bootstrap enabled plan: %s\n' "$*" >&2; exit 1; }

module="$temporary_directory/terraform-source"
cp -a "$root/infra/terraform/." "$module"
rm -f "$module/backend.tf"
cp "$root/docs/gitops/vault-tls-internal-ca.example.yaml" "$module/vault-tls-internal-ca.example.yaml"
cp "$root/docs/gitops/cert-manager-values.example.yaml" "$module/cert-manager-values.example.yaml"
cp "$root/docs/gitops/argocd-private-values.example.yaml" "$module/argocd-private-values.example.yaml"
overlay="$temporary_directory/vault-image-overrides.json"
chmod 700 "$temporary_directory"
server_digest="$(jq -er '.artifacts[] | select(.source | startswith("docker.io/hashicorp/vault@")) | .source | split("@") | .[1]' "$root/.ci/gitops/approved-oci-artifacts.json")"
injector_digest="$(jq -er '.artifacts[] | select(.source | startswith("docker.io/hashicorp/vault-k8s@")) | .source | split("@") | .[1]' "$root/.ci/gitops/approved-oci-artifacts.json")"
repository=123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-vault
if [ -n "${VAULT_OVERLAY_B64:-}" ]; then
  printf '%s' "$VAULT_OVERLAY_B64" | base64 -d > "$overlay"
else
  python3 "$root/scripts/release/render-private-vault-values.py" --approved-catalog "$root/.ci/gitops/approved-oci-artifacts.json" --account 123456789012 --region ap-northeast-2 --vault-repository "$repository" --server-image "$repository@$server_digest" --agent-image "$repository@$server_digest" --injector-image "$repository@$injector_digest" --output "$overlay"
fi
cp "$module/fixtures/offline-vault-bootstrap.tfvars" "$module/fixtures/generated-vault-bootstrap.tfvars"
printf '\nvault_image_values_overlay_base64 = "%s"\n' "$(base64 < "$overlay" | tr -d '\n')" >> "$module/fixtures/generated-vault-bootstrap.tfvars"
export TF_DATA_DIR="$temporary_directory/terraform-data" AWS_ACCESS_KEY_ID=offline AWS_SECRET_ACCESS_KEY=offline AWS_EC2_METADATA_DISABLED=true
terraform -chdir="$module" fmt -check -recursive
terraform -chdir="$module" init -backend=false -input=false -get=false -lockfile=readonly
terraform -chdir="$module" validate
terraform -chdir="$module" plan -refresh=false -input=false -var-file=fixtures/generated-vault-bootstrap.tfvars -out="$temporary_directory/plan"
terraform -chdir="$module" show -json "$temporary_directory/plan" > "$temporary_directory/plan.json"

plan="$temporary_directory/plan.json"
jq -e '
  any(.resource_changes[]?; .address == "aws_codebuild_project.vault_bootstrap[0]" and (.change.actions | index("create")))
  and any(.resource_changes[]?; .address == "aws_eks_access_policy_association.vault_bootstrap_cluster_admin[0]" and (.change.actions | index("create")))
  and any(.resource_changes[]?; .address == "aws_ecr_repository.private_gitops[\"vault\"]" and (.change.actions | index("create")))
' "$plan" >/dev/null || fail 'enabled plan omits the Vault delivery executor, temporary EKS access, or private ECR destination'

jq -e --arg server "${server_digest#sha256:}@$server_digest" --arg injector "${injector_digest#sha256:}@$injector_digest" '
  [.resource_changes[] | select(.address == "aws_codebuild_project.vault_bootstrap[0]") | .change.after.environment[0].environment_variable[] | select(.name == "VAULT_IMAGE_OVERLAY_B64") | .value] | .[0] | @base64d | fromjson as $overlay |
  $overlay.server.image.tag == $server and $overlay.injector.agentImage.tag == $server and $overlay.injector.image.tag == $injector
' "$plan" >/dev/null || fail 'planned Vault overlay does not equal the approved catalog images'

# The precondition is deliberately plan-time: neither missing nor altered
# image authority may reach a CodeBuild start.
sed '$d' "$module/fixtures/generated-vault-bootstrap.tfvars" > "$module/fixtures/missing-overlay.tfvars"
if terraform -chdir="$module" plan -refresh=false -input=false -var-file=fixtures/missing-overlay.tfvars -out="$temporary_directory/missing.plan" >/dev/null 2>&1; then fail 'missing overlay reached a plan'; fi
sed 's/vault_image_values_overlay_base64 = ".*"/vault_image_values_overlay_base64 = "e30="/' "$module/fixtures/generated-vault-bootstrap.tfvars" > "$module/fixtures/wrong-overlay.tfvars"
if terraform -chdir="$module" plan -refresh=false -input=false -var-file=fixtures/wrong-overlay.tfvars -out="$temporary_directory/wrong.plan" >/dev/null 2>&1; then fail 'wrong overlay reached a plan'; fi

# Mutate the approved authority coherently.  A successful plan must use the
# alternate approved values, proving Terraform did not retain legacy literals.
alternate_server="sha256:$(printf '1%.0s' {1..64})"; alternate_injector="sha256:$(printf '2%.0s' {1..64})"
jq --arg server "$alternate_server" --arg injector "$alternate_injector" '.artifacts |= map(if (.source | startswith("docker.io/hashicorp/vault@")) then .source = "docker.io/hashicorp/vault@" + $server | .ecrTag = ($server | ltrimstr("sha256:")) elif (.source | startswith("docker.io/hashicorp/vault-k8s@")) then .source = "docker.io/hashicorp/vault-k8s@" + $injector | .ecrTag = ($injector | ltrimstr("sha256:")) else . end)' "$root/.ci/gitops/approved-oci-artifacts.json" > "$temporary_directory/alternate-catalog.json"
python3 "$root/scripts/release/render-private-vault-values.py" --approved-catalog "$temporary_directory/alternate-catalog.json" --account 123456789012 --region ap-northeast-2 --vault-repository "$repository" --server-image "$repository@$alternate_server" --agent-image "$repository@$alternate_server" --injector-image "$repository@$alternate_injector" --output "$temporary_directory/alternate-overlay.json"
sed -e '/^vault_approved_catalog_base64[[:space:]]*=/d' -e '/^vault_image_values_overlay_base64[[:space:]]*=/d' -e '/^vault_runtime_images = {/,/^}/d' "$module/fixtures/offline-vault-bootstrap.tfvars" > "$module/fixtures/alternate-overlay.tfvars"
printf '\nvault_approved_catalog_base64 = "%s"\nvault_image_values_overlay_base64 = "%s"\nvault_runtime_images = { server = "%s", agent = "%s", injector = "%s", audit_relay = "%s" }\n' "$(base64 < "$temporary_directory/alternate-catalog.json" | tr -d '\n')" "$(base64 < "$temporary_directory/alternate-overlay.json" | tr -d '\n')" "$repository@$alternate_server" "$repository@$alternate_server" "$repository@$alternate_injector" "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-vault-audit-relay@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" >> "$module/fixtures/alternate-overlay.tfvars"
terraform -chdir="$module" plan -refresh=false -input=false -var-file=fixtures/alternate-overlay.tfvars -out="$temporary_directory/alternate.plan" >/dev/null
terraform -chdir="$module" show -json "$temporary_directory/alternate.plan" | jq -e --arg server "${alternate_server#sha256:}@$alternate_server" --arg injector "${alternate_injector#sha256:}@$alternate_injector" '[.resource_changes[] | select(.address == "aws_codebuild_project.vault_bootstrap[0]") | .change.after.environment[0].environment_variable[] | select(.name == "VAULT_IMAGE_OVERLAY_B64") | .value] | .[0] | @base64d | fromjson as $overlay | $overlay.server.image.tag == $server and $overlay.injector.image.tag == $injector' >/dev/null || fail 'alternate approved catalog was not reflected in the plan'

jq -e '
  ([.resource_changes[]? | select(.change.actions | index("create")) | .type]
    | any(. == "aws_nat_gateway" or . == "aws_internet_gateway") | not)
' "$plan" >/dev/null || fail 'enabled plan introduces public network infrastructure'

printf 'PASS Vault bootstrap enabled offline plan is private-boundary compliant.\n'

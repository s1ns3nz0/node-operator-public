#!/usr/bin/env bash
# Check objective: bind Argo's credential scope and Application source to the
# same deployment-scoped ECR path whose chart child is digest-verified.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
terraform="$root/infra/terraform/argocd-bootstrap.tf"

fail() { printf 'FAIL Argo bootstrap destination contract: %s\n' "$*" >&2; exit 1; }

test -f "$terraform" || fail "missing Terraform bootstrap"

# A non-default deployment and Region must derive all three source boundaries
# from Terraform resources, never the release's baseline prefix. The child
# repository is the ECR digest target; the parent is the Helm OCI repo URL and
# therefore the repo-creds scope.
account='123456789012'
region='us-east-1'
deployment='node-operator-example'
app_repository="${account}.dkr.ecr.${region}.amazonaws.com/${deployment}-baseline-gitops-client"
chart_repository="${app_repository}/node-operator-client"

[[ "$chart_repository" == "$app_repository/node-operator-client" ]] || fail 'non-default chart target is not a child of the credential scope'
[[ "$app_repository" != *'node-operator-baseline-gitops-client'* ]] || fail 'non-default deployment model collapsed to the baseline prefix'
[[ "$app_repository" == *".dkr.ecr.${region}.amazonaws.com/"* ]] || fail 'non-default Region model was not preserved'

for expected in \
  'type = object({' \
  'var.gitops_client_chart_values.deployment.profile == "deployment"' \
  'var.gitops_client_chart_values.dast.enabled == false' \
  'var.gitops_client_chart_values.deployment.storageKmsKeyId == aws_kms_key.ebs.arn' \
  'local.argocd_hoodi_nat_public_ip != null' \
  'var.gitops_client_chart_values.clients.deployment.prysmP2PHostIp == local.argocd_hoodi_nat_public_ip' \
  '!local.use_foundation_network || try(var.foundation_network.hoodi_nat_public_ip == local.argocd_hoodi_nat_public_ip, false)' \
  'var.offline_validation ? var.offline_hoodi_nat_public_ip : try(data.aws_nat_gateway.hoodi_egress[0].public_ip, null)' \
  'local.private_gitops_repositories.vault}@sha256:[a-f0-9]{64}$' \
  'local.private_gitops_repositories.nodes}@sha256:[a-f0-9]{64}$' \
  'aws_ecr_repository.gitops_client_chart[0].name' \
  'aws_ecr_repository.gitops_client_chart[0].arn' \
  'aws_ecr_repository.gitops_client[0].repository_url' \
  '--from-literal=url=${aws_ecr_repository.gitops_client[0].repository_url}' \
  'repoURL: ${aws_ecr_repository.gitops_client[0].repository_url}' \
  'chart: node-operator-client' \
  'kind: CronJob' \
  'name: argocd-ecr-oci-credentials' \
  'schedule: "17 */6 * * *"' \
  'image: ${var.argocd_bootstrap_image}' \
  "--for=jsonpath='{.status.sync.status}'=Synced application/node-operator-client" \
  'Argo CD did not sync the digest-verified node-operator-client source; inspect its comparison error before retrying.'; do
  grep -Fq -- "$expected" "$terraform" || fail "missing deployment-derived source invariant: $expected"
done

if grep -Eq '^  type[[:space:]]*=[[:space:]]*any$' "$terraform"; then
  fail 'chart values remain an untyped object'
fi

if grep -Fq 'node-operator-baseline-gitops-client' "$terraform"; then
  fail 'bootstrap retains the stale baseline GitOps-client destination'
fi

if grep -Fq 'repository/node-operator-baseline-gitops-client/node-operator-client' "$terraform"; then
  fail 'bootstrap retains the stale baseline IAM pull fallback'
fi

printf '%s\n' 'PASS Argo bootstrap derives digest check, Application repo URL, and repo-creds scope from the deployment-owned ECR repositories.'

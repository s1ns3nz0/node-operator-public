#!/usr/bin/env bash
set -euo pipefail
umask 077

# Converts the non-secret zero-release handoff into isolated SSM access inputs.
# It does not plan or apply the access host and cannot open an SSM session.
usage() { printf '%s\n' "usage: ${0##*/} --handoff /absolute/ops-access-handoff.json --output-dir /new-absolute-dir" >&2; exit 64; }
handoff=''; output_dir=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --handoff) handoff="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
case "$handoff:$output_dir" in /*:/*) ;; *) usage ;; esac
[ -f "$handoff" ] && [ ! -L "$handoff" ] && [ ! -e "$output_dir" ] && [ ! -L "$output_dir" ] || { printf '%s\n' 'handoff or output path is unsafe' >&2; exit 65; }
command -v jq >/dev/null 2>&1 || { printf '%s\n' 'missing command: jq' >&2; exit 69; }
command -v aws >/dev/null 2>&1 || { printf '%s\n' 'missing command: aws' >&2; exit 69; }

# macOS exposes /tmp through /private/tmp.  Resolve caller-controlled paths
# before recording them in the contract so later canonical-path validation
# compares identical strings on macOS and Linux.
handoff_parent="$(cd "$(dirname "$handoff")" && pwd -P)"
handoff="$handoff_parent/$(basename "$handoff")"
output_parent="$(cd "$(dirname "$output_dir")" && pwd -P)"
output_dir="$output_parent/$(basename "$output_dir")"
jq -e '
  .schema_version == "v1" and (.aws_region | test("^[a-z]{2}-[a-z0-9-]+-[0-9]+$")) and
  (.aws_account_id | test("^[0-9]{12}$")) and (.cluster_name | test("^[a-z][a-z0-9-]{1,38}[a-z0-9]$")) and
  (.vpc_id | test("^vpc-[0-9a-f]+$")) and (.subnet_id | test("^subnet-[0-9a-f]+$")) and
  (.backend | type == "object" and (.bucket | test("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")) and
   (.dynamodb_table | type == "string" and length > 0) and
   (.kms_key_id | test("^arn:aws:kms:[a-z]{2}-[a-z0-9-]+-[0-9]+:[0-9]{12}:key/[A-Za-z0-9-]+$")) and
   (.region | test("^[a-z]{2}-[a-z0-9-]+-[0-9]+$")) and .key == "node-operator/ops-access/terraform.tfstate")
' "$handoff" >/dev/null || { printf '%s\n' 'handoff is not an isolated ops-access contract' >&2; exit 65; }

account="$(jq -r '.aws_account_id' "$handoff")"
cluster="$(jq -r '.cluster_name' "$handoff")"
region="$(jq -r '.aws_region' "$handoff")"
jq -e --arg region "$region" '.backend.region == $region and (.backend.kms_key_id | startswith("arn:aws:kms:" + $region + ":"))' "$handoff" >/dev/null || { printf '%s\n' 'ops-access backend region does not match the deployment region' >&2; exit 65; }
caller_account="$(env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN aws sts get-caller-identity --query Account --output text)"
[ "$caller_account" = "$account" ] || { printf '%s\n' 'current AWS identity does not match the ops-access handoff account' >&2; exit 65; }
cluster_security_group_id="$(env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN aws eks describe-cluster --region "$region" --name "$cluster" --query 'cluster.resourcesVpcConfig.clusterSecurityGroupId' --output text)"
[[ "$cluster_security_group_id" =~ ^sg-[0-9a-f]+$ ]] || { printf '%s\n' 'EKS did not return a valid cluster security group ID' >&2; exit 65; }

mkdir -m 700 "$output_dir"
config="$output_dir/ops-access.tfvars.json"
backend="$output_dir/ops-access.backend.hcl"
metadata="$output_dir/ops-access-inputs.json"
jq --arg cluster_security_group_id "$cluster_security_group_id" '{aws_region,name:(.cluster_name),vpc_id,subnet_id,cluster_security_group_id:$cluster_security_group_id,existing_ssm_endpoint_security_group_id:null,manage_cluster_ingress_rule:true,manage_existing_endpoint_ingress_rule:false,retained_host_instance_id:null,ebs_optimized:true}' "$handoff" > "$config"
jq -r '.backend | "bucket = \"\(.bucket)\"\nkey = \"\(.key)\"\nregion = \"\(.region)\"\ndynamodb_table = \"\(.dynamodb_table)\"\nencrypt = true\nkms_key_id = \"\(.kms_key_id)\"\n"' "$handoff" > "$backend"
jq -n --arg handoff "$handoff" --arg config "$config" --arg backend "$backend" --arg cluster "$cluster" --arg cluster_security_group_id "$cluster_security_group_id" \
  '{schema_version:1,ops_access_handoff:$handoff,cluster_name:$cluster,cluster_security_group_id:$cluster_security_group_id,config:$config,backend_config:$backend}' > "$metadata"
chmod 600 "$config" "$backend" "$metadata"
printf 'PASS: isolated SSM ops-access inputs prepared in %s. Use node-operator-ops-access.sh plan before apply.\n' "$output_dir"

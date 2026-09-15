#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/release/prepare-ops-access-inputs.sh"
scratch="$(mktemp -d /private/tmp/node-operator-ops-inputs.XXXXXX)"
handoff="$scratch/ops-access-handoff.json"; output="$scratch/inputs"
tools="$scratch/tools"; mkdir "$tools"
printf '%s\n' '#!/usr/bin/env bash' 'case " $* " in' '  *" sts get-caller-identity "*) printf "%s\n" 123456789012 ;;' '  *" eks describe-cluster "*) printf "%s\n" sg-0123456789abcdef0 ;;' '  *) exit 1 ;;' 'esac' > "$tools/aws"
chmod 700 "$tools/aws"
jq -n '{schema_version:"v1",aws_region:"ap-northeast-2",aws_account_id:"123456789012",cluster_name:"node-operator",vpc_id:"vpc-0123456789abcdef0",subnet_id:"subnet-0123456789abcdef0",backend:{bucket:"node-operator-tfstate-123456789012-apne2",dynamodb_table:"node-operator-terraform-lock",kms_key_id:"arn:aws:kms:ap-northeast-2:123456789012:key/01234567-89ab-cdef-0123-456789abcdef",region:"ap-northeast-2",key:"node-operator/ops-access/terraform.tfstate"}}' > "$handoff"
PATH="$tools:$PATH" "$script" --handoff "$handoff" --output-dir "$output" >/dev/null
jq -e '.vpc_id == "vpc-0123456789abcdef0" and .cluster_security_group_id == "sg-0123456789abcdef0" and .existing_ssm_endpoint_security_group_id == null and .ebs_optimized == true' "$output/ops-access.tfvars.json" >/dev/null
rg -F 'key = "node-operator/ops-access/terraform.tfstate"' "$output/ops-access.backend.hcl" >/dev/null
jq -e '.schema_version == 1 and .cluster_name == "node-operator"' "$output/ops-access-inputs.json" >/dev/null
printf '%s\n' 'PASS: ops-access inputs are derived only from a bounded zero-release handoff.'

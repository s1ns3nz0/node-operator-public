#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
root="$(repo_root)"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

mock_directory="$temporary_directory/bin"
fixture_directory="$temporary_directory/fixture"
output_directory="$temporary_directory/evidence"
mkdir -p "$mock_directory" "$fixture_directory/.git" "$fixture_directory/infrastructure" "$fixture_directory/infra/ops-access" "$fixture_directory/infra/other-module" "$fixture_directory/.semgrep" "$temporary_directory/plugin-mirror"
fixture_directory="$(cd "$fixture_directory" && pwd -P)"
printf 'ref: refs/heads/main\n' > "$fixture_directory/.git/HEAD"
printf 'terraform {}\n' > "$fixture_directory/infrastructure/main.tf"
printf 'terraform {}\n' > "$fixture_directory/infra/ops-access/main.tf"
printf 'terraform {}\n' > "$fixture_directory/infra/other-module/main.tf"
printf 'rules: []\n' > "$fixture_directory/.semgrep/ci.yml"

write_mock() {
  local name="$1"
  shift
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' "$@" > "$mock_directory/$name"
  chmod +x "$mock_directory/$name"
}

write_mock gitleaks '
[ "$1" = "git" ]
[ "$2" = "'"$fixture_directory"'" ]
report=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--report-path" ]; then report="$2"; shift 2; continue; fi
  shift
done
printf "%s\\n" "[{\"File\":\"config.env\",\"RuleID\":\"fixture-secret\",\"Secret\":\"DO_NOT_PERSIST\"}]" > "$report"
exit 1'
write_mock osv-scanner 'printf "%s\\n" "{\"results\":[{\"packages\":[{\"package\":{\"name\":\"fixture-package\"},\"vulnerabilities\":[{\"id\":\"OSV-1\",\"severity\":\"HIGH\",\"fixed_version\":\"2.0.0\"}]}]}]}"; exit 1'
write_mock semgrep '
report=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--json-output" ]; then report="$2"; shift 2; continue; fi
  shift
done
printf "%s\\n" "{\"results\":[{\"path\":\"app.js\",\"check_id\":\"fixture-rule\",\"extra\":{\"severity\":\"WARNING\",\"message\":\"fixture finding\"}}]}" > "$report"
exit 1'
write_mock zizmor 'printf "%s\\n" "[{\"ident\":\"unpinned-uses\",\"desc\":\"fixture workflow finding\",\"locations\":[{\"symbolic\":{\"key\":{\"Local\":{\"verbatim_path\":\".github/workflows/continuous-integration.yml\"}}}}]}]"; exit 11'
write_mock checkov 'printf "%s\\n" "{\"results\":{\"failed_checks\":[{\"resource\":\"aws_instance.host\",\"check_id\":\"CKV_AWS_126\",\"check_name\":\"valid fixture check\",\"file_abs_path\":\"'"$fixture_directory"'/infra/ops-access/main.tf\"},{\"resource\":\"aws_instance.host\",\"check_id\":\"CKV_AWS_126\",\"check_name\":\"other module same address\",\"file_abs_path\":\"'"$fixture_directory"'/infra/other-module/main.tf\"},{\"resource\":\"aws_instance.host\",\"check_id\":\"CKV_MISSING\",\"check_name\":\"missing path\"},{\"resource\":\"aws_instance.host\",\"check_id\":\"CKV_OUTSIDE\",\"check_name\":\"outside path\",\"file_abs_path\":\"/tmp/untrusted/infra/ops-access/main.tf\"},{\"resource\":\"aws_instance.host\",\"check_id\":\"CKV_TRAVERSAL\",\"check_name\":\"traversal path\",\"file_abs_path\":\"'"$fixture_directory"'/infra/ops-access/../other-module/main.tf\"},{\"resource\":\"aws_instance.host\",\"check_id\":\"CKV_BACKSLASH\",\"check_name\":\"backslash path\",\"file_abs_path\":\"'"$fixture_directory"'\\\\infra\\\\ops-access\\\\main.tf\"}],\"skipped_checks\":[{\"resource\":\"aws_s3_bucket.skipped\",\"check_id\":\"CKV_SKIPPED\",\"check_name\":\"skipped fixture\",\"check_result\":{\"suppress_comment\":\"pull-request suppression\"}}]}}"; exit 1'
write_mock terraform '
if [ "$2" = "init" ]; then exit 0; fi
printf "%s\\n" "{\"valid\":true}"
'
write_mock git '
if [ "$1" = "-C" ]; then shift 2; fi
case "$1" in
  cat-file) exit 0 ;;
  diff) if [ "${GIT_CHANGED_ZIZMOR_SUPPRESSED:-false}" = true ]; then printf "nested/유니코드\\taction.yml\\0"; fi; exit 0 ;;
  show) if [ "${GIT_CHANGED_ZIZMOR_SUPPRESSED:-false}" = true ]; then printf "%s\\n" "# zizmor: ignore[dangerous-triggers]" "runs: {using: composite, steps: []}"; fi; exit 0 ;;
  rev-parse) printf "%s\\n" "'"$root"'" ;;
esac
'

PATH="$mock_directory:$PATH" TERRAFORM_PLUGIN_MIRROR="$temporary_directory/plugin-mirror" "$script_dir/collect-pr-evidence.sh" "$output_directory" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$fixture_directory" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

for tool in gitleaks osv semgrep zizmor checkov; do
  jq -e --arg tool "$tool" '.schema_version == "v1" and .tool == $tool and (.result | type == "object")' "$output_directory/$tool.json" >/dev/null
done
jq -e '.result.findings == [{path:"config.env",rule_id:"fixture-secret"}]' "$output_directory/gitleaks.json" >/dev/null
jq -e '.result.vulnerabilities[0] == {package:"fixture-package",id:"OSV-1",severity:"HIGH",fix_available:true}' "$output_directory/osv.json" >/dev/null
jq -e '.result.failed_checks[] | select(.check_id == "CKV_SKIPPED" and .check_name == "IaC check was suppressed in pull-request source")' "$output_directory/checkov.json" >/dev/null
jq -e 'any(.result.failed_checks[]; .check_id == "CKV_AWS_126" and .check_name == "valid fixture check" and .file_path == "infra/ops-access/main.tf")' "$output_directory/checkov.json" >/dev/null
jq -e 'any(.result.failed_checks[]; .check_id == "CKV_AWS_126" and .check_name == "other module same address" and .file_path == "infra/other-module/main.tf")' "$output_directory/checkov.json" >/dev/null
for check_id in CKV_MISSING CKV_OUTSIDE CKV_TRAVERSAL CKV_BACKSLASH CKV_SKIPPED; do
  jq -e --arg check_id "$check_id" 'any(.result.failed_checks[]; (.check_id == $check_id) and (has("file_path") | not))' "$output_directory/checkov.json" >/dev/null
done
suppression_directory="$temporary_directory/suppression-evidence"
GIT_CHANGED_ZIZMOR_SUPPRESSED=true PATH="$mock_directory:$PATH" TERRAFORM_PLUGIN_MIRROR="$temporary_directory/plugin-mirror" "$script_dir/collect-pr-evidence.sh" "$suppression_directory" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$fixture_directory" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
jq -e '.result.findings[] | select(.rule_id == "untrusted-zizmor-suppression")' "$suppression_directory/zizmor.json" >/dev/null
jq -e '.result.status == "passed"' "$output_directory/format.json" >/dev/null
jq -e '.result.status == "passed" and (.result.modules | sort_by(.module)) == [{module:"infra/ops-access",status:"passed"},{module:"infra/other-module",status:"passed"},{module:"infrastructure",status:"passed"}]' "$output_directory/terraform.json" >/dev/null
if grep -R -l 'DO_NOT_PERSIST' "$output_directory" >/dev/null; then
  printf 'raw Gitleaks secret content was retained in collector output\n' >&2
  exit 1
fi
printf '%s\n' '{"changed_files":["README.md"],"pull_request":{"author":"fixture","head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"approvers":[]}' > "$temporary_directory/scm.json"
"$script_dir/normalize-evidence.sh" "$output_directory" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$temporary_directory/scm.json" "$temporary_directory/normalized.json"
jq -e '.evidence.gitleaks.findings[0].rule_id == "fixture-secret"' "$temporary_directory/normalized.json" >/dev/null

write_mock osv-scanner 'printf "%s\\n" "{}"; exit 1'
if PATH="$mock_directory:$PATH" TERRAFORM_PLUGIN_MIRROR="$temporary_directory/plugin-mirror" "$script_dir/collect-pr-evidence.sh" "$temporary_directory/incomplete-evidence" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$fixture_directory" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; then
  printf 'collector accepted an incomplete OSV report\n' >&2
  exit 1
fi

write_mock osv-scanner 'printf "%s\\n" "No package sources found, --help for usage information." >&2; exit 128'
not_applicable_directory="$temporary_directory/not-applicable-evidence"
PATH="$mock_directory:$PATH" TERRAFORM_PLUGIN_MIRROR="$temporary_directory/plugin-mirror" "$script_dir/collect-pr-evidence.sh" "$not_applicable_directory" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$fixture_directory" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
jq -e '.result == {vulnerabilities:[],status:"not_applicable",reason:"no_supported_dependency_manifests"}' "$not_applicable_directory/osv.json" >/dev/null
"$script_dir/normalize-evidence.sh" "$not_applicable_directory" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$temporary_directory/scm.json" "$temporary_directory/not-applicable-normalized.json"
jq -e '.evidence.osv == {vulnerabilities:[],status:"not_applicable",reason:"no_supported_dependency_manifests"}' "$temporary_directory/not-applicable-normalized.json" >/dev/null

terraform_only_directory="$temporary_directory/terraform-only-evidence"
COLLECTOR_MODE=terraform PATH="$mock_directory:$PATH" TERRAFORM_PLUGIN_MIRROR="$temporary_directory/plugin-mirror" "$script_dir/collect-pr-evidence.sh" "$terraform_only_directory" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$fixture_directory"
test -f "$terraform_only_directory/terraform.json"
if find "$terraform_only_directory" -type f ! -name terraform.json | grep -q .; then
  printf 'Terraform-only collection produced an unexpected scanner envelope\n' >&2
  exit 1
fi

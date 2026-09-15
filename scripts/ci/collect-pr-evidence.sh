#!/usr/bin/env bash
# Check objective: Collect commit-bound secret, dependency, workflow, IaC and optional Terraform findings as non-sensitive policy evidence.
set -euo pipefail

# Collect scanner results into compact, non-sensitive envelopes. The five scanner
# envelopes are the sole inputs accepted by normalize-evidence.sh. Scanner stdout,
# stderr, and full reports stay in a private temporary directory and are deleted.

if [ "$#" -lt 2 ] || [ "$#" -gt 4 ]; then
  printf 'usage: %s OUTPUT_DIRECTORY COMMIT_SHA [SOURCE_DIRECTORY] [BASE_SHA]\n' "$0" >&2
  exit 64
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"

output_directory="$1"
commit_sha="$2"
source_directory="${3:-$(repo_root)}"
base_sha="${4:-${PR_BASE_SHA:-}}"
collector_mode="${COLLECTOR_MODE:-all}"

[[ "$commit_sha" =~ ^[0-9a-f]{40}$ ]] || { printf 'commit SHA must be 40 lowercase hexadecimal characters\n' >&2; exit 64; }
require_command git
require_command jq
case "$collector_mode" in
  all)
    require_command gitleaks
    require_command osv-scanner
    require_command semgrep
    require_command zizmor
    require_command checkov
    if [ "${SKIP_TERRAFORM:-false}" != "true" ]; then require_command terraform; fi
    ;;
  terraform)
    require_command terraform
    ;;
  *)
    printf 'COLLECTOR_MODE must be all or terraform\n' >&2
    exit 64
    ;;
esac
git -C "$source_directory" rev-parse --is-inside-work-tree >/dev/null
source_directory="$(cd "$source_directory" && pwd -P)"

umask 077
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
mkdir -p "$output_directory"

write_envelope() {
  local destination="$1" tool="$2" result_path="$3"
  jq -n --arg tool "$tool" --arg sha "$commit_sha" --arg collected_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --slurpfile result "$result_path" \
    '{schema_version:"v1", tool:$tool, commit_sha:$sha, collected_at:$collected_at, result:$result[0]}' > "$destination"
}

run_report() {
  local report_path="$1" log_path="$2"
  shift 2
  set +e
  "$@" > "$report_path" 2> "$log_path"
  collector_exit_code=$?
  set -e
}

require_json_report() {
  local tool="$1" report_path="$2"
  jq -e . "$report_path" >/dev/null 2>&1 || { printf '%s did not produce a valid JSON report\n' "$tool" >&2; exit 1; }
}

require_json_shape() {
  local tool="$1" report_path="$2" shape="$3"
  jq -e "$shape" "$report_path" >/dev/null 2>&1 || { printf '%s produced an incomplete JSON report\n' "$tool" >&2; exit 1; }
}

collect_gitleaks() {
  local report_path="$temporary_directory/gitleaks.json" result_path="$temporary_directory/gitleaks-result.json"
  set +e
  # The checkout is intentionally full-depth in CI. Scan commit history so a
  # secret cannot be hidden by deleting it in the pull request's final tree.
  local -a trusted_options=()
  if [ -n "${GITLEAKS_CONFIG:-}" ]; then trusted_options+=(--config "$GITLEAKS_CONFIG"); fi
  if [ -n "${GITLEAKS_IGNORE_PATH:-}" ]; then trusted_options+=(--gitleaks-ignore-path "$GITLEAKS_IGNORE_PATH"); fi
  if [ "${#trusted_options[@]}" -gt 0 ]; then
    gitleaks git "$source_directory" "${trusted_options[@]}" --ignore-gitleaks-allow --redact=100 --report-format json --report-path "$report_path" --no-banner --no-color > "$temporary_directory/gitleaks.stdout" 2> "$temporary_directory/gitleaks.stderr"
  else
    gitleaks git "$source_directory" --ignore-gitleaks-allow --redact=100 --report-format json --report-path "$report_path" --no-banner --no-color > "$temporary_directory/gitleaks.stdout" 2> "$temporary_directory/gitleaks.stderr"
  fi
  collector_exit_code=$?
  set -e
  [ "$collector_exit_code" -eq 0 ] || [ "$collector_exit_code" -eq 1 ] || { printf 'gitleaks failed before producing evidence\n' >&2; exit 1; }
  require_json_report gitleaks "$report_path"
  require_json_shape gitleaks "$report_path" 'type == "array"'
  # Never retain a raw Gitleaks result. Paths and rule identifiers are sufficient
  # for the policy decision and cannot reconstruct a detected secret.
  jq '[.[]? | {path:(.File // .file // "unknown"), rule_id:(.RuleID // .rule_id // "unknown")}]' "$report_path" \
    | jq -c '{findings:.}' > "$result_path"
  write_envelope "$output_directory/gitleaks.json" gitleaks "$result_path"
}

collect_osv() {
  local report_path="$temporary_directory/osv.json" result_path="$temporary_directory/osv-result.json"
  if [ -n "${OSV_CONFIG_FILE:-}" ]; then
    run_report "$report_path" "$temporary_directory/osv.stderr" osv-scanner scan source --config="$OSV_CONFIG_FILE" --no-ignore --format=json "$source_directory"
  else
    run_report "$report_path" "$temporary_directory/osv.stderr" osv-scanner scan source --format=json "$source_directory"
  fi
  if [ "$collector_exit_code" -eq 128 ] && grep -Fqx 'No package sources found, --help for usage information.' "$temporary_directory/osv.stderr"; then
    # OSV uses exit 128 when the repository contains no supported dependency
    # manifest. This is not a clean dependency scan: retain that distinction
    # in the evidence while allowing a dependency-free repository to proceed.
    printf '%s\n' '{"vulnerabilities":[],"status":"not_applicable","reason":"no_supported_dependency_manifests"}' > "$result_path"
    write_envelope "$output_directory/osv.json" osv "$result_path"
    return
  fi
  [ "$collector_exit_code" -eq 0 ] || [ "$collector_exit_code" -eq 1 ] || { printf 'osv-scanner failed before producing evidence\n' >&2; exit 1; }
  require_json_report osv "$report_path"
  require_json_shape osv "$report_path" '.results | type == "array"'
  # Retain only package and remediation metadata, never lockfile paths or full
  # advisory descriptions. Severity is preserved when the scanner supplies it.
  jq '[.results[]?.packages[]? as $package | $package.vulnerabilities[]? | {
        package: ($package.package.name // "unknown"),
        id: (.id // "unknown"),
        severity: ((.database_specific.severity // .severity // "UNKNOWN") | if type == "string" then . else "UNKNOWN" end),
        fix_available: ((.database_specific.fixed_version? // .fixed_version? // .fixed_versions?[0]? // null) != null)
      }]' "$report_path" | jq -c '{vulnerabilities:.}' > "$result_path"
  write_envelope "$output_directory/osv.json" osv "$result_path"
}

collect_semgrep() {
  local report_path="$temporary_directory/semgrep.json" result_path="$temporary_directory/semgrep-result.json"
  local semgrep_rules="${SEMGREP_RULES:-$source_directory/.semgrep/ci.yml}"
  require_file "$semgrep_rules"
  set +e
  semgrep scan --config "$semgrep_rules" --metrics=off --error --disable-nosem --no-git-ignore --json-output "$report_path" "$source_directory" > "$temporary_directory/semgrep.stdout" 2> "$temporary_directory/semgrep.stderr"
  collector_exit_code=$?
  set -e
  [ "$collector_exit_code" -eq 0 ] || [ "$collector_exit_code" -eq 1 ] || { printf 'semgrep failed before producing evidence\n' >&2; exit 1; }
  require_json_report semgrep "$report_path"
  require_json_shape semgrep "$report_path" '.results | type == "array"'
  jq '[.results[]? | {
        path:(.path // "unknown"),
        rule_id:(.check_id // "unknown"),
        severity:(.extra.severity // "UNKNOWN")
      }]' "$report_path" | jq -c '{findings:.}' > "$result_path"
  write_envelope "$output_directory/semgrep.json" semgrep "$result_path"
}

collect_zizmor() {
  local report_path="$temporary_directory/zizmor.json" result_path="$temporary_directory/zizmor-result.json"
  run_report "$report_path" "$temporary_directory/zizmor.stderr" zizmor --offline --no-config --format=json-v1 "$source_directory"
  [ "$collector_exit_code" -eq 0 ] || [ "$collector_exit_code" -ge 10 ] || { printf 'zizmor failed before producing evidence\n' >&2; exit 1; }
  require_json_report zizmor "$report_path"
  require_json_shape zizmor "$report_path" 'type == "array"'
  jq '[.[]? | {
        path:((.locations[0].symbolic.key.Local.verbatim_path // .locations[0].symbolic.key.Local.given_path // "unknown") | if contains("/.github/") then ".github/" + (split("/.github/")[1]) else . end),
        rule_id:(.ident // "unknown"),
        message:(.desc // "unsafe workflow finding")
      }]' "$report_path" | jq -c '{findings:.}' > "$result_path"
  local changed_yaml has_changed_suppression=false
  changed_yaml="$temporary_directory/zizmor-changed-yaml"
  if [ -n "$base_sha" ] && git -C "$source_directory" cat-file -e "${base_sha}^{commit}" 2>/dev/null; then
    git -C "$source_directory" diff --name-only -z "$base_sha" "$commit_sha" -- '*.yml' '*.yaml' > "$changed_yaml"
    while IFS= read -r -d '' path; do
      if git -C "$source_directory" show "$commit_sha:$path" 2>/dev/null | grep -E 'zizmor:[[:space:]]*ignore' >/dev/null; then
        has_changed_suppression=true
        break
      fi
    done < "$changed_yaml"
  fi
  if [ "$has_changed_suppression" = true ]; then
    jq '.findings += [{path:"workflow-yaml",rule_id:"untrusted-zizmor-suppression",message:"pull request changes YAML containing a zizmor inline suppression"}]' "$result_path" > "$temporary_directory/zizmor-result-with-suppression.json"
    mv "$temporary_directory/zizmor-result-with-suppression.json" "$result_path"
  fi
  write_envelope "$output_directory/zizmor.json" zizmor "$result_path"
}

collect_checkov() {
  local report_path="$temporary_directory/checkov.json" result_path="$temporary_directory/checkov-result.json" checks_path="$temporary_directory/checkov-checks.ndjson"
  local -a trusted_options=()
  if [ -n "${CHECKOV_CONFIG_FILE:-}" ]; then trusted_options+=(--config-file "$CHECKOV_CONFIG_FILE"); fi
  if [ "${#trusted_options[@]}" -gt 0 ]; then
    run_report "$report_path" "$temporary_directory/checkov.stderr" checkov "${trusted_options[@]}" --directory "$source_directory" --framework terraform --output json --quiet
  else
    run_report "$report_path" "$temporary_directory/checkov.stderr" checkov --directory "$source_directory" --framework terraform --output json --quiet
  fi
  [ "$collector_exit_code" -eq 0 ] || [ "$collector_exit_code" -eq 1 ] || { printf 'checkov failed before producing evidence\n' >&2; exit 1; }
  require_json_report checkov "$report_path"
  require_json_shape checkov "$report_path" '.results.failed_checks | type == "array"'
  : > "$checks_path"
  while IFS= read -r check; do
    local resource check_id check_name file_path
    resource="$(jq -r '(.resource // .resource_address // "unknown") | if type == "string" then . else "unknown" end' <<<"$check")"
    check_id="$(jq -r '(.check_id // "unknown") | if type == "string" then . else "unknown" end' <<<"$check")"
    check_name="$(jq -r 'if (.check_result.suppress_comment? // "") != "" then "IaC check was suppressed in pull-request source" else ((.check_name // "IaC policy failure") | if type == "string" then . else "IaC policy failure" end) end' <<<"$check")"
    file_path="$(canonical_checkov_file_path "$(jq -r '.file_abs_path // empty | if type == "string" then . else empty end' <<<"$check")")"
    if [ -n "$file_path" ]; then
      jq -n --arg resource "$resource" --arg check_id "$check_id" --arg check_name "$check_name" --arg file_path "$file_path" '{resource:$resource,check_id:$check_id,check_name:$check_name,file_path:$file_path}' >> "$checks_path"
    else
      jq -n --arg resource "$resource" --arg check_id "$check_id" --arg check_name "$check_name" '{resource:$resource,check_id:$check_id,check_name:$check_name}' >> "$checks_path"
    fi
  done < <(jq -c '((.results.failed_checks // []) + (.results.skipped_checks // []))[]?' "$report_path")
  jq -s -c '{failed_checks:.}' "$checks_path" > "$result_path"
  write_envelope "$output_directory/checkov.json" checkov "$result_path"
}

canonical_checkov_file_path() {
  local candidate="$1" candidate_directory candidate_name canonical_file

  # Checkov's file_abs_path is accepted only as a canonical path to a regular
  # Terraform file in this checkout's /infra subtree. Reject lexical ambiguity,
  # symlink escapes, and every scanner-relative or foreign path. A missing path
  # must remain missing: resource addresses are not a safe location substitute.
  [ -n "$candidate" ] || return 0
  case "$candidate" in
    /*) ;;
    *) return 0 ;;
  esac
  case "$candidate/" in
    *'//'*|*'/./'*|*'/../'*) return 0 ;;
  esac
  [[ "$candidate" == *\\* ]] && return 0
  [[ "$candidate" == "$source_directory"/* ]] || return 0
  [ -f "$candidate" ] && [ ! -L "$candidate" ] || return 0
  candidate_directory="$(dirname "$candidate")"
  candidate_name="$(basename "$candidate")"
  canonical_file="$(cd "$candidate_directory" 2>/dev/null && pwd -P)/$candidate_name"
  [[ "$canonical_file" == "$source_directory"/infra/*.tf ]] || return 0
  printf '%s\n' "${canonical_file#"$source_directory"/}"
}

collect_format() {
  local result_path="$temporary_directory/format-result.json"
  if [ -z "$base_sha" ]; then
    printf '%s\n' '{"status":"skipped","reason":"base SHA was not provided"}' > "$result_path"
  elif ! [[ "$base_sha" =~ ^[0-9a-f]{40}$ ]] || ! git -C "$source_directory" cat-file -e "${base_sha}^{commit}" 2>/dev/null; then
    printf '%s\n' '{"status":"unavailable","reason":"base SHA is not available locally"}' > "$result_path"
  else
    set +e
    git -C "$source_directory" diff --check "$base_sha" "$commit_sha" > "$temporary_directory/format.stdout" 2> "$temporary_directory/format.stderr"
    collector_exit_code=$?
    set -e
    if [ "$collector_exit_code" -eq 0 ]; then
      printf '%s\n' '{"status":"passed","check":"git-diff-check"}' > "$result_path"
    else
      printf '%s\n' '{"status":"failed","check":"git-diff-check"}' > "$result_path"
    fi
  fi
  write_envelope "$output_directory/format.json" format "$result_path"
}

collect_terraform() {
  local directories_path="$temporary_directory/terraform-directories" result_path="$temporary_directory/terraform-result.json"
  local root_module="$source_directory/infra/terraform"

  # The evidence gate must use the same root-module plan contract as
  # CI Terraform. Walking every nested .tf directory treats implementation
  # fragments as standalone modules and permanently blocks unrelated PRs.
  # This branch is used by the dedicated, network-isolated Terraform image;
  # its collector script is checked out from the trusted default branch.
  if [ -d "$root_module" ] && [ -x "$script_dir/validate-terraform-offline.sh" ]; then
    local validation_directory="$temporary_directory/terraform-root-validation"
    set +e
    "$script_dir/validate-terraform-offline.sh" "$root_module" "$validation_directory" > "$temporary_directory/terraform-root.stdout" 2> "$temporary_directory/terraform-root.stderr"
    local validation_exit=$?
    set -e
    if [ "$validation_exit" -eq 0 ]; then
      printf '%s\n' '{"status":"passed","modules":[{"module":"infra/terraform","status":"passed"}]}' > "$result_path"
    else
      printf '%s\n' '{"status":"failed","modules":[{"module":"infra/terraform","status":"failed"}]}' > "$result_path"
    fi
    write_envelope "$output_directory/terraform.json" terraform "$result_path"
    return
  fi

  find "$source_directory" -type f -name '*.tf' -exec dirname {} \; | LC_ALL=C sort -u > "$directories_path"
  if [ ! -s "$directories_path" ]; then
    printf '%s\n' '{"status":"not_applicable","modules":[]}' > "$result_path"
    write_envelope "$output_directory/terraform.json" terraform "$result_path"
    return
  fi

  if [ -z "${TERRAFORM_PLUGIN_MIRROR:-}" ] || [ ! -d "$TERRAFORM_PLUGIN_MIRROR" ]; then
    printf '%s\n' '{"status":"failed","reason":"offline provider mirror is required"}' > "$result_path"
    write_envelope "$output_directory/terraform.json" terraform "$result_path"
    return
  fi

  cat > "$temporary_directory/terraformrc" <<EOF
provider_installation {
  filesystem_mirror {
    path = "$TERRAFORM_PLUGIN_MIRROR"
  }
  direct {
    exclude = ["*/*"]
  }
}
EOF

  : > "$temporary_directory/terraform-modules.ndjson"
  local index=0 module_directory init_exit validate_exit
  while IFS= read -r module_directory; do
    index=$((index + 1))
    set +e
    TF_CLI_CONFIG_FILE="$temporary_directory/terraformrc" TF_DATA_DIR="$temporary_directory/terraform-data-$index" terraform -chdir="$module_directory" init -backend=false -get=false -input=false -lockfile=readonly -no-color > "$temporary_directory/terraform-init-$index.stdout" 2> "$temporary_directory/terraform-init-$index.stderr"
    init_exit=$?
    if [ "$init_exit" -eq 0 ]; then
      TF_CLI_CONFIG_FILE="$temporary_directory/terraformrc" TF_DATA_DIR="$temporary_directory/terraform-data-$index" terraform -chdir="$module_directory" validate -json -no-color > "$temporary_directory/terraform-validate-$index.json" 2> "$temporary_directory/terraform-validate-$index.stderr"
      validate_exit=$?
    else
      validate_exit=1
    fi
    set -e
    if [ "$init_exit" -eq 0 ] && [ "$validate_exit" -eq 0 ] && jq -e '.valid == true' "$temporary_directory/terraform-validate-$index.json" >/dev/null 2>&1; then
      jq -n --arg module "${module_directory#"$source_directory"/}" '{module:$module,status:"passed"}' >> "$temporary_directory/terraform-modules.ndjson"
    else
      jq -n --arg module "${module_directory#"$source_directory"/}" '{module:$module,status:"failed"}' >> "$temporary_directory/terraform-modules.ndjson"
    fi
  done < "$directories_path"
  jq -s '{status:(if any(.[]; .status == "failed") then "failed" else "passed" end), modules:.}' "$temporary_directory/terraform-modules.ndjson" > "$result_path"
  write_envelope "$output_directory/terraform.json" terraform "$result_path"
}

if [ "$collector_mode" = "terraform" ]; then
  collect_terraform
  exit 0
fi

collect_gitleaks
collect_osv
collect_semgrep
collect_zizmor
collect_checkov
collect_format
if [ "${SKIP_TERRAFORM:-false}" = "true" ]; then
  jq -n --arg sha "$commit_sha" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{schema_version:"v1",tool:"terraform",commit_sha:$sha,collected_at:$at,result:{status:"not_run",modules:[]}}' > "$output_directory/terraform.json"
else
  collect_terraform
fi

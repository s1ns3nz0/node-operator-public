#!/usr/bin/env bash
# Check objective: Reject untrusted scanner policy replacement before collecting evidence.
# Purpose: Block PR changes to scanner rules and ignore files that must remain trusted control-plane inputs.
# Inputs: .pr-source checkout plus BASE_SHA and SUBJECT_SHA.
# Outputs: Exit status only, with the prohibited path on stderr.
# Side effects: Read-only local Git comparison; no network or workspace mutation.
set -euo pipefail

while IFS= read -r -d '' path; do
  name="${path##*/}"
  case "$path:$name" in
    .semgrep/*:*|*/.semgrep/*:*|*:*.semgrepignore|*:*.gitleaks.toml|*:*.gitleaksignore|*:*.checkov.yml|*:*.checkov.yaml|*:osv-scanner.toml|*:.osv-scanner.toml)
      echo "Pull requests cannot replace trusted scanner policy or ignore files: $path" >&2
      exit 1
      ;;
  esac
done < <(git -C .pr-source diff --name-only -z "$BASE_SHA" "$SUBJECT_SHA")

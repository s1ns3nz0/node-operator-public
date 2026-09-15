#!/usr/bin/env bash
# Check objective: Select one provenance-bound CI evidence artifact for archival.
# Inputs: isolated gate/review artifact roots, EXPECTED_GATE_RUN_ID, and GITHUB_OUTPUT.
# Outputs: subject_sha and evidence_directory GitHub step outputs; nonzero on ambiguity or invalid provenance.
# Trust boundary: the workflow must download from its exact trusted producer run.
# This helper checks bundle consistency, not independent GitHub provenance. Review
# refresh bundles retain their original gate context; the triggering run's SHA is
# the control-plane revision and must not be substituted for the PR subject SHA.
# archive-ci-evidence.sh independently allowlists members and validates the decision.
set -euo pipefail

: "${EVIDENCE_ROOT:?EVIDENCE_ROOT is required}"
: "${EXPECTED_GATE_RUN_ID:?EXPECTED_GATE_RUN_ID is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
[[ "$EXPECTED_GATE_RUN_ID" =~ ^[1-9][0-9]*$ ]] || { printf '%s\n' 'expected gate run ID must be numeric' >&2; exit 64; }

candidate_directories=()
for source in gate review; do
  source_root="$EVIDENCE_ROOT/$source"
  evidence_files=()
  while IFS= read -r evidence_file; do
    evidence_files+=("$evidence_file")
  done < <(find "$source_root" -type f -name evidence.json -print 2>/dev/null)
  test "${#evidence_files[@]}" -le 1 || { printf '%s\n' "multiple evidence files in $source artifact download" >&2; exit 1; }
  test "${#evidence_files[@]}" -eq 0 && continue

  evidence_directory="$(dirname "${evidence_files[0]}")"
  for member in evidence.json decision.json cache-context.json; do
    test -f "$evidence_directory/$member" && test ! -L "$evidence_directory/$member" || { printf '%s\n' "required safe evidence member is absent: $member" >&2; exit 1; }
  done
  subject_sha="$(jq -er '.subject.commit_sha' "$evidence_directory/evidence.json")"
  [[ "$subject_sha" =~ ^[a-f0-9]{40}$ ]] || { printf '%s\n' 'evidence subject must be a lowercase commit SHA' >&2; exit 1; }
  case "$source" in
    gate) expected_artifact_directory="$source_root/ci-evidence-gate-$subject_sha" ;;
    review) expected_artifact_directory="$source_root/ci-review-decision-$EXPECTED_GATE_RUN_ID" ;;
  esac
  test "$evidence_directory" = "$expected_artifact_directory" || { printf '%s\n' 'evidence is not in its expected exact-run artifact directory' >&2; exit 1; }
  jq -e --arg subject_sha "$subject_sha" '
    .schema_version == 1 and .subject_sha == $subject_sha and
    (.base_sha | type == "string" and test("^[a-f0-9]{40}$")) and
    (.trusted_sha | type == "string" and test("^[a-f0-9]{40}$")) and
    (.source_run_id | type == "number" and . > 0) and
    (.gate_run_id | type == "number" and . > 0)
  ' "$evidence_directory/cache-context.json" >/dev/null || { printf '%s\n' 'cache context does not bind the exact evidence subject' >&2; exit 1; }
  if [ "$source" = gate ]; then
    jq -e --argjson run_id "$EXPECTED_GATE_RUN_ID" '.gate_run_id == $run_id' "$evidence_directory/cache-context.json" >/dev/null || { printf '%s\n' 'gate cache context does not bind the triggering run' >&2; exit 1; }
  fi
  candidate_directories+=("$evidence_directory")
done

test "${#candidate_directories[@]}" -eq 1 || { printf '%s\n' 'expected exactly one valid exact-run evidence artifact' >&2; exit 1; }
evidence_directory="${candidate_directories[0]}"
subject_sha="$(jq -er '.subject.commit_sha' "$evidence_directory/evidence.json")"
printf 'subject_sha=%s\n' "$subject_sha" >> "$GITHUB_OUTPUT"
printf 'evidence_directory=%s\n' "$evidence_directory" >> "$GITHUB_OUTPUT"

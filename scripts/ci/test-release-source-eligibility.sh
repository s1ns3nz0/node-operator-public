#!/usr/bin/env bash
# Check objective: Verify release source eligibility accepts only approved workflow provenance.
# shellcheck disable=SC2016 # Fixtures intentionally write scripts with runtime variables.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/../.." && pwd)"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
mkdir -p "$temporary_directory/bin"
sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

grep -Fq 'pull_request:' "$root/.github/workflows/continuous-integration.yml"
grep -Fq 'branches: [main]' "$root/.github/workflows/continuous-integration.yml"

printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'exit "${GIT_RESULT:-0}"' > "$temporary_directory/bin/git"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
  'for arg in "$@"; do case "$arg" in *commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/check-runs*) jq -c ".check_runs[]" "$SOURCE_CHECK_FIXTURE"; exit ;; *commits/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/check-runs*) jq -c ".check_runs[]" "$PR_CHECK_FIXTURE"; exit ;; *commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/pulls) cat "$PULL_FIXTURE"; exit ;; *actions/runs/106/artifacts*) cat "$ARTIFACT_FIXTURE"; exit ;; *actions/artifacts/777/zip*) printf fixture; exit ;; *actions/runs/*) run_id="${arg##*/}"; jq -c --arg id "$run_id" ".[\$id]" "$RUN_FIXTURE"; if [ "${FAIL_RUN_API:-false}" = true ]; then exit 1; fi; exit ;; esac; done; exit 1' > "$temporary_directory/bin/gh"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' '
case "$1" in
  -Z1) printf "%s\n" evidence.json decision.json ;;
  -p) case "$3" in evidence.json) cat "$EVIDENCE_FIXTURE" ;; decision.json) cat "$DECISION_FIXTURE" ;; *) exit 1 ;; esac ;;
  *) exit 1 ;;
esac' > "$temporary_directory/bin/unzip"
chmod +x "$temporary_directory/bin/git" "$temporary_directory/bin/gh" "$temporary_directory/bin/unzip"
jq -n --arg sha "$sha" '
  ["quality","scanners","Policy Rules","Terraform Validation","Evidence Contracts"] |
  to_entries | map({name:.value,status:"completed",conclusion:"success",head_sha:$sha,app:{slug:"github-actions"},details_url:("https://github.com/owner/repo/actions/runs/10" + ((.key + 1) | tostring) + "/job/456")}) |
  {total_count:length,check_runs:.}
' > "$temporary_directory/pass.json"
printf '%s\n' '{"total_count":1,"check_runs":[{"id":900,"external_id":"ci-evidence-workflow-run:106:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","name":"CI Evidence Decision","status":"completed","conclusion":"success","head_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","app":{"slug":"github-actions"},"details_url":"https://github.com/owner/repo/actions/runs/106"}]}' > "$temporary_directory/pr-check.json"
printf '%s\n' '[{"merged_at":"2026-09-08T00:00:00Z","merge_commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","base":{"ref":"main","repo":{"full_name":"owner/repo"}},"head":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}]' > "$temporary_directory/pulls.json"
jq -n --arg sha "$sha" '[101,102,103,104,105,106] as $ids | {"101":{repository:{full_name:"owner/repo"},path:".github/workflows/continuous-integration.yml",event:"push",head_sha:$sha},"102":{repository:{full_name:"owner/repo"},path:".github/workflows/continuous-integration.yml",event:"push",head_sha:$sha},"103":{repository:{full_name:"owner/repo"},path:".github/workflows/continuous-integration.yml",event:"push",head_sha:$sha},"104":{repository:{full_name:"owner/repo"},path:".github/workflows/continuous-integration.yml",event:"push",head_sha:$sha},"105":{repository:{full_name:"owner/repo"},path:".github/workflows/continuous-integration.yml",event:"push",head_sha:$sha},"106":{repository:{full_name:"owner/repo"},path:".github/workflows/evidence-gate.yml",event:"workflow_run",head_sha:"cccccccccccccccccccccccccccccccccccccccc"}} | with_entries(.value.status="completed" | .value.conclusion="success")' > "$temporary_directory/runs.json"
printf '%s\n' '{"artifacts":[{"id":777,"name":"ci-evidence-gate-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expired":false,"workflow_run":{"id":106}}]}' > "$temporary_directory/artifacts.json"
printf '%s\n' '{"subject":{"commit_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}' > "$temporary_directory/evidence.json"
printf '%s\n' '{"summary":{"block":0,"require_approval":0},"violations":[]}' > "$temporary_directory/decision.json"
export EVIDENCE_FIXTURE="$temporary_directory/evidence.json" DECISION_FIXTURE="$temporary_directory/decision.json"
SOURCE_CHECK_FIXTURE="$temporary_directory/pass.json" PR_CHECK_FIXTURE="$temporary_directory/pr-check.json" PULL_FIXTURE="$temporary_directory/pulls.json" RUN_FIXTURE="$temporary_directory/runs.json" ARTIFACT_FIXTURE="$temporary_directory/artifacts.json" GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/verify-release-source-eligibility.sh" "$sha" >/dev/null

# A review-refresh decision is eligible only when its artifact name binds it to
# the same trusted gate run that owns the exact-head CI Evidence Decision.
printf '%s\n' '{"artifacts":[{"id":777,"name":"ci-review-decision-106","expired":false,"workflow_run":{"id":106}}]}' > "$temporary_directory/review-artifacts.json"
SOURCE_CHECK_FIXTURE="$temporary_directory/pass.json" PR_CHECK_FIXTURE="$temporary_directory/pr-check.json" PULL_FIXTURE="$temporary_directory/pulls.json" RUN_FIXTURE="$temporary_directory/runs.json" ARTIFACT_FIXTURE="$temporary_directory/review-artifacts.json" GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/verify-release-source-eligibility.sh" "$sha" >/dev/null
printf '%s\n' '{"artifacts":[{"id":777,"name":"ci-review-decision-107","expired":false,"workflow_run":{"id":106}}]}' > "$temporary_directory/wrong-review-artifacts.json"
if SOURCE_CHECK_FIXTURE="$temporary_directory/pass.json" PR_CHECK_FIXTURE="$temporary_directory/pr-check.json" PULL_FIXTURE="$temporary_directory/pulls.json" RUN_FIXTURE="$temporary_directory/runs.json" ARTIFACT_FIXTURE="$temporary_directory/wrong-review-artifacts.json" GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/verify-release-source-eligibility.sh" "$sha" 2>/dev/null; then
  printf 'eligibility accepted a review decision artifact from another gate run\n' >&2
  exit 1
fi

if FAIL_RUN_API=true SOURCE_CHECK_FIXTURE="$temporary_directory/pass.json" PR_CHECK_FIXTURE="$temporary_directory/pr-check.json" PULL_FIXTURE="$temporary_directory/pulls.json" RUN_FIXTURE="$temporary_directory/runs.json" ARTIFACT_FIXTURE="$temporary_directory/artifacts.json" GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/verify-release-source-eligibility.sh" "$sha" 2>/dev/null; then
  printf 'eligibility accepted valid-looking run JSON from a failed API request\n' >&2
  exit 1
fi
: > "$temporary_directory/empty.json"
if SOURCE_CHECK_FIXTURE="$temporary_directory/pass.json" PR_CHECK_FIXTURE="$temporary_directory/pr-check.json" PULL_FIXTURE="$temporary_directory/pulls.json" RUN_FIXTURE="$temporary_directory/runs.json" ARTIFACT_FIXTURE="$temporary_directory/artifacts.json" EVIDENCE_FIXTURE="$temporary_directory/empty.json" DECISION_FIXTURE="$temporary_directory/decision.json" GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/verify-release-source-eligibility.sh" "$sha" 2>/dev/null; then
  printf 'eligibility accepted an empty evidence document\n' >&2
  exit 1
fi
if SOURCE_CHECK_FIXTURE="$temporary_directory/pass.json" PR_CHECK_FIXTURE="$temporary_directory/pr-check.json" PULL_FIXTURE="$temporary_directory/pulls.json" RUN_FIXTURE="$temporary_directory/runs.json" ARTIFACT_FIXTURE="$temporary_directory/artifacts.json" EVIDENCE_FIXTURE="$temporary_directory/evidence.json" DECISION_FIXTURE="$temporary_directory/empty.json" GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/verify-release-source-eligibility.sh" "$sha" 2>/dev/null; then
  printf 'eligibility accepted an empty decision document\n' >&2
  exit 1
fi

printf '%s\n' '{"summary":{"block":1,"require_approval":0},"violations":[{"id":"fixture.block"}]}' > "$temporary_directory/blocked-decision.json"
if SOURCE_CHECK_FIXTURE="$temporary_directory/pass.json" PR_CHECK_FIXTURE="$temporary_directory/pr-check.json" PULL_FIXTURE="$temporary_directory/pulls.json" RUN_FIXTURE="$temporary_directory/runs.json" ARTIFACT_FIXTURE="$temporary_directory/artifacts.json" EVIDENCE_FIXTURE="$temporary_directory/evidence.json" DECISION_FIXTURE="$temporary_directory/blocked-decision.json" GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/verify-release-source-eligibility.sh" "$sha" 2>/dev/null; then
  printf 'eligibility accepted an artifact containing a blocked decision\n' >&2
  exit 1
fi

printf '%s\n' '{"artifacts":[{"name":"ci-evidence-gate-cccccccccccccccccccccccccccccccccccccccc","expired":false,"workflow_run":{"id":106}}]}' > "$temporary_directory/wrong-artifacts.json"
if SOURCE_CHECK_FIXTURE="$temporary_directory/pass.json" PR_CHECK_FIXTURE="$temporary_directory/pr-check.json" PULL_FIXTURE="$temporary_directory/pulls.json" RUN_FIXTURE="$temporary_directory/runs.json" ARTIFACT_FIXTURE="$temporary_directory/wrong-artifacts.json" GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/verify-release-source-eligibility.sh" "$sha" 2>/dev/null; then
  printf 'eligibility accepted a publisher run without exact-subject evidence\n' >&2
  exit 1
fi
jq '.check_runs[0].external_id = "ci-evidence-workflow-run:106:cccccccccccccccccccccccccccccccccccccccc"' "$temporary_directory/pr-check.json" > "$temporary_directory/replayed-subject.json"
if SOURCE_CHECK_FIXTURE="$temporary_directory/pass.json" PR_CHECK_FIXTURE="$temporary_directory/replayed-subject.json" PULL_FIXTURE="$temporary_directory/pulls.json" RUN_FIXTURE="$temporary_directory/runs.json" ARTIFACT_FIXTURE="$temporary_directory/artifacts.json" GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/verify-release-source-eligibility.sh" "$sha" 2>/dev/null; then
  printf 'eligibility accepted an external publisher binding for another subject\n' >&2
  exit 1
fi

jq '(.check_runs[] | select(.name == "CI Evidence Decision") | .conclusion) = "failure"' "$temporary_directory/pr-check.json" > "$temporary_directory/fail.json"
if SOURCE_CHECK_FIXTURE="$temporary_directory/pass.json" PR_CHECK_FIXTURE="$temporary_directory/fail.json" PULL_FIXTURE="$temporary_directory/pulls.json" RUN_FIXTURE="$temporary_directory/runs.json" GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/verify-release-source-eligibility.sh" "$sha" 2>/dev/null; then
  printf 'eligibility accepted a failed OPA evidence decision\n' >&2
  exit 1
fi
jq '.check_runs[0].external_id = "ci-evidence-workflow-run:101"' "$temporary_directory/pr-check.json" > "$temporary_directory/spoofed-publisher.json"
if SOURCE_CHECK_FIXTURE="$temporary_directory/pass.json" PR_CHECK_FIXTURE="$temporary_directory/spoofed-publisher.json" PULL_FIXTURE="$temporary_directory/pulls.json" RUN_FIXTURE="$temporary_directory/runs.json" GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/verify-release-source-eligibility.sh" "$sha" 2>/dev/null; then
  printf 'eligibility accepted a custom check bound to the wrong publisher workflow\n' >&2
  exit 1
fi
jq '.check_runs[0].details_url = "https://github.com/owner/repo/runs/901"' "$temporary_directory/pr-check.json" > "$temporary_directory/spoofed-check-id.json"
if SOURCE_CHECK_FIXTURE="$temporary_directory/pass.json" PR_CHECK_FIXTURE="$temporary_directory/spoofed-check-id.json" PULL_FIXTURE="$temporary_directory/pulls.json" RUN_FIXTURE="$temporary_directory/runs.json" GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/verify-release-source-eligibility.sh" "$sha" 2>/dev/null; then
  printf 'eligibility accepted a mismatched custom check ID\n' >&2
  exit 1
fi
jq '(.check_runs[] | select(.name == "quality") | .app.slug) = "untrusted-app"' "$temporary_directory/pass.json" > "$temporary_directory/spoofed.json"
if SOURCE_CHECK_FIXTURE="$temporary_directory/spoofed.json" PR_CHECK_FIXTURE="$temporary_directory/pr-check.json" PULL_FIXTURE="$temporary_directory/pulls.json" RUN_FIXTURE="$temporary_directory/runs.json" GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/verify-release-source-eligibility.sh" "$sha" 2>/dev/null; then
  printf 'eligibility accepted a check from an untrusted app\n' >&2
  exit 1
fi
jq '.["101"].path = ".github/workflows/untrusted.yml"' "$temporary_directory/runs.json" > "$temporary_directory/spoofed-runs.json"
if SOURCE_CHECK_FIXTURE="$temporary_directory/pass.json" PR_CHECK_FIXTURE="$temporary_directory/pr-check.json" PULL_FIXTURE="$temporary_directory/pulls.json" RUN_FIXTURE="$temporary_directory/spoofed-runs.json" GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/verify-release-source-eligibility.sh" "$sha" 2>/dev/null; then
  printf 'eligibility accepted a check created by the wrong workflow\n' >&2
  exit 1
fi
jq '.[0].merge_commit_sha = "cccccccccccccccccccccccccccccccccccccccc"' "$temporary_directory/pulls.json" > "$temporary_directory/stale-pulls.json"
if SOURCE_CHECK_FIXTURE="$temporary_directory/pass.json" PR_CHECK_FIXTURE="$temporary_directory/pr-check.json" PULL_FIXTURE="$temporary_directory/stale-pulls.json" RUN_FIXTURE="$temporary_directory/runs.json" GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/verify-release-source-eligibility.sh" "$sha" 2>/dev/null; then
  printf 'eligibility accepted an associated pull request for an old merge commit\n' >&2
  exit 1
fi
if GIT_RESULT=1 SOURCE_CHECK_FIXTURE="$temporary_directory/pass.json" PR_CHECK_FIXTURE="$temporary_directory/pr-check.json" PULL_FIXTURE="$temporary_directory/pulls.json" RUN_FIXTURE="$temporary_directory/runs.json" GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/verify-release-source-eligibility.sh" "$sha" 2>/dev/null; then
  printf 'eligibility accepted a source outside origin/main\n' >&2
  exit 1
fi
printf 'PASS: release eligibility requires main ancestry and exact-SHA trusted security checks.\n'

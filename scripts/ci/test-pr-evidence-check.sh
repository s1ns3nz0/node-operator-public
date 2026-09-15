#!/usr/bin/env bash
# Check objective: Verify PR evidence collection binds GitHub workflow data to the reviewed commit.
# shellcheck disable=SC2016 # The fake gh fixture intentionally expands variables only when executed.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
mkdir -p "$temporary_directory/bin"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'printf "%s\n" "$@" > "$GH_CAPTURE"' > "$temporary_directory/bin/gh"
chmod +x "$temporary_directory/bin/gh"
sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
url="https://github.com/owner/repo/actions/runs/123"

printf '%s\n' '{"violations":[],"summary":{"block":0,"warn":0,"require_approval":0}}' > "$temporary_directory/pass.json"
GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo GH_CAPTURE="$temporary_directory/pass.args" PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/publish-pr-evidence-check.sh" "$sha" "$temporary_directory/pass.json" "$url" >/dev/null
grep -Fx 'head_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$temporary_directory/pass.args" >/dev/null
grep -Fx 'conclusion=success' "$temporary_directory/pass.args" >/dev/null
grep -Fx 'name=CI Evidence Decision' "$temporary_directory/pass.args" >/dev/null
grep -Fx 'external_id=ci-evidence-workflow-run:123:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$temporary_directory/pass.args" >/dev/null

printf '%s\n' '{"violations":[{"id":"sast.synthetic","class":"block"}],"summary":{"block":1,"warn":0,"require_approval":0}}' > "$temporary_directory/fail.json"
GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo GH_CAPTURE="$temporary_directory/fail.args" PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/publish-pr-evidence-check.sh" "$sha" "$temporary_directory/fail.json" "$url" >/dev/null
grep -Fx 'conclusion=failure' "$temporary_directory/fail.args" >/dev/null
grep -Fx 'output[summary]=Trusted OPA decision reported block=1 and require_approval=0.' "$temporary_directory/fail.args" >/dev/null

printf '%s\n' '{}' > "$temporary_directory/malformed.json"
GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo GH_CAPTURE="$temporary_directory/malformed.args" PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/publish-pr-evidence-check.sh" "$sha" "$temporary_directory/malformed.json" "$url" >/dev/null
grep -Fx 'conclusion=failure' "$temporary_directory/malformed.args" >/dev/null

GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo GH_CAPTURE="$temporary_directory/upstream.args" PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/publish-pr-evidence-check.sh" "$sha" - "$url" >/dev/null
grep -Fx 'conclusion=failure' "$temporary_directory/upstream.args" >/dev/null

if GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo GH_CAPTURE="$temporary_directory/invalid.args" PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/publish-pr-evidence-check.sh" 'refs/heads/main' "$temporary_directory/pass.json" "$url" 2>/dev/null; then
  printf 'publisher accepted a non-SHA check subject\n' >&2
  exit 1
fi

printf '%s\n' '{"repository":{"default_branch":"main"},"workflow_run":{"event":"pull_request","name":"CI","path":".github/workflows/continuous-integration.yml","repository":{"full_name":"owner/repo"},"head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pull_requests":[{"number":7}]}}' > "$temporary_directory/event.json"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
  'case "$2" in repos/owner/repo/pulls/7) printf "%s\n" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;; *) exit 1 ;; esac' > "$temporary_directory/bin/gh"
chmod +x "$temporary_directory/bin/gh"
GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo TRUSTED_WORKFLOW_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/resolve-pr-evidence-context.sh" "$temporary_directory/event.json" "$temporary_directory/context.out"
grep -Fx 'subject_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$temporary_directory/context.out" >/dev/null
grep -Fx 'trusted_sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' "$temporary_directory/context.out" >/dev/null
jq '.workflow_run.path = ".github/workflows/attacker.yml"' "$temporary_directory/event.json" > "$temporary_directory/wrong-workflow.json"
if GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo TRUSTED_WORKFLOW_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/resolve-pr-evidence-context.sh" "$temporary_directory/wrong-workflow.json" "$temporary_directory/wrong.out" 2>/dev/null; then
  printf 'resolver accepted the wrong upstream workflow identity\n' >&2
  exit 1
fi
printf 'PASS: trusted evidence publishes a fail-closed check on the exact PR head SHA.\n'

# The consolidated producer accepts only the new exact pair.
jq '.workflow_run.name = "CI" | .workflow_run.path = ".github/workflows/continuous-integration.yml"' "$temporary_directory/event.json" > "$temporary_directory/new-ci.json"
GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo TRUSTED_WORKFLOW_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/resolve-pr-evidence-context.sh" "$temporary_directory/new-ci.json" "$temporary_directory/new-ci.out"
grep -Fx 'subject_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$temporary_directory/new-ci.out" >/dev/null
for name in 'CI' 'CI Security'; do
  if [ "$name" = 'CI' ]; then wrong_path='.github/workflows/ci-security.yml'; else wrong_path='.github/workflows/continuous-integration.yml'; fi
  jq --arg name "$name" --arg path "$wrong_path" '.workflow_run.name=$name | .workflow_run.path=$path' "$temporary_directory/event.json" > "$temporary_directory/crossed.json"
  if GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo TRUSTED_WORKFLOW_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb PATH="$temporary_directory/bin:$PATH" \
    "$script_dir/resolve-pr-evidence-context.sh" "$temporary_directory/crossed.json" "$temporary_directory/crossed.out" 2>/dev/null; then
    printf 'resolver accepted a mismatched workflow name/path pair\n' >&2
    exit 1
  fi
done
jq '.workflow_run.name = "CI Security" | .workflow_run.path = ".github/workflows/ci-security.yml"' "$temporary_directory/event.json" > "$temporary_directory/legacy-ci.json"
if GH_TOKEN=fixture GITHUB_REPOSITORY=owner/repo TRUSTED_WORKFLOW_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/resolve-pr-evidence-context.sh" "$temporary_directory/legacy-ci.json" "$temporary_directory/legacy-ci.out" 2>/dev/null; then
  printf 'resolver accepted the retired CI workflow\n' >&2
  exit 1
fi
printf 'PASS: consolidated CI identity accepted; legacy and crossed identities rejected.\n'

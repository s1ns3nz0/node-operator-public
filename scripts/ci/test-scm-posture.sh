#!/usr/bin/env bash
# shellcheck disable=SC2016 # Fake gh expands fixture variables at execution time.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
temporary_directory="$(mktemp -d)"; trap 'rm -rf "$temporary_directory"' EXIT
mkdir -p "$temporary_directory/bin"
printf '%s\n' '#!/usr/bin/env bash' 'case "$*" in *"pulls/1"*files*) printf "%s\n" "[{\"filename\":\"policy/decision.rego\"}]" ;; *"pulls/1"*reviews*) cat "$REVIEWS_FIXTURE" ;; *"pulls/1"*) printf "%s\n" "{\"user\":{\"login\":\"author\"},\"head\":{\"sha\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}" ;; *) exit 64 ;; esac' > "$temporary_directory/bin/gh"
chmod +x "$temporary_directory/bin/gh"
printf '%s\n' '[{"id":1,"state":"APPROVED","commit_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","user":{"login":"fjybjinsu"}}]' > "$temporary_directory/reviews.json"
printf '%s\n' '{"pull_request":{"number":1,"user":{"login":"author"},"head":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}' > "$temporary_directory/event.json"
REVIEWS_FIXTURE="$temporary_directory/reviews.json" PATH="$temporary_directory/bin:$PATH" GITHUB_EVENT_PATH="$temporary_directory/event.json" GITHUB_REPOSITORY="owner/repo" "$script_dir/collect-scm-posture.sh" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$temporary_directory/scm.json"
jq -e '.changed_files == ["policy/decision.rego"] and .pull_request.head_sha == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and .approvers == ["fjybjinsu"]' "$temporary_directory/scm.json" >/dev/null
REVIEWS_FIXTURE="$temporary_directory/reviews.json" PATH="$temporary_directory/bin:$PATH" GITHUB_EVENT_PATH="$temporary_directory/event.json" GITHUB_REPOSITORY="owner/repo" "$script_dir/collect-scm-posture.sh" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$temporary_directory/workflow-run-scm.json" 1
jq -e '.changed_files == ["policy/decision.rego"] and .pull_request.head_sha == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and .approvers == ["fjybjinsu"]' "$temporary_directory/workflow-run-scm.json" >/dev/null
printf '%s\n' '[{"id":1,"state":"APPROVED","commit_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","user":{"login":"fjybjinsu"}},{"id":2,"state":"CHANGES_REQUESTED","commit_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","user":{"login":"fjybjinsu"}}]' > "$temporary_directory/reviews.json"
REVIEWS_FIXTURE="$temporary_directory/reviews.json" PATH="$temporary_directory/bin:$PATH" GITHUB_EVENT_PATH="$temporary_directory/event.json" GITHUB_REPOSITORY="owner/repo" "$script_dir/collect-scm-posture.sh" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$temporary_directory/revoked-scm.json"
jq -e '.approvers == []' "$temporary_directory/revoked-scm.json" >/dev/null

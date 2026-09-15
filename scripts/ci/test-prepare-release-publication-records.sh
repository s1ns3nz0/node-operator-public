#!/usr/bin/env bash
# Check objective: Prove release record preparation only selects a bounded hint and delegates trust validation to the retriever.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
helper="$root/scripts/ci/prepare-release-publication-records.sh"
workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT
sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
log="$workspace/log"
fail() { printf 'FAIL prepare release publication records: %s\n' "$*" >&2; exit 1; }

mkdir "$workspace/bin"
mkdir "$workspace/legacy-source"
# shellcheck disable=SC2016 # The fake commands must receive these expansions literally.
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'printf "gh %s\\n" "$*" >> "$FAKE_LOG"' 'if [ "${FAKE_GH_MODE:-success}" = empty ]; then exit 0; fi' 'printf "%s\\n" "${FAKE_GH_RUN_ID:-123}"' > "$workspace/bin/gh"
# shellcheck disable=SC2016 # The fake Python program must receive these expansions literally.
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'printf "python %s\\n" "$*" >> "$FAKE_LOG"' 'output=""; authorization=""; previous=""' 'for argument in "$@"; do if [ "$previous" = --output-dir ]; then output="$argument"; fi; if [ "$previous" = --authorization-path ]; then authorization="$argument"; fi; previous="$argument"; done' '[ -n "$output" ] || exit 91' 'mkdir -p "$output"' 'case "$1" in *fetch-prysm-mtls-publication-record.py) printf "{}\\n" > "$output/prysm-mtls-publication-record.json" ;; *fetch-fence-publication-record.py) case "$authorization" in /*) ;; *) exit 92 ;; esac; printf "{}\\n" > "$output/fence-release-verification.json" ;; *fetch-signer-probe-publication-record.py) case "$authorization" in /*) ;; *) exit 94 ;; esac; printf "{}\\n" > "$output/signer-identity-probe-publication-record.json" ;; *fetch-client-chart-publication-records.py) case "$authorization" in /*) ;; *) exit 93 ;; esac; for name in gitops-chart-subject.json gitops-chart-sbom.json gitops-chart-grype.json gitops-chart-provenance-predicate.json gitops-chart-provenance-verified.json; do printf "{}\\n" > "$output/$name"; done ;; *) for component in vault-bootstrap vault-audit-relay gitops-oci-mirror; do printf "{}\\n" > "$output/$component-publication-record.json"; done ;; esac' > "$workspace/bin/python3"
chmod +x "$workspace/bin/gh" "$workspace/bin/python3"

invoke() {
  local source_root="${SOURCE_ROOT:-$workspace/legacy-source}"
  (cd "$source_root" && PATH="$workspace/bin:$PATH" FAKE_LOG="$log" GITHUB_ACTIONS="${TEST_GITHUB_ACTIONS:-false}" GITHUB_SHA="$sha" GITHUB_REPOSITORY=owner/repository RUNNER_TEMP="${TEST_RUNNER:-$workspace/runner}" bash "$helper")
}

: > "$log"
invoke
grep -F 'gh run list --workflow image-publish.yml --commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --branch main --status success --limit 1 --json databaseId --jq .[0].databaseId // empty' "$log" >/dev/null || fail 'candidate selection is not exact-main successful image publication only'
grep -F "python scripts/ci/fetch-release-publication-records.py --repository owner/repository --source-sha $sha --run-id 123 --output-dir $workspace/runner/release-publication-records" "$log" >/dev/null || fail 'retriever interface differs from its independent validation contract'
for component in vault-bootstrap vault-audit-relay gitops-oci-mirror; do
  [ -f "$workspace/runner/release-publication-records/$component-publication-record.json" ] || fail "retriever did not populate $component"
done

: > "$log"
PUBLICATION_RUN_ID=456 invoke
if grep -Fq 'gh run list' "$log"; then fail 'explicit publication run override performed a second candidate selection'; fi
grep -F -- "--run-id 456" "$log" >/dev/null || fail 'explicit publication run override was not forwarded'

: > "$log"
if PUBLICATION_RUN_ID=bad invoke >/dev/null 2>&1; then fail 'invalid explicit publication run id succeeded'; fi
if [ -s "$log" ]; then fail 'invalid explicit publication run id invoked a remote helper'; fi

: > "$log"
if FAKE_GH_MODE=empty invoke >/dev/null 2>&1; then fail 'missing candidate succeeded'; fi
grep -Fq 'gh run list' "$log" || fail 'missing candidate did not perform bounded selection'
if grep -Fq 'python ' "$log"; then fail 'missing candidate invoked the retriever'; fi

prysm_source="$workspace/prysm-source"
mkdir -p "$prysm_source/release"
printf '%s\n' '{}' > "$prysm_source/release/prysm-publication-authorization.json"
: > "$log"
SOURCE_ROOT="$prysm_source" invoke
grep -F -- "python scripts/ci/fetch-prysm-mtls-publication-record.py --authorization-path release/prysm-publication-authorization.json --source-root $prysm_source --output-dir $workspace/runner/prysm-publication-record" "$log" >/dev/null || fail 'authorized Prysm retrieval does not bind the checked-out source and dedicated output'
[ -f "$workspace/runner/prysm-publication-record/prysm-mtls-publication-record.json" ] || fail 'authorized Prysm retriever did not populate the dedicated frozen input path'

fence_source="$workspace/fence-source"
mkdir -p "$fence_source/release"
printf '%s\n' '{}' > "$fence_source/release/fence-publication-authorization.json"
: > "$log"
SOURCE_ROOT="$fence_source" invoke
grep -F -- "python scripts/ci/fetch-fence-publication-record.py --authorization-path $fence_source/release/fence-publication-authorization.json --source-root $fence_source --output-dir $workspace/runner/fence-publication-record" "$log" >/dev/null || fail 'authorized Fence retrieval does not bind the checked-out source and dedicated output'
[ -f "$workspace/runner/fence-publication-record/fence-release-verification.json" ] || fail 'authorized Fence retriever did not populate the dedicated frozen input path'

signer_source="$workspace/signer-source"; mkdir -p "$signer_source/release"; printf '%s\n' '{}' > "$signer_source/release/signer-probe-publication-authorization.json"
: > "$log"; SOURCE_ROOT="$signer_source" invoke
grep -F -- "python scripts/ci/fetch-signer-probe-publication-record.py --authorization-path $signer_source/release/signer-probe-publication-authorization.json --source-root $signer_source --output-dir $workspace/runner/signer-probe-publication-record" "$log" >/dev/null || fail 'authorized signer-probe retrieval does not use absolute authorization and dedicated output'
[ -f "$workspace/runner/signer-probe-publication-record/signer-identity-probe-publication-record.json" ] || fail 'authorized signer-probe retriever did not populate frozen input path'

chart_source="$workspace/chart-source"; mkdir -p "$chart_source/release"; printf '%s\n' '{}' > "$chart_source/release/client-chart-publication-authorization.json"
: > "$log"; SOURCE_ROOT="$chart_source" invoke
grep -F -- "python scripts/ci/fetch-client-chart-publication-records.py --authorization-path $chart_source/release/client-chart-publication-authorization.json --output-dir $workspace/runner/client-chart-publication-records" "$log" >/dev/null || fail 'authorized client chart retrieval does not use absolute authorization and dedicated output'
[ -f "$workspace/runner/client-chart-publication-records/gitops-chart-subject.json" ] || fail 'authorized client chart retriever did not populate frozen input path'

# Synthetic credentials only: ensure cross-repository scope does not escape
# the chart child and the caller's GITHUB_TOKEN remains unchanged.
cp "$workspace/bin/python3" "$workspace/bin/python3-base"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
  '[ "${GITHUB_TOKEN:-}" = original-github-token ] || exit 96' \
  'case "$1" in *fetch-client-chart-publication-records.py) [ "${GH_TOKEN:-}" = synthetic-reader-token ] || exit 97 ;; *) [ "${GH_TOKEN:-}" = original-gh-token ] || exit 98 ;; esac' \
  'exec "$(dirname "$0")/python3-base" "$@"' > "$workspace/bin/python3"
chmod +x "$workspace/bin/python3"
SOURCE_ROOT="$chart_source" TEST_RUNNER="$workspace/scoped-runner" TEST_GITHUB_ACTIONS=true GH_TOKEN=original-gh-token GITHUB_TOKEN=original-github-token GITOPS_EVIDENCE_TOKEN=synthetic-reader-token invoke
if SOURCE_ROOT="$chart_source" TEST_RUNNER="$workspace/no-reader-runner" TEST_GITHUB_ACTIONS=true GH_TOKEN=original-gh-token GITHUB_TOKEN=original-github-token GITOPS_EVIDENCE_TOKEN='' invoke > "$workspace/missing-reader.log" 2>&1; then
  fail 'Actions accepted a missing cross-repository reader token'
fi
grep -F 'GitOps evidence reader App token is required' "$workspace/missing-reader.log" >/dev/null || fail 'missing reader was not diagnosed'

printf 'PASS release publication record preparation is bounded and retrieval-owned.\n'

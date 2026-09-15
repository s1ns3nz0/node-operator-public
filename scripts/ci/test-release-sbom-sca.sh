#!/usr/bin/env bash
# Check objective: Verify pinned offline SBOM vulnerability scanning and its release evidence contract.
# shellcheck disable=SC2016 # Fixtures intentionally write literal shell variables for the fake Grype executable.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
installer="$script_dir/install-release-sca-tool.sh"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
mkdir -p "$temporary_directory/bin"

grep -Fq 'version="0.118.0"' "$installer"
grep -Eq 'archive_sha256="[0-9a-f]{64}"' "$installer"
grep -Fq 'actual_sha256="$(sha256sum' "$installer"

digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
printf '%s\n' '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"bundle","version":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},"components":[]}' > "$temporary_directory/sbom.json"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
  'test "$1" = "sbom:'"$temporary_directory"'/sbom.json"' \
  'test "$2" = "--output"; test "$3" = "json"; test "$4" = "--file"' \
  'cp "$GRYPE_FIXTURE" "$5"' > "$temporary_directory/bin/grype"
chmod +x "$temporary_directory/bin/grype"

printf '%s\n' '{"descriptor":{"name":"grype","version":"0.118.0","db":{"status":{"built":"2026-09-08T00:00:00Z","schemaVersion":"6.1.9","valid":true}}},"matches":[]}' > "$temporary_directory/clean.json"
GRYPE_FIXTURE="$temporary_directory/clean.json" PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/scan-release-sbom.sh" "$temporary_directory/sbom.json" "$temporary_directory/pass.json"
jq -e --arg digest "$digest" '.status == "passed" and .artifact_digest == $digest and .findings == {critical:0,high:0,medium:0,low:0,unknown:0} and (.sbom_sha256 | test("^[0-9a-f]{64}$"))' "$temporary_directory/pass.json" >/dev/null

printf '%s\n' '{"descriptor":{"name":"grype","version":"0.118.0","db":{"status":{"built":"2026-09-08T00:00:00Z","schemaVersion":"6.1.9","valid":true}}},"matches":[{"artifact":{"name":"DO_NOT_PERSIST_PACKAGE"},"vulnerability":{"id":"CVE-DO-NOT-PERSIST","severity":"High","description":"DO_NOT_PERSIST_DETAIL"}},{"vulnerability":{"severity":"Critical"}}]}' > "$temporary_directory/blocked.json"
GRYPE_FIXTURE="$temporary_directory/blocked.json" PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/scan-release-sbom.sh" "$temporary_directory/sbom.json" "$temporary_directory/fail.json"
jq -e '.status == "blocked" and .findings.high == 1 and .findings.critical == 1' "$temporary_directory/fail.json" >/dev/null
if grep -E -n -- 'DO_NOT_PERSIST_|CVE-DO-NOT-PERSIST' "$temporary_directory/fail.json" >/dev/null; then
  printf 'raw vulnerability details escaped into retained summary\n' >&2
  exit 1
fi

printf '%s\n' '{"descriptor":{"name":"grype","version":"0.118.0","db":{"status":{"built":"2026-09-08T00:00:00Z","schemaVersion":"6.1.9","valid":true}}},"matches":[{}]}' > "$temporary_directory/malformed.json"
if GRYPE_FIXTURE="$temporary_directory/malformed.json" PATH="$temporary_directory/bin:$PATH" \
  "$script_dir/scan-release-sbom.sh" "$temporary_directory/sbom.json" "$temporary_directory/malformed-summary.json" 2>/dev/null; then
  printf 'malformed vulnerability evidence was accepted\n' >&2
  exit 1
fi

printf '%s\n' 'PASS: exact release SBOM is analyzed, high/critical findings block, and retained evidence is compact.'

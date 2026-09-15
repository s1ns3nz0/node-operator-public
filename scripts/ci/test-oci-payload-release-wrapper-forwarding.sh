#!/usr/bin/env bash
# Check objective: Prove optional OCI payload manifests are fail-closed and forwarded read-only into release Docker wrappers.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
bin="$temporary_directory/bin"; mkdir -m 700 "$bin"
docker_log="$temporary_directory/docker.log"

cat > "$bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >> "$DOCKER_LOG"
cat >/dev/null || true
EOF
cat > "$bin/python3" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# Wrapper coverage only: the builder/index validation is exercised by its own suite.
exit 0
EOF
cat > "$bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%040d\n' 0 | tr '0' a
EOF
cat > "$bin/jq" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$APPROVED_ARTIFACT_DIGEST"
EOF
chmod 700 "$bin/docker" "$bin/python3" "$bin/git" "$bin/jq"

workspace="$temporary_directory/workspace"
mkdir -p "$workspace/scripts/release" "$workspace/.ci/gitops" "$temporary_directory/publication-records" "$temporary_directory/runner/release"
touch "$workspace/scripts/release/create-installer-artifact-index.py" "$workspace/.ci/gitops/approved-oci-artifacts.json"
for component in vault-bootstrap vault-audit-relay gitops-oci-mirror; do touch "$temporary_directory/publication-records/$component-publication-record.json"; done
printf 'bundle\n' > "$temporary_directory/runner/release/node-operator-release-bundle.tar"
digest="sha256:$(shasum -a 256 "$temporary_directory/runner/release/node-operator-release-bundle.tar" | awk '{print $1}')"
printf '{}\n' > "$temporary_directory/runner/release/sbom.cyclonedx.json"
manifest="$temporary_directory/oci-payload-manifest.json"; printf '{}\n' > "$manifest"

run_release_wrapper() {
  PATH="$bin:$PATH" DOCKER_LOG="$docker_log" GITHUB_WORKSPACE="$workspace" RUNNER_TEMP="$temporary_directory/runner" \
    PUBLICATION_RECORDS_DIR="$temporary_directory/publication-records" REGISTRY_TOKEN=token REGISTRY_USERNAME=user RELEASE_BUILD_IMAGE=fixture \
    APPROVED_ARTIFACT_DIGEST="$digest" OCI_PAYLOAD_MANIFEST="$1" \
    bash "$root/scripts/release/build-release-bundle.sh"
}

: > "$docker_log"
if run_release_wrapper relative-manifest >/dev/null 2>&1; then
  printf '%s\n' 'release wrapper accepted a relative OCI manifest' >&2; exit 1
fi
test ! -s "$docker_log"

# The deterministic test wrapper has no Docker boundary of its own. Verify its
# option parser and the single builder argument assembly together, so a future
# wrapper edit cannot silently drop the authenticated manifest between the
# reproducibility container and the deterministic double-build.
python3 - "$root/scripts/ci/test-build-release-bundle.sh" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
assert '--oci-payload-manifest) [ -n "${2:-}" ] || exit 64; oci_payload_manifest="$2"; shift 2' in source
assert 'arguments+=(--oci-payload-manifest "$oci_payload_manifest")' in source
assert '"$script_dir/build-release-bundle.sh" ${arguments[@]+"${arguments[@]}"} "$first"' in source
assert '"$script_dir/build-release-bundle.sh" ${arguments[@]+"${arguments[@]}"} "$temporary_directory/second"' in source
PY
run_release_wrapper "$manifest"
grep -F -x -- "${manifest}:/oci-payload-manifest.json:ro" "$docker_log" >/dev/null
grep -F -x -- '--oci-payload-manifest' "$docker_log" >/dev/null
grep -F -x -- '/oci-payload-manifest.json' "$docker_log" >/dev/null

: > "$docker_log"
link="$temporary_directory/oci-payload-link.json"; ln -s "$manifest" "$link"
if run_release_wrapper "$link" >/dev/null 2>&1; then
  printf '%s\n' 'release wrapper accepted a symlinked OCI manifest' >&2; exit 1
fi
test ! -s "$docker_log"

run_reproducibility_wrapper() {
  PATH="$bin:$PATH" DOCKER_LOG="$docker_log" GITHUB_WORKSPACE="$root" RUNNER_TEMP="$temporary_directory/repro" \
    REGISTRY_TOKEN=token REGISTRY_USERNAME=user RELEASE_BUILD_IMAGE=fixture OCI_PAYLOAD_MANIFEST="$1" \
    bash "$root/scripts/ci/workflows/check-reproducible-release.sh"
}
mkdir -p "$temporary_directory/repro/release-publication-records"
: > "$docker_log"
if run_reproducibility_wrapper relative-manifest >/dev/null 2>&1; then
  printf '%s\n' 'reproducibility wrapper accepted a relative OCI manifest' >&2; exit 1
fi
test ! -s "$docker_log"
run_reproducibility_wrapper "$manifest"
grep -F -x -- "${manifest}:/oci-payload-manifest.json:ro" "$docker_log" >/dev/null
grep -F -x -- '--oci-payload-manifest' "$docker_log" >/dev/null
grep -F -x -- '/oci-payload-manifest.json' "$docker_log" >/dev/null

: > "$docker_log"
if run_reproducibility_wrapper "$link" >/dev/null 2>&1; then
  printf '%s\n' 'reproducibility wrapper accepted a symlinked OCI manifest' >&2; exit 1
fi
test ! -s "$docker_log"

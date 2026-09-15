#!/usr/bin/env bash
# Purpose: Run the isolated Fence black-box security fixture and collect its report.
# Inputs: Docker, the local Fence source/fixture, and configured report paths.
# Outputs: Bounded DAST report artifacts for later validation.
# Side effects: Builds or runs only local test containers; no cloud target or production traffic.
# Check objective: Require isolated Fence black-box checks and a valid loopback-health ZAP report with no HIGH findings.
set -euo pipefail

[ "$#" -eq 1 ] || { printf 'usage: %s OUTPUT_DIRECTORY\n' "$0" >&2; exit 64; }
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
output="$1"; mkdir -p "$output"; output="$(cd "$output" && pwd -P)"
find "$output" -mindepth 1 -maxdepth 1 -print -quit | grep -q . && { printf 'DAST output directory must be empty\n' >&2; exit 64; }
command -v docker >/dev/null 2>&1; command -v jq >/dev/null 2>&1; command -v sha256sum >/dev/null 2>&1
# shellcheck disable=SC1091
source "$root/.ci/fence-security/tools.env"
revision="$(git -C "$root" rev-parse HEAD)"
fixture="fence-dast-$RANDOM-$$"; image="node-operator/fence-dast:$revision"
output_mode="$(stat -c '%a' "$output" 2>/dev/null || stat -f '%Lp' "$output")"
# Both unprivileged containers need the declared artifact mount, and nothing
# else. Restore the caller's directory mode during cleanup.
chmod 0777 "$output"
cleanup() { set +e; docker logs "$fixture" > "$output/fixture.log" 2>&1; docker rm -f "$fixture" >/dev/null 2>&1; chmod "$output_mode" "$output"; }
trap cleanup EXIT
docker build --platform linux/amd64 --file "$root/.ci/fence-security/Dockerfile" --tag "$image" "$root"
# The fixture has no external network and no Docker socket. ZAP shares only
# its network namespace, so it can reach the ephemeral loopback health target.
docker run -d --name "$fixture" --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=32m --mount "type=bind,src=$output,dst=/out" "$image" -target-file /out/target-url -scan-done /out/scan.done >/dev/null
for _ in $(seq 1 100); do [ -s "$output/target-url" ] && break; sleep 0.1; done
[ -s "$output/target-url" ] || { docker logs "$fixture" >&2; exit 1; }
target="$(tr -d '\r\n' < "$output/target-url")"
case "$target" in http://127.0.0.1:*) ;; *) printf 'fixture emitted non-loopback target\n' >&2; exit 1;; esac
set +e
docker run --rm --network "container:$fixture" --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges --pids-limit 512 -v "$output:/zap/wrk:rw" "$ZAP_IMAGE" zap-baseline.py -m 1 -t "$target" -J fence-health-zap.json -r fence-health-zap.html
zap_exit=$?
set -e
case "$zap_exit" in 0|1|2) ;; *) printf 'ZAP failed with exit %s\n' "$zap_exit" >&2; exit 1;; esac
test -s "$output/fence-health-zap.json"
jq -e --arg target "$target" -f "$root/.ci/fence-security/zap-report.jq" "$output/fence-health-zap.json" >/dev/null || { printf 'ZAP report incomplete, target-mismatched, unknown-risk, or HIGH\n' >&2; exit 1; }
touch "$output/scan.done"
docker wait "$fixture" > "$output/fixture.exit"
fixture_exit="$(tr -d '\r\n' < "$output/fixture.exit")"
docker logs "$fixture" > "$output/fixture.log" 2>&1
[ "$fixture_exit" = 0 ] || { cat "$output/fixture.log" >&2; exit 1; }
fixture_id_sha="$(docker image inspect --format '{{index .Id}}' "$image" | sha256sum | awk '{print $1}')"
zap_sha="$(sha256sum "$output/fence-health-zap.json" | awk '{print $1}')"
jq -n --arg source_sha "$revision" --arg fixture_image "$image" --arg fixture_image_id_sha256 "$fixture_id_sha" --arg zap_image "$ZAP_IMAGE" --arg zap_report_sha256 "$zap_sha" '{schema_version:1,source_sha:$source_sha,result:"PASS",fixture:{image:$fixture_image,image_id_sha256:$fixture_image_id_sha256,network:"none",synthetic_mtls_signer:true,fake_tls_kube_api:true},zap:{image:$zap_image,report_sha256:$zap_report_sha256,network:"container:fixture"}}' > "$output/result.json"

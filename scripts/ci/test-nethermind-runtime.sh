#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
for tool in docker grype jq diff; do command -v "$tool" >/dev/null || { printf 'missing command: %s\n' "$tool" >&2; exit 69; }; done
source_image=nethermind/nethermind@sha256:ec5f6c8158dbf82d4ddbd5500f895c930f52aa3b4c998148d9e1b452793d828e
candidate=node-operator-nethermind:runtime-10.0.11
scan_output="${NETHERMIND_SCAN_OUTPUT:-}"
if test -z "$scan_output"; then scan_output="$(mktemp /tmp/nethermind-runtime-grype.XXXXXX.json)"; fi
scratch="$(mktemp -d)"
source_container='' candidate_container=''
cleanup() {
  if [[ "$source_container" =~ ^[a-f0-9]{64}$ ]]; then docker rm -v "$source_container" >/dev/null; fi
  if [[ "$candidate_container" =~ ^[a-f0-9]{64}$ ]]; then docker rm -v "$candidate_container" >/dev/null; fi
  rm -rf -- "$scratch"
}
trap cleanup EXIT
docker buildx build --platform linux/amd64 --load --progress plain -f "$root/.ci/nethermind-runtime/Dockerfile" -t "$candidate" "$root"
image_id="$(docker image inspect --format '{{.Id}}' "$candidate")"
[[ "$image_id" =~ ^sha256:[a-f0-9]{64}$ ]] || exit 65
source_container="$(docker create --platform linux/amd64 "$source_image")"
candidate_container="$(docker create --platform linux/amd64 "$image_id")"
docker cp "$source_container:/nethermind" "$scratch/original"
docker cp "$candidate_container:/nethermind" "$scratch/candidate"
diff -r "$scratch/original" "$scratch/candidate" > "$scratch/application-diff.txt"
docker run --rm --platform linux/amd64 --network none --read-only --cap-drop ALL --security-opt no-new-privileges --entrypoint dotnet "$image_id" --list-runtimes > "$scratch/runtimes.txt"
grep -Fxq 'Microsoft.AspNetCore.App 10.0.11 [/usr/share/dotnet/shared/Microsoft.AspNetCore.App]' "$scratch/runtimes.txt"
grep -Fxq 'Microsoft.NETCore.App 10.0.11 [/usr/share/dotnet/shared/Microsoft.NETCore.App]' "$scratch/runtimes.txt"
test "$(wc -l < "$scratch/runtimes.txt" | tr -d ' ')" = 2
docker run --rm --platform linux/amd64 --network none --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp "$image_id" --version > "$scratch/version.txt"
grep -Eq '(^|[/ ])1\.39\.3([+ /-]|$)' "$scratch/version.txt"
GRYPE_CHECK_FOR_APP_UPDATE=false grype --config "$root/.ci/nethermind-runtime/grype.yaml" "docker:$image_id" --platform linux/amd64 -o json > "$scan_output"
jq -e '.descriptor.name=="grype" and .descriptor.db.status.valid==true and .descriptor.configuration["only-fixed"]==false and .descriptor.configuration["only-notfixed"]==false and .descriptor.configuration["show-suppressed"]==true and .descriptor.configuration.exclude==[] and (.matches|type)=="array" and all((.matches + [.ignoredMatches[]?.match])[]; (.vulnerability.severity|type)=="string" and (.vulnerability.severity|ascii_downcase|IN("critical","high")|not))' "$scan_output" >/dev/null
printf 'PASS: exact Nethermind application files preserved; 1.39.3 runs on .NET/ASP.NET10.0.11; final image Critical/High=0.\nImage: %s\nScan: %s\n' "$image_id" "$scan_output"

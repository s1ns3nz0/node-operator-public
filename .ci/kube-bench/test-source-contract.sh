#!/usr/bin/env bash
# Check objective: Validate the kube-bench candidate's pinned node-only contract.
set -euo pipefail
directory=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
dockerfile="$directory/Dockerfile"
lock="$directory/source-lock.json"
source_root=${KUBE_BENCH_SOURCE_ROOT:-/private/tmp/kube-bench-source.1ms4fg}
python3 - "$lock" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["candidate_status"] == "package-pinned-built-scanned-not-approved"
assert data["source"]["commit"] == "5c6c22d51b926020e7414e1f1e051851d1a2feff"
assert data["build"]["go_version_expected"] == "1.27.1"
packages = ["alpine-baselayout=3.7.2-r1", "alpine-baselayout-data=3.7.2-r1", "alpine-keys=2.6-r0", "alpine-release=3.24.1-r0", "apk-tools=3.0.8-r0", "busybox=1.37.0-r31", "busybox-binsh=1.37.0-r31", "ca-certificates-bundle=20260611-r0", "libapk=3.0.8-r0", "libcrypto3=3.5.8-r0", "libintl=1.0-r0", "libncursesw=6.6_p20260516-r0", "libproc2=4.0.6-r0", "libssl3=3.5.8-r0", "musl=1.2.6-r2", "musl-utils=1.2.6-r2", "ncurses-terminfo-base=6.6_p20260516-r0", "procps-ng=4.0.6-r0", "scanelf=1.3.9-r1", "skalibs-libs=2.15.0.0-r0", "ssl_client=1.37.0-r31", "utmps-libs=0.1.3.3-r0", "zlib=1.3.2-r0"]
assert data["runtime"]["apk_packages"] == packages
assert data["runtime"]["package_pinning_status"] == "frozen in recipe; rebuild and rescan required before approval"
assert data["profile"]["supported_invocation"] == ["run", "--targets", "node", "--benchmark", "eks-1.5.0", "--json"]
assert data["profile"]["base_config_yaml_sha256"] == "18d59f216f679c2732e409f3c4a9e377add285df32f97f1afa115bb52d6d20c6"
assert data["profile"]["controls"] == ["3.1.1", "3.1.2", "3.1.3", "3.1.4", "3.2.1", "3.2.2", "3.2.3", "3.2.4", "3.2.5", "3.2.6", "3.2.7", "3.2.8", "3.2.9"]
PY
python3 - "$dockerfile" "$lock" <<'PY'
import json, pathlib, re, sys
dockerfile, lock = map(pathlib.Path, sys.argv[1:])
text = dockerfile.read_text(encoding="utf-8")
assert not re.search(r"\bapk\b.*\bupgrade\b", text)
actual = re.findall(r"^      ([a-z0-9][a-z0-9_-]*=[^\s\\]+)", text, re.MULTILINE)
assert actual == json.loads(lock.read_text(encoding="utf-8"))["runtime"]["apk_packages"]
PY
grep -Fq 'GOMAXPROCS=2 GOMEMLIMIT=2GiB' "$dockerfile"
grep -Fq 'GOFLAGS=-mod=readonly' "$dockerfile"
grep -Fq 'test "$(go env GOVERSION)" = go1.27.1' "$dockerfile"
grep -Fq 'procps-ng=4.0.6-r0' "$dockerfile"
grep -Fq 'COPY --from=build /src/cfg/eks-1.5.0/node.yaml' "$dockerfile"
grep -Fq '"$3" != node' "$dockerfile"
python3 - "$dockerfile" "$source_root/cfg/eks-1.5.0/node.yaml" <<'PY'
import pathlib, re, subprocess, sys, tempfile
dockerfile, node = map(pathlib.Path, sys.argv[1:])
text = dockerfile.read_text(encoding="utf-8")
match = re.search(r"grep -Ec '([^']+)' cfg/eks-1[.]5[.]0/node[.]yaml", text)
assert match, "Dockerfile control-count pattern is missing"
pattern = match.group(1)
assert subprocess.run(["grep", "-Ec", pattern, node], check=True, capture_output=True, text=True).stdout.strip() == "13"
with tempfile.TemporaryDirectory() as temporary:
    changed = pathlib.Path(temporary) / "node.yaml"
    changed.write_text(node.read_text(encoding="utf-8").replace("      - id: 3.2.9", "      - id: 3.2.x", 1), encoding="utf-8")
    assert subprocess.run(["grep", "-Ec", pattern, changed], check=True, capture_output=True, text=True).stdout.strip() == "12"
PY
if grep -Eq '(^|[[:space:]])(bash|findutils|gcompat|jq|kubectl|openssl)([[:space:]]|$)' "$dockerfile"; then
  echo 'unexpected generic-profile runtime dependency' >&2
  exit 1
fi
printf '%s\n' 'PASS kube-bench source contract'

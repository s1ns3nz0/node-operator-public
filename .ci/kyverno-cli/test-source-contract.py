#!/usr/bin/env python3
"""Static candidate review only; it does not prove an upstream build compiles."""
import json
from pathlib import Path
root=Path(__file__).parent
docker=(root/'Dockerfile').read_text(); lock=json.loads((root/'source-lock.json').read_text())
assert lock['source']['commit'] in docker and lock['build']['go_image'] in docker
assert 'git fetch --depth=1 origin "$KYVERNO_COMMIT"' in docker
assert 'mkdir -p /artifacts/metadata' in docker and 'update-etcd /src > /artifacts/metadata/resolved-modules.json' in docker
assert 'COPY scripts/update-etcd.sh /usr/local/bin/update-etcd' in docker
helper=(root/'scripts/update-etcd.sh').read_text()
assert 'update-etcd /src > /artifacts/metadata/resolved-modules.json' in docker and 'cmp /tmp/go.mod.resolved go.mod' in docker
assert 'go get go.etcd.io/etcd/client/pkg/v3@v3.6.14' in helper and 'GOTOOLCHAIN=local GOFLAGS=-mod=readonly go list -m -json all' in helper
assert 'if [ "${1:-}" = --check-only ]' in helper and 'cd "$dir"' in helper
assert 'cp go.mod go.sum /buildinfo.txt /artifacts/metadata/' in docker and '/ko-app/kubectl-kyverno' in docker
assert 'make build-cli VERSION=v1.19.1' in docker and 'build-all' not in docker
assert 'go version -m cmd/cli/kubectl-kyverno/kubectl-kyverno' in docker
assert 'cp cmd/cli/kubectl-kyverno/kubectl-kyverno /artifacts/kubectl-kyverno' in docker

#!/usr/bin/env python3
# Check objective: Enforce the reviewed Vault Server and Agent gRPC patch source lock.
"""Offline source lock contract for the Vault Server and Agent gRPC patch."""
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / ".ci/vault-server-hardened/Dockerfile"
AGENT = ROOT / ".ci/vault-agent-hardened/Dockerfile"
LOCK = ROOT / ".ci/vault-agent-hardened/upstream.lock.json"

GRPC = "google.golang.org/grpc@v1.83.2"
GO_MOD_SHA256 = "0377034eba756738494bdc0c0f1ff0fef524846398a5f96aa977049331c5d6b2"
GO_SUM_SHA256 = "3f06f5ebaed07dc186567fa3a48f0d310e505b090c386ddad77a76ceba72d303"
GO_VERSION = "go version go1.26.6 linux/amd64"
GO_IMAGE = "golang@sha256:1a9c10cf505a9e6b1e96ea77ebdbfe79a0f10380181faf88bc3b51d7e4315fae"


def validate(server, agent, lock, server_verifier, agent_verifier):
    assert lock["dependency_overrides"]["google.golang.org/grpc"] == "v1.83.2"
    assert lock["dependency_overrides"]["resulting_go_mod_sha256"] == GO_MOD_SHA256
    assert lock["dependency_overrides"]["resulting_go_sum_sha256"] == GO_SUM_SHA256

    for name, dockerfile in (("server", server), ("agent", agent)):
        assert "v1.83.1" not in dockerfile, f"{name} retains an inactive old gRPC pin"
        assert dockerfile.count(GRPC) == 2, f"{name} must pin both edit and download"
        assert "go mod edit" in dockerfile and "-require=" + GRPC in dockerfile
        assert "go mod download" in dockerfile and GRPC in dockerfile
        assert dockerfile.count(GO_MOD_SHA256) == 1 and "go.mod" in dockerfile
        assert dockerfile.count(GO_SUM_SHA256) == 1 and "go.sum" in dockerfile
        assert GO_VERSION in dockerfile, f"{name} Go version pin changed"
        assert GO_IMAGE in dockerfile, f"{name} Go image pin changed"

    # Keep the existing readonly/test boundaries while changing only the module closure.
    assert "go test -mod=readonly -p 2 -count=1 -timeout=10m ./command" in server
    assert "go build -mod=readonly -p 2 -trimpath -buildvcs=false" in server
    assert "go test -count=1 ./command/agent/..." in agent
    assert "go build -buildvcs=false -mod=readonly -trimpath -tags=minimal" in agent
    assert "go list -mod=readonly -tags=minimal -deps ./agent-main.go" in agent

    # These are frozen historical candidate proofs, not outputs of this patch.
    assert "sha256:5463f9d70fe71b897b165e019dbc1e85aeaa8271130572bd060729dc124ff51f" in server_verifier
    assert "b53b65e6b7b8dc7945222418e6d0484757de722caae6c6fd1be98f040d6629e7" in server_verifier
    assert "sha256:33458e87c790b140717f2f4c688d31327292f67677ba004d32838deed8b8f30a" in agent_verifier
    assert "b53b65e6b7b8dc7945222418e6d0484757de722caae6c6fd1be98f040d6629e7" in agent_verifier


server = SERVER.read_text()
agent = AGENT.read_text()
lock = json.loads(LOCK.read_text())
server_verifier = (ROOT / "scripts/ci/verify-vault-server-candidate.sh").read_text()
agent_verifier = (ROOT / "scripts/ci/verify-vault-agent-candidate.sh").read_text()
validate(server, agent, lock, server_verifier, agent_verifier)

mutations = (
    (server.replace("v1.83.2", "v1.83.1"), agent, lock),
    (server.replace("-require=" + GRPC, ""), agent, lock),
    (server, agent.replace("-require=" + GRPC, ""), lock),
    (server.replace(GO_MOD_SHA256, "0" * 64), agent, lock),
    (server, agent, {**lock, "dependency_overrides": {**lock["dependency_overrides"], "resulting_go_sum_sha256": "0" * 64}}),
)
for bad_server, bad_agent, bad_lock in mutations:
    try:
        validate(bad_server, bad_agent, bad_lock, server_verifier, agent_verifier)
    except AssertionError:
        continue
    raise AssertionError("unsafe Vault gRPC patch mutation accepted")

print("PASS: Vault Server/Agent pin gRPC v1.83.2 with matching immutable module locks; five regressions rejected")

#!/usr/bin/env python3
"""Render temporary runtime diagnostic Pods only; never apply them."""

import argparse, importlib.util, json, pathlib, re

spec = importlib.util.spec_from_file_location(
    "network", pathlib.Path(__file__).with_name("render-signer-network-probe.py")
)
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)
RUN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,10}[a-z0-9])?$")


def hardened(p):
    p["metadata"]["labels"]["node-operator.io/purpose"] = "validator-runtime-probe"
    p["metadata"]["annotations"]["node-operator.io/control-semantics"] = (
        "Matches fence Service selectors; run only while client and fence replicas are zero. The never-ready gate is mandatory."
    )
    p["spec"]["readinessGates"] = [
        {"conditionType": "node-operator.io/never-ready-runtime-diagnostic"}
    ]
    return p


def tls(role, set, key, image, run):
    p = hardened(
        network.pod(
            f"runtime-tls-{role}-{run}",
            set,
            key,
            "validator-signing-fence",
            role,
            "diagnostic only",
            "Matches the public signer Service: client and Fence must be zero; never-ready gate required.",
        )
    )
    c = p["spec"]["containers"][0]
    c["image"] = image
    c["args"] = [
        "--mode",
        "tls",
        "--validator-set",
        set,
        "--expected-public-key",
        key,
        "--tls-case",
        {"prepositive": "positive", "postpositive": "positive"}.get(role, role),
    ]
    if role in ("no-client", "untrusted-client"):
        a = p["metadata"]["annotations"]
        for k in list(a):
            if "tls.crt" in k or "tls.key" in k:
                a.pop(k)
    return p


def vault(role, set, key, image, run, sa):
    p = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": f"runtime-vault-{role}-{run}",
            "namespace": "validator-operations",
            "labels": {
                "app.kubernetes.io/component": "validator-runtime-diagnostic",
                "node-operator.io/validator-set": set,
                "node-operator.io/vault-client": "true",
                "node-operator.io/purpose": "validator-runtime-probe",
            },
            "annotations": {
                "node-operator.io/scope": "Vault GET/LIST boundary diagnostic only; no write/delete"
            },
        },
        "spec": {
            "restartPolicy": "Never",
            "activeDeadlineSeconds": 120,
            "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "serviceAccountName": sa,
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 65532,
                "runAsGroup": 65532,
                "fsGroup": 65532,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "volumes": [
                {
                    "name": "vault-ca",
                    "secret": {
                        "secretName": "vault-agent-ca",
                        "items": [{"key": "ca.crt", "path": "ca.crt"}],
                    },
                },
                {
                    "name": "vault-auth",
                    "projected": {
                        "sources": [
                            {
                                "serviceAccountToken": {
                                    "audience": "vault",
                                    "expirationSeconds": 600,
                                    "path": "token",
                                }
                            }
                        ]
                    },
                },
            ],
            "containers": [
                {
                    "name": "runtime-probe",
                    "image": image,
                    "args": [
                        "--mode",
                        "vault-read",
                        "--validator-set",
                        set,
                        "--expected-public-key",
                        key,
                        "--workload",
                        role,
                    ],
                    "resources": {
                        "requests": {"cpu": "10m", "memory": "32Mi"},
                        "limits": {"cpu": "100m", "memory": "64Mi"},
                    },
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                        "capabilities": {"drop": ["ALL"]},
                    },
                    "volumeMounts": [
                        {
                            "name": "vault-ca",
                            "mountPath": "/vault/tls",
                            "readOnly": True,
                        },
                        {
                            "name": "vault-auth",
                            "mountPath": "/var/run/secrets/vault.hashicorp.com/serviceaccount",
                            "readOnly": True,
                        },
                    ],
                }
            ],
        },
    }
    return p


def engine_vault(role, validator_set, key, image, run):
    if role not in ("nethermind", "prysm"):
        raise ValueError("unsupported engine workload")
    service_account = "nethermind-execution" if role == "nethermind" else "prysm-beacon"
    p = vault(role, validator_set, key, image, run, service_account)
    p["metadata"]["namespace"] = "node-operator"
    p["metadata"]["labels"]["app.kubernetes.io/name"] = (
        "nethermind" if role == "nethermind" else "prysm-beacon"
    )
    p["metadata"]["annotations"]["node-operator.io/service-selector-warning"] = (
        "Service-selecting labels: require every matched Service publishNotReadyAddresses=false before create."
    )
    p["spec"]["readinessGates"] = [
        {"conditionType": "node-operator.io/never-ready-runtime-diagnostic"}
    ]
    p["spec"]["containers"][0]["readinessProbe"] = {
        "exec": {"command": ["/validator-runtime-probe", "--mode", "never-ready"]},
        "periodSeconds": 2,
        "timeoutSeconds": 1,
        "failureThreshold": 1,
    }
    p["spec"]["containers"][0]["securityContext"]["runAsNonRoot"] = True
    return p


def engine_auth(case, validator_set, key, image, run):
    if case not in ("prepositive", "postpositive", "missing", "wrong"):
        raise ValueError("unsupported engine authentication control")
    p = engine_vault("prysm", validator_set, key, image, run)
    p["metadata"]["name"] = f"runtime-engine-{case}-{run}"
    c = p["spec"]["containers"][0]
    scenario = "positive" if case in ("prepositive", "postpositive") else case
    c["args"] = ["--mode", "engine-auth", "--validator-set", validator_set, "--engine-case", scenario]
    p["spec"]["volumes"] = []
    c["volumeMounts"] = []
    a = p["metadata"]["annotations"]
    a["node-operator.io/scope"] = "Fixed read-only eth_chainId Engine JWT authentication control"
    if scenario == "positive":
        # Agent alone receives the projected identity. The application only
        # receives the memory-backed injected JWT, never a Kubernetes Secret.
        p["spec"]["volumes"] = [{"name": "vault-auth", "projected": {"sources": [{"serviceAccountToken": {
            "audience": "vault", "expirationSeconds": 600, "path": "token"
        }}]}}]
        a.update({
            "vault.hashicorp.com/agent-inject": "true",
            "vault.hashicorp.com/agent-pre-populate-only": "true",
            "vault.hashicorp.com/agent-service-account-token-volume-name": "vault-auth",
            "vault.hashicorp.com/secret-volume-path": "/engine",
            "vault.hashicorp.com/tls-secret": "vault-agent-ca",
            "vault.hashicorp.com/ca-cert": "/vault/tls/ca.crt",
            "vault.hashicorp.com/tls-server-name": "vault.vault.svc",
            "vault.hashicorp.com/role": "hoodi-engine-prysm",
            "vault.hashicorp.com/agent-inject-secret-engine.jwt": "node-operator-runtime/data/nodes/hoodi/engine-api-jwt",
            "vault.hashicorp.com/agent-inject-template-engine.jwt": '{{- with secret "node-operator-runtime/data/nodes/hoodi/engine-api-jwt" -}}{{ .Data.data.jwt }}{{- end }}',
        })
    return p


def engine_network_deny(validator_set, key, image, run):
    p = engine_auth("missing", validator_set, key, image, run)
    p["metadata"]["name"] = "runtime-engine-network-" + run
    del p["metadata"]["labels"]["app.kubernetes.io/name"]
    p["spec"]["containers"][0]["args"] = ["--mode", "engine-network-deny", "--validator-set", validator_set]
    return p


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--validator-set", required=True)
    a.add_argument("--expected-public-key", required=True)
    a.add_argument("--image", required=True)
    a.add_argument("--run-id", required=True)
    x = a.parse_args()
    key = x.expected_public_key.lower()
    if (
        not network.SET_RE.fullmatch(x.validator_set)
        or not network.KEY_RE.fullmatch(key)
        or not RUN.fullmatch(x.run_id)
        or not re.fullmatch(
            r"123456789012\.dkr\.ecr\.ap-northeast-2\.amazonaws\.com/node-operator-baseline-validator-signer-identity-probe@sha256:[0-9a-f]{64}",
            x.image,
        )
    ):
        a.error("invalid identity, image digest, or run id")
    items = [
        tls(r, x.validator_set, key, x.image, x.run_id)
        for r in (
            "prepositive",
            "bad-ca",
            "no-client",
            "untrusted-client",
            "postpositive",
        )
    ]
    items += [
        vault(r, x.validator_set, key, x.image, x.run_id, sa)
        for r, sa in (
            ("client", "validator-client"),
            ("db", "validator-slashing-db"),
            ("signer", "validator-remote-signer"),
        )
    ]
    print(
        json.dumps({"apiVersion": "v1", "kind": "List", "items": items}, sort_keys=True)
    )


if __name__ == "__main__":
    main()

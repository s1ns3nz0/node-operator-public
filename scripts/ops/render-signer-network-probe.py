#!/usr/bin/env python3
"""Render bounded, GET-only signer NetworkPolicy probe Pods; never apply them."""
import json
import os
import re
import sys

ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
IMAGE = ("123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/"
         "node-operator-baseline-validator-signer-identity-probe@sha256:"
         "11212189c98afaeb719eaaa8ac7d3c86179884c84986c97c9c1a35b6b4f4ec8f")
NAMESPACE = "validator-operations"
SET_RE = re.compile(r"^hoodi-[a-z0-9][a-z0-9-]{0,20}$")
KEY_RE = re.compile(r"^0x[0-9a-f]{96}$")


def usage() -> None:
    print("Usage: render-signer-network-probe.py --validator-set hoodi-X "
          "--expected-public-key 0x... --output /absolute/file.json", file=sys.stderr)
    raise SystemExit(64)


def pod(name: str, validator_set: str, public_key: str, component: str,
        role: str, expected: str, selector_warning: str) -> dict:
    labels = {
        "node-operator.io/vault-client": "true",
        "app.kubernetes.io/component": component,
        "node-operator.io/validator-set": validator_set,
        "node-operator.io/purpose": "signer-network-probe",
        "node-operator.io/probe-role": role,
    }
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": labels,
            "annotations": {
                "node-operator.io/expected-result": expected,
                "node-operator.io/control-semantics": "Both Pods issue only the fixed public-key GET through the direct signer Service; the fence-labelled Pod is the required positive control.",
                "node-operator.io/service-selector-warning": selector_warning,
                "vault.hashicorp.com/agent-inject": "true",
                "vault.hashicorp.com/secret-volume-path": "/tls",
                "vault.hashicorp.com/agent-pre-populate-only": "true",
                "vault.hashicorp.com/agent-service-account-token-volume-name": "vault-auth",
                "vault.hashicorp.com/tls-secret": "vault-agent-ca",
                "vault.hashicorp.com/ca-cert": "/vault/tls/ca.crt",
                "vault.hashicorp.com/tls-server-name": "vault.vault.svc",
                "vault.hashicorp.com/role": f"hoodi-{validator_set}-client-tls",
                "vault.hashicorp.com/agent-inject-secret-tls.crt": f"node-operator-runtime/data/validators/hoodi/{validator_set}/runtime/client-tls",
                "vault.hashicorp.com/agent-inject-template-tls.crt": "{{- with secret \"node-operator-runtime/data/validators/hoodi/" + validator_set + "/runtime/client-tls\" -}}{{ .Data.data.tls_crt_b64 | base64Decode }}{{- end }}",
                "vault.hashicorp.com/agent-inject-secret-tls.key": f"node-operator-runtime/data/validators/hoodi/{validator_set}/runtime/client-tls",
                "vault.hashicorp.com/agent-inject-template-tls.key": "{{- with secret \"node-operator-runtime/data/validators/hoodi/" + validator_set + "/runtime/client-tls\" -}}{{ .Data.data.tls_key_b64 | base64Decode }}{{- end }}",
                "vault.hashicorp.com/agent-inject-secret-ca.crt": f"node-operator-runtime/data/validators/hoodi/{validator_set}/runtime/client-tls",
                "vault.hashicorp.com/agent-inject-template-ca.crt": "{{- with secret \"node-operator-runtime/data/validators/hoodi/" + validator_set + "/runtime/client-tls\" -}}{{ .Data.data.ca_crt_b64 | base64Decode }}{{- end }}",
            },
        },
        "spec": {
            "restartPolicy": "Never",
            "activeDeadlineSeconds": 120,
            "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 65532,
                "runAsGroup": 65532,
                "fsGroup": 65532,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [{
                "name": "get-only-identity-probe",
                "image": IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "args": ["--validator-set", validator_set,
                         "--expected-public-key", public_key],
                "resources": {
                    "requests": {"cpu": "10m", "memory": "32Mi"},
                    "limits": {"cpu": "100m", "memory": "64Mi"},
                },
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
                "volumeMounts": [{"name": "vault-auth", "mountPath": "/var/run/secrets/vault.hashicorp.com/serviceaccount", "readOnly": True}],
            }],
            "serviceAccountName": "validator-client",
            "volumes": [{"name": "vault-auth", "projected": {"sources": [{"serviceAccountToken": {
                "audience": "vault", "expirationSeconds": 600, "path": "token",
            }}]}}],
        },
    }


def main(argv: list[str]) -> None:
    if len(argv) != 6 or argv[0] != "--validator-set" or argv[2] != "--expected-public-key" or argv[4] != "--output":
        usage()
    validator_set, public_key, output = argv[1], argv[3].lower(), argv[5]
    if not SET_RE.fullmatch(validator_set) or not KEY_RE.fullmatch(public_key) or not os.path.isabs(output):
        usage()
    parent = os.path.dirname(output)
    if not os.path.isdir(parent):
        print("output parent directory does not exist", file=sys.stderr)
        raise SystemExit(66)
    document = {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            pod(f"signer-probe-direct-{validator_set}", validator_set, public_key,
                "validator-client", "direct-bypass-negative",
                "must fail: the client-labelled source is not allowed to reach the direct signer",
                "This label can temporarily match a client Service selector; do not run while a real client Service is in use."),
            pod(f"signer-probe-control-{validator_set}", validator_set, public_key,
                "validator-signing-fence", "fence-positive-control",
                "must succeed with one matching public key before interpreting the negative result",
                "This label can temporarily match the public signer Service selector; do not run while that Service has consumers."),
        ],
    }
    temporary = output + ".tmp"
    try:
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(document, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
        os.replace(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == "__main__":
    main(sys.argv[1:])

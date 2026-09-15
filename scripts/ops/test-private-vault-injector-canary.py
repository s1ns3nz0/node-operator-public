#!/usr/bin/env python3
"""One-shot, dry-run-only admission canary for the frozen Vault Injector."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

ACCOUNT = "123456789012"
CLUSTER = "node-operator"
GLOBAL_WEBHOOK = "vault-agent-injector-cfg"
GLOBAL_WEBHOOK_UID = "3741b870-8a89-465f-bab2-95c955636c35"
INJECTOR = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-vault-runtime-injector@sha256:2937fbc5d368430d089b9b94f82b44baab71524d166358bb8ea48f7b395152d4"
AGENT = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-vault-runtime-agent@sha256:33458e87c790b140717f2f4c688d31327292f67677ba004d32838deed8b8f30a"
APP = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-node-runtime-upcheck-python@sha256:fb305627ba331d70f8cc82509a4fae4be858422fd257e170543fbbefcefb9588"


def fail(message, code=1):
    print(message, file=sys.stderr)
    raise SystemExit(code)


def command(*args, input_text=None, check=True):
    result = subprocess.run(args, input=input_text, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({args[0]}); sensitive command output withheld")
    return result.stdout


def kubectl(*args, input_object=None, check=True):
    payload = None if input_object is None else json.dumps(input_object)
    return command("kubectl", *args, input_text=payload, check=check)


def kubectl_json(*args, input_object=None):
    return json.loads(kubectl(*args, input_object=input_object))


def webhook_hash(webhook):
    return hashlib.sha256(json.dumps(webhook["webhooks"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require_annotation_denial(result, webhook_name):
    if result.returncode == 0 or webhook_name not in result.stderr or "denied the request" not in result.stderr:
        fail("malformed annotation did not receive an explicit denial from the canary webhook")


def expect_global_webhook():
    webhook = kubectl_json("get", "mutatingwebhookconfiguration", GLOBAL_WEBHOOK, "-o", "json")
    if webhook.get("metadata", {}).get("uid") != GLOBAL_WEBHOOK_UID:
        fail("global injector webhook UID differs; refusing canary")
    if len(webhook.get("webhooks", [])) != 1:
        fail("global injector webhook membership differs; refusing canary")
    expressions = webhook.get("webhooks", [{}])[0].get("objectSelector", {}).get("matchExpressions", [])
    required = {"key": "app.kubernetes.io/name", "operator": "NotIn", "values": ["vault-agent-injector"]}
    if required not in expressions:
        fail("global injector webhook does not exclude the canary label")
    if any(item.get("failurePolicy") != "Ignore" for item in webhook.get("webhooks", [])):
        fail("global injector webhook failure policy differs; refusing canary")
    return webhook_hash(webhook)


def main():
    usage = "Usage: test-private-vault-injector-canary.py --execute"
    if sys.argv[1:] == ["--help"]:
        print(usage)
        return
    if sys.argv[1:] != ["--execute"]:
        fail(usage, 64)
    script = str(Path(__file__).resolve())
    root = str(Path(__file__).resolve().parent)
    if os.environ.get("PRIVATE_EKS_SESSION") != "1":
        tunnel_env = dict(os.environ, EKS_CLUSTER_NAME=CLUSTER, AWS_REGION="ap-northeast-2")
        os.execvpe(f"{root}/with-private-eks.sh", [f"{root}/with-private-eks.sh", "--", "env",
                   "PRIVATE_EKS_SESSION=1", "python3", script, "--execute"], tunnel_env)
    if os.environ.get("EKS_CLUSTER_NAME", CLUSTER) != CLUSTER:
        fail("only the node-operator EKS cluster is permitted")
    for binary in ("aws", "kubectl", "openssl"):
        if not shutil_which(binary):
            fail(f"missing command: {binary}", 69)
    account = command("aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text").strip()
    if account != ACCOUNT:
        fail("AWS account does not match the reviewed canary account")
    arn = command("aws", "eks", "describe-cluster", "--name", CLUSTER, "--region", "ap-northeast-2",
                  "--query", "cluster.arn", "--output", "text").strip()
    if arn != f"arn:aws:eks:ap-northeast-2:{ACCOUNT}:cluster/{CLUSTER}":
        fail("EKS cluster identity does not match the reviewed canary cluster")
    if kubectl("config", "current-context").strip() != arn:
        fail("active Kubernetes context is not the reviewed EKS cluster")
    before_hash = expect_global_webhook()

    suffix = uuid.uuid4().hex[:8]
    namespace = f"hoodi-injector-canary-{suffix}"
    name = f"vault-injector-canary-{suffix}"
    label = {"node-operator.io/injector-canary": name}
    created = []

    def create(manifest, path):
        result = kubectl_json("create", "-f", "-", "-o", "json", input_object=manifest)
        uid = result.get("metadata", {}).get("uid")
        if not uid:
            fail("create response lacked UID")
        created.append((path, uid))
        return result

    def cleanup():
        failures = []
        for path, uid in reversed(created):
            options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}}
            result = subprocess.run(["kubectl", "delete", "--raw", path, "-f", "-"], input=json.dumps(options), text=True, capture_output=True)
            if result.returncode:
                failures.append(path)
        if failures:
            raise RuntimeError("canary cleanup could not confirm all UID-bound deletions")
        if created:
            kubectl("wait", "--for=delete", f"namespace/{namespace}", "--timeout=120s")

    try:
        create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace, "labels": {
            **label, "pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "v1.35"}}},
               f"/api/v1/namespaces/{namespace}")
        create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name, "namespace": namespace, "labels": label},
                "automountServiceAccountToken": True}, f"/api/v1/namespaces/{namespace}/serviceaccounts/{name}")
        create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": name, "labels": label},
                "rules": [{"apiGroups": ["admissionregistration.k8s.io"], "resources": ["mutatingwebhookconfigurations"], "verbs": ["get", "list", "watch"]}]},
               f"/apis/rbac.authorization.k8s.io/v1/clusterroles/{name}")
        create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": name, "labels": label},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": name},
                "subjects": [{"kind": "ServiceAccount", "name": name, "namespace": namespace}]},
               f"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{name}")
        with tempfile.TemporaryDirectory(prefix="hoodi-injector-canary-") as temporary:
            temp = Path(temporary)
            cert, key = temp / "tls.crt", temp / "tls.key"
            service = f"{name}.{namespace}.svc"
            command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=vault-injector-canary",
                    "-addext", f"subjectAltName=DNS:{service}", "-keyout", str(key), "-out", str(cert))
            key.chmod(0o600)
            secret = kubectl_json("-n", namespace, "create", "secret", "generic", name,
                                  f"--from-file=tls.crt={cert}", f"--from-file=tls.key={key}", f"--from-file=ca.crt={cert}", "-o", "json")
            created.append((f"/api/v1/namespaces/{namespace}/secrets/{name}", secret["metadata"]["uid"]))
            deployment = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name, "namespace": namespace, "labels": label},
                          "spec": {"replicas": 1, "selector": {"matchLabels": label}, "template": {"metadata": {"labels": {**label, "app.kubernetes.io/name": "vault-agent-injector"}}, "spec": {
                              "serviceAccountName": name, "automountServiceAccountToken": True, "nodeSelector": {"kubernetes.io/arch": "amd64"},
                              "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000, "seccompProfile": {"type": "RuntimeDefault"}},
                              "containers": [{"name": "injector", "image": INJECTOR, "command": ["/bin/vault-k8s", "agent-inject"],
                                  "args": ["-listen=0.0.0.0:8080", "-tls-cert-file=/tls/tls.crt", "-tls-key-file=/tls/tls.key", "-tls-ca-cert-file=/tls/ca.crt", "-vault-address=https://vault-active.vault.svc:8200", f"-vault-image={AGENT}"],
                                  "ports": [{"containerPort": 8080, "name": "https"}], "volumeMounts": [{"name": "tls", "mountPath": "/tls", "readOnly": True}],
                                  "readinessProbe": {"httpGet": {"path": "/health/ready", "port": 8080, "scheme": "HTTPS"}, "periodSeconds": 2, "timeoutSeconds": 3},
                                  "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "runAsNonRoot": True, "capabilities": {"drop": ["ALL"]}},
                                  "resources": {"requests": {"cpu": "25m", "memory": "64Mi"}, "limits": {"cpu": "100m", "memory": "128Mi"}}}],
                              "volumes": [{"name": "tls", "secret": {"secretName": name}}]}}}}
            create(deployment, f"/apis/apps/v1/namespaces/{namespace}/deployments/{name}")
            create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": namespace, "labels": label},
                    "spec": {"selector": label, "ports": [{"name": "https", "port": 443, "targetPort": 8080}]}},
                   f"/api/v1/namespaces/{namespace}/services/{name}")
            kubectl("-n", namespace, "rollout", "status", f"deployment/{name}", "--timeout=120s")
            ca = base64.b64encode(cert.read_bytes()).decode()
            webhook = {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "MutatingWebhookConfiguration", "metadata": {"name": name, "labels": label},
                       "webhooks": [{"name": f"{name}.node-operator.invalid", "admissionReviewVersions": ["v1"], "sideEffects": "None", "failurePolicy": "Fail", "matchPolicy": "Exact",
                           "namespaceSelector": {"matchLabels": {**label, "kubernetes.io/metadata.name": namespace}}, "objectSelector": {"matchLabels": {**label, "node-operator.io/admission-test": "true"}}, "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"], "scope": "Namespaced"}],
                           "clientConfig": {"service": {"namespace": namespace, "name": name, "path": "/mutate", "port": 443}, "caBundle": ca}}]}
            create(webhook, f"/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations/{name}")
            pod_base = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": f"pod-{suffix}", "namespace": namespace, "labels": {**label, "app.kubernetes.io/name": "vault-agent-injector", "node-operator.io/admission-test": "true"}},
                        "spec": {"serviceAccountName": name, "automountServiceAccountToken": True,
                            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "seccompProfile": {"type": "RuntimeDefault"}},
                            "containers": [{"name": "app", "image": APP, "command": ["true"], "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}}]}}
            unannotated = kubectl_json("create", "--dry-run=server", "-f", "-", "-o", "json", input_object=pod_base)
            if any(c["name"].startswith("vault-agent") for c in unannotated["spec"].get("containers", []) + unannotated["spec"].get("initContainers", [])):
                fail("unannotated canary Pod was mutated")
            positive = json.loads(json.dumps(pod_base))
            positive["metadata"]["annotations"] = {"vault.hashicorp.com/agent-inject": "true", "vault.hashicorp.com/role": "synthetic-role", "vault.hashicorp.com/agent-inject-secret-test": "secret/data/synthetic"}
            mutated = kubectl_json("create", "--dry-run=server", "-f", "-", "-o", "json", input_object=positive)
            agents = [c for c in mutated["spec"].get("containers", []) + mutated["spec"].get("initContainers", []) if c.get("name") in {"vault-agent", "vault-agent-init"}]
            if {c["name"] for c in agents} != {"vault-agent", "vault-agent-init"}:
                fail("positive canary did not inject both Agent containers")
            for agent in agents:
                if agent.get("image") != AGENT or not agent.get("securityContext", {}).get("runAsNonRoot"):
                    fail("injected Agent image or non-root setting differs")
                config = next((env["value"] for env in agent.get("env", []) if env.get("name") == "VAULT_CONFIG"), None)
                if not config:
                    fail("injected Agent config is missing")
                parsed = json.loads(base64.b64decode(config))
                if parsed["vault"].get("tls_skip_verify", False) or parsed["auto_auth"]["method"]["config"].get("role") != "synthetic-role" or parsed["auto_auth"]["method"].get("type") != "kubernetes":
                    fail("injected Agent config did not retain TLS verification and role")
            if not any(any("serviceAccountToken" in source for source in volume.get("projected", {}).get("sources", [])) for volume in mutated["spec"].get("volumes", [])):
                fail("mutated canary lacks the default projected service-account token")
            negative = json.loads(json.dumps(positive)); negative["metadata"]["annotations"]["vault.hashicorp.com/agent-inject"] = "invalid-boolean"
            rejected = subprocess.run(["kubectl", "create", "--dry-run=server", "-f", "-", "-o", "json"], input=json.dumps(negative), text=True, capture_output=True)
            require_annotation_denial(rejected, f"{name}.node-operator.invalid")
        after_hash = expect_global_webhook()
        if after_hash != before_hash:
            fail("global injector webhook changed during canary")
    finally:
        cleanup()
    if expect_global_webhook() != before_hash:
        fail("global injector webhook changed during cleanup")
    print(json.dumps({"namespace": namespace, "injector": INJECTOR, "agent": AGENT, "dry_run_admission_only": True,
                      "global_webhook_unchanged": True, "cleanup_confirmed": True}))


def shutil_which(binary):
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / binary
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


if __name__ == "__main__":
    main()

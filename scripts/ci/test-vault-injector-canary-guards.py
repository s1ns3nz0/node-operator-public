#!/usr/bin/env python3
# Check objective: Verify Vault injector canary execution and rejection guards without a cluster.
"""No-cluster tests for live canary execution and rejection guards."""
import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.dont_write_bytecode = True
path = Path(__file__).resolve().parents[1] / "ops/test-private-vault-injector-canary.py"
spec = importlib.util.spec_from_file_location("canary", path)
canary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canary)


def refused(callback, code=1):
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            callback()
        except SystemExit as error:
            assert error.code == code
        else:
            raise AssertionError("unsafe input accepted")


with patch.object(canary, "command", side_effect=AssertionError("external command invoked")), patch.object(canary.os, "execvpe", side_effect=AssertionError("tunnel invoked")):
    for arguments in ([], ["--execute", "unexpected"], ["--dry-run"]):
        with patch.object(sys, "argv", [str(path)] + arguments):
            refused(canary.main, 64)
    with patch.object(sys, "argv", [str(path), "--help"]), contextlib.redirect_stdout(io.StringIO()):
        canary.main()

name = "synthetic.node-operator.invalid"
for status, error in ((0, ""), (1, "timeout"), (1, f'failed calling webhook "{name}"'), (1, 'other webhook denied the request')):
    result = subprocess.CompletedProcess([], status, "", error)
    refused(lambda: canary.require_annotation_denial(result, name))
canary.require_annotation_denial(subprocess.CompletedProcess([], 1, "", f'admission webhook "{name}" denied the request: invalid syntax'), name)

actual_arn = "arn:aws:eks:ap-northeast-2:123456789012:cluster/node-operator"
def identity_command(*args, **kwargs):
    if args[:3] == ("aws", "sts", "get-caller-identity"): return "123456789012\n"
    if args[:3] == ("aws", "eks", "describe-cluster"): return actual_arn + "\n"
    if args == ("kubectl", "config", "current-context"): return actual_arn + "\n"
    raise AssertionError("unexpected external operation")

with patch.dict(canary.os.environ, {"PRIVATE_EKS_SESSION": "1", "EKS_CLUSTER_NAME": "node-operator"}), \
     patch.object(sys, "argv", [str(path), "--execute"]), \
     patch.object(canary, "shutil_which", return_value="mock"), \
     patch.object(canary, "command", side_effect=identity_command), \
     patch.object(canary, "expect_global_webhook", side_effect=RuntimeError("identity passed without writes")):
    try:
        canary.main()
    except RuntimeError as error:
        assert str(error) == "identity passed without writes"
    else:
        raise AssertionError("missing identity guard stop")

# Real OpenSSL: service FQDN can exceed the X.509 CN length limit. Identity is
# in SAN; the short display CN must not prevent synthetic certificate creation.
with tempfile.TemporaryDirectory(prefix="injector-cert-guard-") as directory:
    certificate = str(Path(directory) / "cert.pem")
    key = str(Path(directory) / "key.pem")
    service = "vault-injector-canary-12345678.hoodi-injector-canary-12345678.svc"
    canary.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                   "-subj", "/CN=vault-injector-canary", "-addext", f"subjectAltName=DNS:{service}",
                   "-keyout", key, "-out", certificate)
    san = canary.command("openssl", "x509", "-in", certificate, "-noout", "-ext", "subjectAltName")
    assert service in san

baseline = {"metadata": {"uid": canary.GLOBAL_WEBHOOK_UID}, "webhooks": [{"failurePolicy": "Ignore", "objectSelector": {
    "matchExpressions": [{"key": "app.kubernetes.io/name", "operator": "NotIn", "values": ["vault-agent-injector"]}]}}]}
with patch.object(canary, "kubectl_json", return_value=baseline):
    assert canary.expect_global_webhook() == canary.webhook_hash(baseline)
for mutation in ("uid", "extra", "selector", "policy"):
    changed = copy.deepcopy(baseline)
    if mutation == "uid": changed["metadata"]["uid"] = "other"
    if mutation == "extra": changed["webhooks"].append(copy.deepcopy(changed["webhooks"][0]))
    if mutation == "selector": changed["webhooks"][0]["objectSelector"] = {}
    if mutation == "policy": changed["webhooks"][0]["failurePolicy"] = "Fail"
    with patch.object(canary, "kubectl_json", return_value=changed):
        refused(canary.expect_global_webhook)
print("PASS: no-write CLI guard, explicit admission denial and global webhook drift guards (mocked, not live canary)")

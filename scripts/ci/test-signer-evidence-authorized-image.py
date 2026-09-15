#!/usr/bin/env python3
# Check objective: Validate the signer-evidence probe image authorization boundary.
"""Offline integration checks for the signer-evidence probe image boundary."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ops/collect-hoodi-signer-public-key-evidence.sh"
IMAGE = "222222222222.dkr.ecr.ap-northeast-2.amazonaws.com/target-node-baseline-validator-signer-identity-probe@sha256:" + "f" * 64
KEY = "0x" + "a" * 96


class SignerEvidenceAuthorizedImageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"; self.bin.mkdir()
        self.log = self.root / "kubectl.log"
        self.manifest = self.root / "manifest.json"
        (self.bin / "kubectl").write_text("""#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$FAKE_KUBECTL_LOG"
for ((i=1; i <= $#; i++)); do
  if [ "${!i}" = -f ]; then j=$((i+1)); [ "${!j}" = - ] || cp "${!j}" "$FAKE_MANIFEST"; fi
done
case " $* " in
  *' get deployment '*'-signing-fence '*) printf '{"spec":{"replicas":%s}}\\n' "${FAKE_FENCE_REPLICAS:-0}" ;;
  *' get deployment '*) printf '%s\\n' '{"spec":{"replicas":1},"status":{"readyReplicas":1}}' ;;
  *' get statefulset '*) printf '{"spec":{"replicas":%s}}\\n' "${FAKE_CLIENT_REPLICAS:-0}" ;;
  *' create -f '*' -o json '*) printf '%s\\n' '{"metadata":{"uid":"test-uid"}}' ;;
  *' get pod '* ) if [ "${FAKE_PENDING:-0}" = 1 ]; then printf '%s\\n' '{"status":{"phase":"Running"}}'; else printf '%s\\n' '{"status":{"phase":"Succeeded","initContainerStatuses":[{"name":"vault-agent-init","state":{"terminated":{"exitCode":0}}}],"containerStatuses":[{"name":"get-only-identity-probe","state":{"terminated":{"exitCode":0}}}]}}'; fi ;;
  *' logs '*) printf '%s\\n' '{"tls_verified":true,"public_key_match":true,"public_key_count":1,"validator_public_key":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' ;;
  *' delete --raw '*) cat > "$FAKE_DELETE_BODY"; [ "${FAKE_DELETE_FAIL:-0}" = 0 ] || exit 1 ;;
  *) : ;;
esac
""")
        (self.bin / "kubectl").chmod(0o755)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(self, *arguments: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ, PRIVATE_EKS_SESSION="1", PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                           FAKE_KUBECTL_LOG=str(self.log), FAKE_MANIFEST=str(self.manifest),
                           FAKE_DELETE_BODY=str(self.root / "delete.json"))
        if extra_env:
            environment.update(extra_env)
        return subprocess.run([str(SCRIPT), "--validator-set", "hoodi-test", "--validator-public-key", KEY,
                               *arguments, "--output-dir", str(self.root / "evidence")],
                              text=True, capture_output=True, env=environment, timeout=20)

    def test_selected_private_destination_is_the_created_pod_image_and_zero_signing_guards_remain(self) -> None:
        result = self.invoke("--probe-image", IMAGE)
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads(self.manifest.read_text())
        self.assertEqual(manifest["spec"]["containers"][0]["image"], IMAGE)
        self.assertIn("GET-only public-key identity probe; no signing request", manifest["metadata"]["annotations"]["node-operator.io/scope"])
        commands = self.log.read_text()
        self.assertIn("get statefulset validator-hoodi-test-client", commands)
        self.assertIn("get deployment validator-hoodi-test-signing-fence", commands)
        self.assertLess(commands.index("get statefulset"), commands.index("create --dry-run=server"))
        self.assertFalse(any("sign" in item for item in manifest["spec"]["containers"][0]["args"]))
        self.assertEqual(json.loads((self.root / "delete.json").read_text())["preconditions"]["uid"], "test-uid")

    def test_missing_or_invalid_image_rejects_before_kubernetes_access(self) -> None:
        for arguments in ((), ("--probe-image", "docker.io/untrusted:latest")):
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.log.exists())

    def test_nonzero_client_or_fence_guard_rejects_before_pod_creation(self) -> None:
        for environment in ({"FAKE_CLIENT_REPLICAS": "1"}, {"FAKE_FENCE_REPLICAS": "1"}):
            with self.subTest(environment=environment):
                result = self.invoke("--probe-image", IMAGE, extra_env=environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.manifest.exists())
                self.assertNotIn(" create ", self.log.read_text())
                self.log.unlink()

    def test_cleanup_failure_is_nonzero_and_sanitized(self) -> None:
        result = self.invoke("--probe-image", IMAGE, extra_env={"FAKE_DELETE_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signer public-key probe cleanup failed", result.stderr)
        self.assertNotIn("PASS: signer public key", result.stdout)

    def test_interruption_never_reports_success(self) -> None:
        environment = dict(os.environ, PRIVATE_EKS_SESSION="1", PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                           FAKE_KUBECTL_LOG=str(self.log), FAKE_MANIFEST=str(self.manifest),
                           FAKE_DELETE_BODY=str(self.root / "delete.json"), FAKE_PENDING="1")
        process = subprocess.Popen([str(SCRIPT), "--validator-set", "hoodi-test", "--validator-public-key", KEY,
                                    "--probe-image", IMAGE, "--output-dir", str(self.root / "evidence")],
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        try:
            __import__("time").sleep(0.2)
            process.send_signal(__import__("signal").SIGINT)
            stdout, stderr = process.communicate(timeout=10)
        finally:
            if process.poll() is None:
                process.kill(); process.wait()
        self.assertNotEqual(process.returncode, 0)
        self.assertNotIn("PASS: signer public key", stdout + stderr)

    def test_wrapper_command_contract_keeps_the_selected_image_argument(self) -> None:
        source = SCRIPT.read_text()
        self.assertIn('PRIVATE_EKS_SESSION=1 "$0" --validator-set "$validator_set" --validator-public-key "$public_key" --probe-image "$probe_image" --output-dir "$output_dir"', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)

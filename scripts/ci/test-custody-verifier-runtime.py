#!/usr/bin/env python3
# Check objective: Validate custody-verifier runtime boundaries and dependencies.
"""Runtime boundary tests, with an explicit opt-in for real dependency installation."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/release/custody_verifier_runtime.py"
KEY = "0x" + "a" * 96
CANONICAL_CLONE_SOURCE = "https://github.com/ethstaker/ethstaker-deposit-cli.git"
PINNED_SOURCE_VALUE = os.environ.get("CUSTODY_VERIFIER_UPSTREAM_ROOT")
PINNED_SOURCE = Path(PINNED_SOURCE_VALUE) if PINNED_SOURCE_VALUE else Path(os.devnull)

spec = importlib.util.spec_from_file_location("runtime", MODULE_PATH)
runtime = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(runtime)


class CustodyVerifierRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.work = self.base / "work"; self.work.mkdir(mode=0o700)
        self.bundle = self.base / "bundle"; (self.bundle / "source/scripts/ops").mkdir(parents=True)
        (self.bundle / "source/.ci/custody-verifier").mkdir(parents=True)
        self.verifier = self.bundle / "source/scripts/ops/verify-custody-keystore-secret.py"
        self.lock = self.bundle / "source/.ci/custody-verifier/source-lock.json"
        self.verifier.write_text("# fixture verifier\n")
        self.lock.write_text('{"fixture":"lock"}\n')
        self._manifest()

    def tearDown(self):
        self.temp.cleanup()

    def _manifest(self):
        entries = []
        for relative in ("source/scripts/ops/verify-custody-keystore-secret.py", "source/.ci/custody-verifier/source-lock.json"):
            path = self.bundle / relative
            entries.append({"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size})
        (self.bundle / "bundle-manifest.json").write_text(json.dumps({"source_revision": "b" * 40, "entries": entries}, sort_keys=True))

    def _run(self, command, **kwargs):
        args = list(command)
        self.calls.append(args)
        if args[:2] == ["git", "clone"]:
            Path(args[-1]).mkdir()
        elif args[:4] == ["git", "-C", str(self.upstream), "rev-parse"]:
            return subprocess.CompletedProcess(args, 0, f"{runtime.COMMIT}\n{'c' * 40}\n", "")
        elif args[1:5] == ["-I", "-m", "venv", "--copies"]:
            venv = Path(args[5])
            python = venv / "bin/python"
            python.parent.mkdir(parents=True)
            python.write_text("synthetic python\n")
            python.chmod(0o700)
            site = venv / "lib/python3.14/site-packages"; site.mkdir(parents=True)
            (site / "fixture.py").write_text("fixture\n")
        return subprocess.CompletedProcess(args, 0, "", "")

    def test_prepare_creates_bound_receipt_and_verify_is_network_free(self):
        self.calls = []
        self.upstream = self.work / runtime.RUNTIME / "upstream"
        self.python = self.work / runtime.RUNTIME / "venv/bin/python"
        with mock.patch.object(runtime, "_verify_source"), mock.patch.object(runtime.subprocess, "run", side_effect=self._run):
            prepared = runtime.prepare(self.work, self.bundle, KEY)
            self.assertEqual(prepared["python"], str(self.python))
            self.assertEqual(prepared["upstream_root"], str(self.upstream))
            self.assertTrue((self.work / runtime.RUNTIME / "receipt.json").is_file())
            clones = [call for call in self.calls if call[:2] == ["git", "clone"]]
            self.assertEqual(runtime.UPSTREAM, CANONICAL_CLONE_SOURCE)
            self.assertEqual(len(clones), 1)
            self.assertEqual(clones[0][-2], CANONICAL_CLONE_SOURCE)
            self.assertTrue(any(call[:5] == [str(self.python), "-I", "-m", "pip", "install"] and "--require-hashes" in call for call in self.calls))
            before = list(self.calls)
            verified = runtime._verify(self.work, self.bundle, KEY)
            (self.work / runtime.RUNTIME / "venv/lib/python3.14/site-packages/fixture.py").write_text("tampered\n")
            with self.assertRaises(runtime.RuntimeError):
                runtime._verify(self.work, self.bundle, KEY)
        self.assertEqual(verified, prepared)
        after = self.calls[len(before):]
        self.assertFalse(any(call[:2] == ["git", "clone"] or "pip" in call for call in after))

    def test_partial_runtime_is_reused_without_deletion_and_receipt_key_mismatch_fails(self):
        partial = self.work / runtime.RUNTIME / "upstream"
        partial.mkdir(parents=True)
        marker = partial / "partial-state"; marker.write_text("retain")
        self.calls = []
        self.upstream = partial
        self.python = self.work / runtime.RUNTIME / "venv/bin/python"
        with mock.patch.object(runtime, "_verify_source"), mock.patch.object(runtime.subprocess, "run", side_effect=self._run):
            runtime.prepare(self.work, self.bundle, KEY)
            self.assertTrue(marker.exists())
            self.assertFalse(any(call[:2] == ["git", "clone"] for call in self.calls))
            with self.assertRaises(runtime.RuntimeError):
                runtime._verify(self.work, self.bundle, "0x" + "b" * 96)

    def test_manifest_binding_is_fail_closed_before_tool_invocation(self):
        manifest = json.loads((self.bundle / "bundle-manifest.json").read_text())
        manifest["entries"][0]["sha256"] = "0" * 64
        (self.bundle / "bundle-manifest.json").write_text(json.dumps(manifest))
        with mock.patch.object(runtime.subprocess, "run") as run:
            with self.assertRaises(runtime.RuntimeError):
                runtime.prepare(self.work, self.bundle, KEY)
        run.assert_not_called()

    @unittest.skipUnless(PINNED_SOURCE.is_dir() and os.environ.get("RUN_CUSTODY_DEPENDENCY_INSTALL") == "1", "real dependency installation requires explicit opt-in and pinned source")
    def test_actual_prepare_install_and_network_free_verify(self):
        self.verifier.write_bytes((ROOT / "scripts/ops/verify-custody-keystore-secret.py").read_bytes())
        self.lock.write_bytes((ROOT / ".ci/custody-verifier/source-lock.json").read_bytes())
        self._manifest()
        self.assertTrue(PINNED_SOURCE.is_dir())
        original_run = subprocess.run
        calls = []

        def local_only(command, **kwargs):
            args = list(command); calls.append(args)
            if args[:2] == ["git", "clone"] and args[-2] == runtime.UPSTREAM:
                return original_run(["git", "clone", "--quiet", "--no-local", str(PINNED_SOURCE), args[-1]], check=True)
            return original_run(args, **kwargs)

        with mock.patch.object(runtime.subprocess, "run", side_effect=local_only):
            prepared = runtime.prepare(self.work, self.bundle, KEY)
            before_verify = len(calls)
            verified = runtime._verify(self.work, self.bundle, KEY)
        self.assertEqual(verified, prepared)
        self.assertTrue(any(call[:2] == ["git", "clone"] for call in calls))
        self.assertTrue(any("--require-hashes" in call for call in calls))
        self.assertFalse(any(call[:2] == ["git", "clone"] or "pip" in call for call in calls[before_verify:]))

    def test_real_venv_copies_has_a_regular_derived_python(self):
        venv = self.base / "real-venv"
        subprocess.run([sys.executable, "-I", "-m", "venv", "--copies", str(venv)], check=True, timeout=120)
        python = venv / "bin/python"
        self.assertTrue(python.is_file())
        self.assertFalse(python.is_symlink())

    def test_python_and_pip_configuration_is_not_inherited(self):
        with mock.patch.dict(os.environ, {"PYTHONPATH": "unsafe", "PYTHONHOME": "unsafe", "PIP_INDEX_URL": "https://unsafe.invalid", "PIP_CONFIG_FILE": "unsafe"}, clear=False):
            environment = runtime._clean_python_env()
        for key in ("PYTHONPATH", "PYTHONHOME", "PIP_INDEX_URL", "PIP_CONFIG_FILE"):
            self.assertNotIn(key, environment)


if __name__ == "__main__":
    unittest.main()

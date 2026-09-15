#!/usr/bin/env python3
# Check objective: Verify private checkpoint storage, context binding and exclusive execution.
"""Offline tests for the future installer's strict local checkpoint store."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("installer_state", ROOT / "scripts/release/installer_state.py")
assert SPEC and SPEC.loader
state = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(state)

CONTEXT = {
    "release_sha": "a" * 40,
    "bundle_digest": "sha256:" + "b" * 64,
    "aws_profile": "installer",
    "aws_account_id": "123456789012",
    "aws_region": "ap-northeast-2",
    "deployment_name": "hoodi-node",
}


class InstallerStateTests(unittest.TestCase):
    def store(self, root: Path, context: dict[str, str] = CONTEXT):
        return state.CheckpointStore(root / "checkpoint", context)

    def test_creates_private_atomic_checkpoint_and_retains_running(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = self.store(Path(temporary))
            with store.lock():
                self.assertEqual(store.resume()["stages"], {})
                store.set_stage("preflight", "running")
                stored = store.resume()
            self.assertEqual(stored["stages"], {"preflight": {"status": "running"}})
            self.assertEqual(stat.S_IMODE(store.directory.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(store.path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(store.lock_path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(store.path.read_text())["context"], CONTEXT)

    def test_corruption_context_mismatch_and_secret_fields_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = self.store(Path(temporary))
            with store.lock():
                store.resume()
            store.path.write_text("not json")
            store.path.chmod(0o600)
            with store.lock(), self.assertRaises(state.StateError):
                store.resume()
            store.path.write_text(json.dumps({"schema_version": 1, "context": CONTEXT, "stages": {}, "secret": "no"}))
            store.path.chmod(0o600)
            with store.lock(), self.assertRaises(state.StateError):
                store.resume()
            store.path.write_text(json.dumps({"schema_version": 1, "context": CONTEXT,
                                              "stages": {"preflight": {"status": "pending", "secret": "no"}}}))
            store.path.chmod(0o600)
            with store.lock(), self.assertRaises(state.StateError):
                store.resume()
            store.path.write_text(json.dumps({"schema_version": 1, "context": CONTEXT, "stages": {}}))
            store.path.chmod(0o600)
            other = dict(CONTEXT); other["deployment_name"] = "other-node"
            with self.store(Path(temporary), other).lock() as mismatched, self.assertRaises(state.ContextMismatchError):
                mismatched.resume()

    def test_rejects_invalid_context_and_duplicate_json_keys(self):
        invalid_cases = (
            ("release_sha", "A" * 40), ("bundle_digest", "sha256:" + "b" * 63),
            ("aws_profile", "profile with spaces"), ("aws_account_id", "1234"),
            ("aws_region", "us-east-1"), ("deployment_name", "UPPERCASE"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            for field, value in invalid_cases:
                with self.subTest(field=field):
                    context = dict(CONTEXT); context[field] = value
                    with self.assertRaises(state.StateError):
                        self.store(Path(temporary), context)
            store = self.store(Path(temporary))
            with store.lock(): store.resume()
            store.path.write_text('{"schema_version":1,"schema_version":1,"context":{},"stages":{}}')
            store.path.chmod(0o600)
            with store.lock(), self.assertRaises(state.StateError):
                store.resume()

    def test_refuses_symlinks_and_unsafe_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"; target.mkdir()
            (root / "checkpoint").symlink_to(target, target_is_directory=True)
            with self.assertRaises(state.StateError):
                with self.store(root).lock():
                    pass
            (root / "checkpoint").unlink()
            store = self.store(root)
            with store.lock(): store.resume()
            store.path.unlink(); store.path.symlink_to(target)
            with self.assertRaises(state.StateError):
                with store.lock(): store.resume()
            store.path.unlink(); store.path.write_text("{}")
            store.path.chmod(0o644)
            with self.assertRaises(state.StateError):
                with store.lock(): store.resume()

    def test_rejects_concurrent_lock_and_invalid_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = self.store(Path(temporary))
            other = self.store(Path(temporary))
            with store.lock():
                store.resume()
                with self.assertRaises(state.StateLockedError):
                    with other.lock():
                        pass
                with self.assertRaises(state.StateError):
                    store.set_stage("preflight", "complete-with-output")
                with self.assertRaises(state.StateError):
                    store.set_stage("../credential", "pending")
                with self.assertRaises(state.StateError):
                    store.set_stage("credential", "pending")
                with self.assertRaises(state.StateError):
                    store.set_stage("preflight", [])  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("public_export", ROOT / "scripts/release/create-public-source-export.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("public export module is unavailable")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PublicExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.source = self.tmp / "source"
        self.source.mkdir()
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        self.write("README.md", "account 123456789012 uses hoodi-example in node-operator-example and i-0123456789abcdef0\n")
        self.write("release/env.example", "ACCOUNT=123456789012\nVALIDATOR_SET=hoodi-example\n")
        self.write("plans/live.json", "must not export\n")
        self.write("docs/handoff/live.md", "must not export\n")
        self.write(".claude/spec.md", "must not export\n")
        subprocess.run(["git", "-C", str(self.source), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"], check=True)

    def write(self, relative, text):
        path = self.source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def test_exports_only_sanitized_allowed_tracked_files(self):
        output = self.tmp / "public"
        self.assertEqual(MODULE.create(self.source, output), 0)
        self.assertIn("123456789012", (output / "README.md").read_text())
        self.assertIn("hoodi-example", (output / "README.md").read_text())
        self.assertIn("node-operator-example", (output / "README.md").read_text())
        self.assertIn("i-0123456789abcdef0", (output / "README.md").read_text())
        self.assertTrue((output / "release/env.example").is_file())
        self.assertFalse((output / "plans/live.json").exists())
        self.assertFalse((output / "docs/handoff/live.md").exists())
        self.assertFalse((output / ".claude/spec.md").exists())

    def test_refuses_existing_output_and_credentials(self):
        output = self.tmp / "public"
        output.mkdir()
        with self.assertRaises(ValueError):
            MODULE.create(self.source, output)
        shutil.rmtree(output)
        self.write("unsafe.txt", "ghp_" + "a" * 32 + "\n")
        subprocess.run(["git", "-C", str(self.source), "add", "unsafe.txt"], check=True)
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-qm", "unsafe"], check=True)
        with self.assertRaises(ValueError):
            MODULE.create(self.source, output)


if __name__ == "__main__":
    unittest.main()

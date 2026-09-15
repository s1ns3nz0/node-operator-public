#!/usr/bin/env python3
# Check objective: Validate the local hash-enforced custody-verifier test environment.
"""Boundary tests for the local, hash-enforced custody-verifier test environment."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/prepare-custody-verifier-test-env.sh"


class CustodyVerifierTestEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.bin = self.base / "bin"; self.bin.mkdir()
        self.upstream = self.base / "upstream"; self.upstream.mkdir()
        self.work = self.base / "work"
        self.trace = self.base / "trace"
        self._write_fake_commands()

    def tearDown(self):
        self.temp.cleanup()

    def _write(self, name, text):
        path = self.bin / name
        path.write_text(text)
        path.chmod(0o700)

    def _write_fake_commands(self):
        self._write("python3", "#!/usr/bin/env bash\nset -eu\nprintf 'python3 %s\\n' \"$*\" >> \"$TRACE\"\n"
                    "[ \"$1\" != - ] || { [ \"${VALIDATION_FAIL:-0}\" != 1 ] || exit 65; exit 0; }\n"
                    "if [ \"$1\" = -m ] && [ \"$2\" = venv ]; then mkdir -p \"$3/bin\"; cp \"$0\" \"$3/bin/python\"; exit 0; fi\n"
                    "if [ \"$1\" = -m ] && [ \"$2\" = pip ]; then exit 0; fi\nexit 0\n")
        self._write("git", "#!/usr/bin/env bash\nset -eu\nprintf 'git %s\\n' \"$*\" >> \"$TRACE\"\n"
                    "case \"$3\" in rev-parse) printf '%s\\n' d8016bc8ca25d7f85e143828b6d99160f55a640f cb4515b6c62efa869294cc417a1b6cfe960e9ce4 d8016bc8ca25d7f85e143828b6d99160f55a640f ;;\n"
                    "cat-file) printf '%s\\n' tag ;; status) [ \"${STATUS_FAIL:-0}\" != 1 ] || exit 2; if [ \"${DIRTY:-0}\" = 1 ]; then printf ' M pkg/dirty.py\\n'; fi ;; esac\n")

    def invoke(self, **extra):
        env = os.environ.copy()
        env.update({"PATH": f"{self.bin}:{env['PATH']}", "TRACE": str(self.trace)})
        env.update({key: str(value) for key, value in extra.items()})
        return subprocess.run(["bash", str(SCRIPT), "--upstream-root", str(self.upstream), "--work-dir", str(self.work)],
                              text=True, capture_output=True, check=False, env=env)

    def test_verified_checkout_creates_private_venv_and_uses_hash_only_pip(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.work.stat().st_mode & 0o777, 0o700)
        trace = self.trace.read_text()
        self.assertIn("python3 -m venv " + str(self.work / "venv"), trace)
        self.assertIn("python3 -m pip install --disable-pip-version-check --no-input --require-hashes -r " + str(self.upstream / "requirements.txt"), trace)
        self.assertIn(f"CUSTODY_VERIFIER_UPSTREAM_ROOT={self.upstream}", result.stdout)
        self.assertIn(f"CUSTODY_VERIFIER_PYTHON={self.work / 'venv/bin/python'}", result.stdout)

    def test_dirty_python_source_is_rejected_before_workspace_or_installer(self):
        result = self.invoke(DIRTY=1)
        self.assertEqual(result.returncode, 65)
        self.assertFalse(self.work.exists())
        trace = self.trace.read_text()
        self.assertIn("git -C", trace)
        self.assertNotIn("-m venv", trace)
        self.assertNotIn("-m pip", trace)

    def test_invalid_source_lock_validation_is_rejected_before_git_workspace_or_installer(self):
        result = self.invoke(VALIDATION_FAIL=1)
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stderr, "custody verifier source lock validation failed\n")
        self.assertFalse(self.work.exists())
        trace = self.trace.read_text()
        self.assertIn("python3 - ", trace)
        self.assertNotIn("git -C", trace)
        self.assertNotIn("-m venv", trace)
        self.assertNotIn("-m pip", trace)

    def test_python_status_command_failure_is_rejected_before_workspace_or_installer(self):
        result = self.invoke(STATUS_FAIL=1)
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stderr, "custody verifier Python source status failed\n")
        self.assertFalse(self.work.exists())
        trace = self.trace.read_text()
        self.assertIn(" status --porcelain=v1 --untracked-files=all -- :(glob)**/*.py", trace)
        self.assertNotIn("-m venv", trace)
        self.assertNotIn("-m pip", trace)

    def test_invalid_arguments_and_existing_workspace_are_rejected_without_commands(self):
        result = subprocess.run(["bash", str(SCRIPT), "--upstream-root", "relative", "--work-dir", str(self.work)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 64)
        self.work.mkdir()
        result = self.invoke()
        self.assertEqual(result.returncode, 65)
        self.assertFalse(self.trace.exists())


if __name__ == "__main__":
    unittest.main()

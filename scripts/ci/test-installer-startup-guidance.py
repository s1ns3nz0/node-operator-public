#!/usr/bin/env python3
"""Exercise the public installer before its local bundle builder can run."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class InstallerStartupGuidanceTests(unittest.TestCase):
    def make_fixture(self, directory):
        root = Path(directory)
        installer = root / "scripts/release/node-operator-install.sh"
        installer.parent.mkdir(parents=True)
        shutil.copy2(ROOT / "scripts/release/node-operator-install.sh", installer)
        builder = root / "scripts/ci/build-release-bundle.sh"
        builder.parent.mkdir(parents=True)
        builder.write_text("#!/usr/bin/env bash\nprintf '%s\\n' BUILDER_REACHED >&2\nexit 91\n")
        builder.chmod(0o755)
        return installer

    def test_guidance_precedes_local_bundle_build_without_network_or_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            installer = self.make_fixture(directory)
            result = subprocess.run(
                ["bash", str(installer)], text=True, capture_output=True,
                env={**os.environ, "GITHUB_TOKEN": "preserve-me", "NO_COLOR": "1"},
            )
        self.assertEqual(result.returncode, 91)
        self.assertIn("Installer startup guidance", result.stderr)
        self.assertIn("Optional self-hosted CI/release administration", result.stderr)
        self.assertIn("CodeConnections GitHub App", result.stderr)
        self.assertIn("OIDC trust is separate", result.stderr)
        self.assertIn("RELEASE_RUNNER_ROLE_ARN", result.stderr)
        self.assertIn("GITOPS_EVIDENCE_APP_PRIVATE_KEY", result.stderr)
        self.assertIn("Do not provide credentials, tokens, private keys", result.stderr)
        self.assertIn("designated hidden ceremony prompt", result.stderr)
        self.assertIn("--profile <selected-profile> --region <selected-region>", result.stderr)
        self.assertIn("BUILDER_REACHED", result.stderr)
        self.assertLess(result.stderr.index("Installer startup guidance"), result.stderr.index("BUILDER_REACHED"))
        self.assertNotIn("preserve-me", result.stderr)
        self.assertNotIn("\x1b[", result.stderr)

    def test_arguments_fail_without_starting_a_bundle_build(self):
        with tempfile.TemporaryDirectory() as directory:
            installer = self.make_fixture(directory)
            result = subprocess.run(["bash", str(installer), "unexpected"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 64)
        self.assertIn("accepts no command-line options", result.stderr)
        self.assertNotIn("BUILDER_REACHED", result.stderr)

    def test_extracted_bundle_does_not_rebuild_its_signed_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            installer = self.make_fixture(root / "source")
            (root / "bundle-manifest.json").write_text('{"schema_version":"v1"}')
            flow = installer.with_name("interactive-hoodi-release.sh")
            flow.write_text('#!/usr/bin/env bash\n[ "$PYTHONDONTWRITEBYTECODE" = 1 ] || exit 92\nprintf "%s\\n" DOWNLOADED_BUNDLE_FLOW\n')
            flow.chmod(0o755)
            result = subprocess.run(["bash", str(installer)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DOWNLOADED_BUNDLE_FLOW", result.stdout)
        self.assertNotIn("BUILDER_REACHED", result.stderr)


if __name__ == "__main__":
    unittest.main()

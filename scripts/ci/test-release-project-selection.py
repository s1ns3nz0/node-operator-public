#!/usr/bin/env python3
"""Offline contracts for selecting CodeBuild projects without shell injection."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SIGNER = ROOT / "scripts/release/sign-release-bundle.sh"
WORKFLOW = ROOT / ".github/workflows/release-bundle.yml"


class ReleaseProjectSelectionTests(unittest.TestCase):
    def test_runner_default_and_environment_override_keep_exact_run_identity(self):
        source = WORKFLOW.read_text()
        self.assertIn(
            "runs-on: codebuild-${{ vars.PRIVATE_RELEASE_RUNNER_PROJECT || 'node-operator-baseline-private-release' }}-${{ github.run_id }}-${{ github.run_attempt }}",
            source,
        )
        self.assertIn("PRIVATE_RELEASE_RUNNER_PROJECT is a repository variable", source)
        self.assertIn("resolved before the release Environment is available", source)
        self.assertNotIn("runs-on: ubuntu-", source[source.index("  build-and-publish:"):])

    def signer_environment(self, root, project=None):
        fake_bin = root / "bin"
        fake_bin.mkdir(parents=True)
        workspace = root / "workspace"
        (workspace / "deploy/vault").mkdir(parents=True)
        (workspace / "deploy/vault/buildspec-release-sign.yml").write_text("version: 0.2\n")
        runner_temp = root / "runner-temp"
        release = runner_temp / "release"
        release.mkdir(parents=True)
        sha = "a" * 40
        (release / "node-operator-release-bundle.tar").write_text("bundle")
        (release / "node-operator-release-bundle.sha256").write_text("digest\n")
        (release / "provenance-input.json").write_text(
            '{"predicate":{"buildDefinition":{"resolvedDependencies":'
            '[{"uri":"git+node-operator","digest":{"gitCommit":"' + sha + '"}}]}}}'
        )
        starts = root / "start-build-args"
        (fake_bin / "curl").write_text('#!/usr/bin/env bash\nprintf \'{"value":"oidc"}\'\n')
        (fake_bin / "aws").write_text(
            "#!/usr/bin/env bash\n"
            "case \"$1 $2\" in\n"
            "  'sts assume-role-with-web-identity') printf '%s\\n' '{\"Credentials\":{\"AccessKeyId\":\"a\",\"SecretAccessKey\":\"b\",\"SessionToken\":\"c\"}}' ;;\n"
            "  's3api put-object') exit 0 ;;\n"
            "  's3api head-object') printf '%s\\n' version-1 ;;\n"
            f"  'codebuild start-build') printf '%s\\n' \"$@\" > {starts}; exit 91 ;;\n"
            "  *) exit 92 ;;\n"
            "esac\n"
        )
        for command in (fake_bin / "curl", fake_bin / "aws"):
            command.chmod(0o755)
        env = {
            **os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/release", "AWS_REGION": "ap-northeast-2",
            "INPUT_BUCKET": "release-bucket", "RUNNER_TEMP": str(runner_temp), "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_RUN_ID": "123", "GITHUB_SHA": sha,
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc", "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.example/request?x=1",
        }
        if project is not None:
            env["RELEASE_SIGNER_PROJECT"] = project
        return env, starts, fake_bin / "curl-called"

    def test_signer_default_and_custom_names_are_selected(self):
        source = SIGNER.read_text()
        self.assertIn('release_signer_project="${RELEASE_SIGNER_PROJECT:-node-operator-baseline-release-signer}"', source)
        self.assertIn('^[A-Za-z0-9][A-Za-z0-9_-]{1,254}$', source)
        self.assertIn('--project-name "$release_signer_project"', source)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, starts, _ = self.signer_environment(root / "default")
            result = subprocess.run(["bash", str(SIGNER)], text=True, capture_output=True, env=env)
            self.assertEqual(result.returncode, 91)
            self.assertIn("--project-name\nnode-operator-baseline-release-signer", starts.read_text())
        with tempfile.TemporaryDirectory() as directory:
            env, starts, _ = self.signer_environment(Path(directory) / "custom", "node-operator-example-baseline-release-signer")
            result = subprocess.run(["bash", str(SIGNER)], text=True, capture_output=True, env=env)
            self.assertEqual(result.returncode, 91)
            self.assertIn("--project-name\nnode-operator-example-baseline-release-signer", starts.read_text())

    def test_invalid_signer_name_rejects_before_network_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, _, curl_marker = self.signer_environment(root, "bad;touch injected")
            curl = Path(env["PATH"].split(":", 1)[0]) / "curl"
            curl.write_text(f"#!/usr/bin/env bash\ntouch {curl_marker}\n")
            curl.chmod(0o755)
            result = subprocess.run(["bash", str(SIGNER)], text=True, capture_output=True, env=env)
            self.assertEqual(result.returncode, 64)
            self.assertIn("RELEASE_SIGNER_PROJECT must be", result.stderr)
            self.assertFalse(curl_marker.exists())


if __name__ == "__main__":
    unittest.main()

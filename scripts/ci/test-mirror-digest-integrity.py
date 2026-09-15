#!/usr/bin/env python3
# Check objective: Execute both mirror entrypoints against mocked CLIs and reject unbound or malformed destination digests before publishing outputs.
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
TARGETS = {"signer": ("mirror-signer-image.sh", "ghcr.io/s1ns3nz0/node-operator/vault-release-signer"),
           "collector": ("mirror-validator-log-collector.sh", "cr.fluentbit.io/fluent/fluent-bit")}
MOCK = r'''
import json, os, pathlib, sys
tool = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["MOCK_CALLS"], "a") as log:
    log.write(json.dumps([tool] + args) + "\n")
if tool == "curl":
    print('{"value":"synthetic-oidc"}')
elif tool == "aws":
    if args[:2] == ["sts", "assume-role-with-web-identity"]:
        print(json.dumps({"Credentials":{"AccessKeyId":"fixture", "SecretAccessKey":"fixture", "SessionToken":"fixture"}}))
    elif args[:2] == ["ecr", "get-login-password"]:
        print("fixture-password")
    elif args[:2] == ["ecr", "describe-images"]:
        if os.environ.get("QUERY_FAIL") == "1": sys.exit(29)
        print(os.environ["RETURN_DIGEST"])
    else: sys.exit(98)
elif tool == "docker":
    if args[0] == "login": sys.stdin.read()
    elif args[0] in {"pull", "tag"}: pass
    elif args[0] == "push" or args[:3] == ["buildx", "imagetools", "create"]:
        if os.environ.get("COPY_FAIL") == "1": sys.exit(28)
    else: sys.exit(97)
else: sys.exit(99)
'''


def run_mirror(target, returned=DIGEST, source=None, source_digest=DIGEST, **overrides):
    filename, repository = TARGETS[target]
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        binary = root / "bin"
        binary.mkdir()
        for tool in ("aws", "docker", "curl"):
            executable = binary / tool
            executable.write_text("#!" + sys.executable + "\n" + MOCK)
            executable.chmod(0o700)
        output, summary = root / "outputs", root / "summary"
        output.write_text("prior-output\n")
        summary.write_text("prior-summary\n")
        reference = source if source is not None else repository + "@" + DIGEST
        environment = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"],
                           MOCK_CALLS=str(root / "calls"), RETURN_DIGEST=returned,
                           SOURCE=reference, SOURCE_IMAGE=reference, SOURCE_DIGEST=source_digest,
                           ACCOUNT_ID="123456789012", AWS_REGION="ap-northeast-2", AWS_ROLE_ARN="fixture-role",
                           REGISTRY_TOKEN="fixture", REGISTRY_USERNAME="fixture", RUNNER_TEMP=str(root),
                           GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(summary), GITHUB_RUN_ID="1",
                           ACTIONS_ID_TOKEN_REQUEST_TOKEN="fixture", ACTIONS_ID_TOKEN_REQUEST_URL="https://fixture.invalid/token")
        environment.update(overrides)
        result = subprocess.run(["bash", str(ROOT / "scripts/release" / filename)],
                                cwd=ROOT, env=environment, text=True, capture_output=True)
        calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()] if (root / "calls").exists() else []
        return result, output.read_text(), summary.read_text(), calls


class MirrorIntegrity(unittest.TestCase):
    def assert_rejected(self, result):
        process, output, summary, _ = result
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(output, "prior-output\n")
        self.assertEqual(summary, "prior-summary\n")

    def test_matching_digest_succeeds(self):
        for target in TARGETS:
            with self.subTest(target=target):
                process, output, summary, _ = run_mirror(target)
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertIn(DIGEST, summary)
                self.assertEqual("ecr_image=" in output, target == "signer")

    def test_different_valid_digest_is_rejected(self):
        for target in TARGETS:
            with self.subTest(target=target):
                self.assert_rejected(run_mirror(target, returned=OTHER))

    def test_malformed_destination_is_rejected(self):
        for target in TARGETS:
            for returned in ("", "None", "sha256:abc", DIGEST.upper(), DIGEST + " ", DIGEST + "\n" + OTHER):
                with self.subTest(target=target, returned=returned):
                    self.assert_rejected(run_mirror(target, returned=returned))

    def test_signer_source_alias_cannot_override_pinned_source(self):
        for alias in (OTHER, "", "sha256:abc", DIGEST.upper()):
            with self.subTest(alias=alias):
                result = run_mirror("signer", returned=OTHER, source_digest=alias)
                self.assert_rejected(result)
                self.assertEqual(result[3], [])

    def test_invalid_source_fails_before_external_calls(self):
        for target, (_, repository) in TARGETS.items():
            for source in (repository + ":latest", "evil.invalid/image@" + DIGEST, repository + "@sha256:bad"):
                with self.subTest(target=target, source=source):
                    result = run_mirror(target, source=source)
                    self.assert_rejected(result)
                    self.assertEqual(result[3], [])

    def test_copy_and_query_failures_are_rejected(self):
        for target in TARGETS:
            for failure in ("COPY_FAIL", "QUERY_FAIL"):
                with self.subTest(target=target, failure=failure):
                    self.assert_rejected(run_mirror(target, **{failure: "1"}))

    def test_copy_preserves_manifest_or_index(self):
        for target, (_, repository) in TARGETS.items():
            with self.subTest(target=target):
                process, _, _, calls = run_mirror(target)
                self.assertEqual(process.returncode, 0)
                copies = [call for call in calls if call[:4] == ["docker", "buildx", "imagetools", "create"]]
                self.assertEqual(len(copies), 1)
                self.assertIn("--prefer-index=false", copies[0])
                self.assertEqual(copies[0][-1], repository + "@" + DIGEST)
                self.assertFalse(any(call[:2] in (["docker", "pull"], ["docker", "tag"], ["docker", "push"]) for call in calls))


if __name__ == "__main__":
    unittest.main()

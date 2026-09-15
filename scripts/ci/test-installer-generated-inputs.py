#!/usr/bin/env python3
"""Offline checks for installer-owned generated and selected input boundaries."""
import json, pathlib, shutil, subprocess, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
ZERO = ROOT / "scripts/release/prepare-zero-resource-inputs.sh"
WRAPPER = ROOT / "scripts/release/interactive-hoodi-release.sh"
ACCOUNT = "123456789012"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/NodeOperatorTerraformApply"


class GeneratedInputs(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def zero(self, name, *extra, identities=True):
        output = self.tmp / name
        command = [str(ZERO), "--aws-account-id", ACCOUNT,
            "--aws-region", "ap-northeast-2", "--availability-zone", "ap-northeast-2a",
            "--availability-zone", "ap-northeast-2c", "--name", "node-2401010000-a1b2",
            "--backend-principal-arn", ROLE]
        if identities:
            command += ["--github-repository", "example/operator",
            "--github-owner-id", "101", "--github-repository-id", "202",
            "--gitops-client-github-repository", "example/gitops", "--gitops-client-github-owner-id", "303",
            "--gitops-client-github-repository-id", "404"]
        return subprocess.run([*command, "--output-dir", str(output), *extra], text=True, capture_output=True), output

    def test_explicit_identity_and_replica_default(self):
        result, output = self.zero("default")
        self.assertEqual(result.returncode, 0, result.stderr)
        baseline = json.loads((output / "baseline.tfvars.json").read_text())
        self.assertEqual(baseline["audit_replica_region"], "ap-northeast-1")
        self.assertEqual(baseline["github_repository"], "example/operator")
        self.assertEqual(baseline["gitops_client_github_repository"], "example/gitops")

    def test_explicit_replica_and_exact_identity_propagate(self):
        result, output = self.zero("custom", "--audit-replica-region", "ap-northeast-1",
            "--github-repository", "example/operator", "--github-owner-id", "101",
            "--github-repository-id", "202", "--gitops-client-github-repository", "example/gitops",
            "--gitops-client-github-owner-id", "303", "--gitops-client-github-repository-id", "404")
        self.assertEqual(result.returncode, 0, result.stderr)
        baseline = json.loads((output / "baseline.tfvars.json").read_text())
        self.assertEqual({k: baseline[k] for k in ("github_repository", "github_owner_id", "github_repository_id")},
                         {"github_repository":"example/operator", "github_owner_id":"101", "github_repository_id":"202"})
        self.assertEqual(baseline["gitops_client_github_repository_id"], "404")

    def test_same_replica_and_partial_identity_rejected_before_output(self):
        result, output = self.zero("same", "--audit-replica-region", "ap-northeast-2")
        self.assertNotEqual(result.returncode, 0); self.assertFalse(output.exists())
        result, output = self.zero("partial", "--github-repository", "example/operator", identities=False)
        self.assertNotEqual(result.returncode, 0); self.assertFalse(output.exists())

    def test_wrapper_has_pre_aws_explicit_withdrawal_and_random_bounded_name(self):
        source = WRAPPER.read_text()
        fresh = source.index("step 'Collecting deployment settings'")
        withdrawal_guard = source.index("withdrawal address must be explicitly configured", fresh)
        aws_identity = source.index('identity="$(aws sts get-caller-identity', fresh)
        self.assertLess(withdrawal_guard, aws_identity)
        self.assertIn('DEFAULT_WITHDRAWAL="${DEFAULT_WITHDRAWAL:-}"', source)
        self.assertIn('node-$(date -u +%y%m%d%H%M)-$(printf \'%04x\' "$RANDOM")', source)
        # node- + ten UTC digits + hyphen + four random hexadecimal characters.
        self.assertLessEqual(len("node-") + 10 + 1 + 4, 20)
        self.assertIn('if [ -n "${WORK_DIR:-}" ]; then', source)

    def test_name_generation_executes_under_fixed_time_and_preserves_override(self):
        source = WRAPPER.read_text()
        line = next(row for row in source.splitlines() if row.startswith('DEFAULT_DEPLOYMENT_NAME='))
        script = 'date() { printf 2609151234; }; RANDOM=1234;\n'
        script += 'for attempt in 1 2; do unset DEFAULT_DEPLOYMENT_NAME;\n' + line
        script += '\nprintf "%s\\n" "$DEFAULT_DEPLOYMENT_NAME"; done\n'
        script += 'DEFAULT_DEPLOYMENT_NAME=existing-deployment;\n' + line
        script += '\nprintf "%s\\n" "$DEFAULT_DEPLOYMENT_NAME"\n'
        result = subprocess.run(['bash', '-c', script], capture_output=True, text=True, check=True)
        names = result.stdout.splitlines()
        self.assertNotEqual(names[0], names[1])
        for name in names[:2]:
            self.assertRegex(name, r'^node-2609151234-[0-9a-f]{4}$')
            self.assertLessEqual(len(name), 20)
        self.assertEqual(names[2], 'existing-deployment')

    def test_partial_trust_stops_in_wrapper_before_aws(self):
        source = WRAPPER.read_text()
        function = source.split('validate_selected_github_identity() {', 1)[1].split('\n}', 1)[0]
        script = 'validate_selected_github_identity() {' + function + '\n}\n'
        script += 'validate_selected_github_identity example/operator "" "" || exit $?\nprintf SHOULD_NOT_RUN\n'
        result = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 64)
        self.assertNotIn('SHOULD_NOT_RUN', result.stdout)
        self.assertLess(source.index('validate_selected_github_identity "$DEFAULT_GITHUB_REPOSITORY"'),
                        source.index('identity="$(aws sts get-caller-identity'))


if __name__ == "__main__":
    unittest.main()

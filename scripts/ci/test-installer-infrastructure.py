# Check objective: Verify context-bound infrastructure preparation without Terraform or cloud operations.
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
infra = importlib.import_module("installer_infrastructure")
DISCOVERY = {"aws_profile": "operator", "aws_account_id": "123456789012", "aws_region": "ap-northeast-1",
             "deployment_name": "test-node", "availability_zones": ["ap-northeast-1a", "ap-northeast-1c"],
             "configuration_recorder": {"result": "recorder_absent_verified", "existing_count": 0,
                                          "manage_config_recorder": True, "existing_recorder_adoption": "not_authorized"}}
ROLE = "arn:aws:iam::123456789012:role/backend"


@unittest.skipUnless(shutil.which("jq"), "release preparation requires jq")
class InfrastructurePreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name).resolve()
        self.bundle = self.directory / "bundle"
        script_dir = self.bundle / "source/scripts/release"
        script_dir.mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/release/prepare-zero-resource-inputs.sh", script_dir / "prepare-zero-resource-inputs.sh")
        self.destination = self.directory / "inputs"

    def tearDown(self):
        self.temporary.cleanup()

    def test_real_release_script_prepares_private_inputs_and_reuses_without_execution(self):
        result = infra.prepare_inputs(self.bundle, self.destination, DISCOVERY, ROLE)
        self.assertEqual(result, self.destination / "zero-resource-inputs.json")
        for name, expected in infra.expected_inputs(self.destination, DISCOVERY, ROLE).items():
            path = self.destination / name
            self.assertEqual(json.loads(path.read_text()), expected)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with patch.object(infra.subprocess, "run") as run:
            self.assertEqual(infra.prepare_inputs(self.bundle, self.destination, DISCOVERY, ROLE), result)
        run.assert_not_called()
        self.assertEqual(list(self.directory.glob(".infrastructure-inputs-*")), [])

    def test_generator_feature_flags_are_exact_and_tampering_is_rejected(self):
        infra.prepare_inputs(self.bundle, self.destination, DISCOVERY, ROLE)
        path = self.destination / "baseline.tfvars.json"
        values = json.loads(path.read_text())
        self.assertEqual(values["terraform_apply_role_arn"], ROLE)
        self.assertEqual(
            {key: values[key] for key in (
                "enable_validator_runtime_ecr_mirror",
                "enable_validator_client_ecr_mirror",
                "enable_vault_audit_relay_repository",
                "manage_config_recorder",
            )},
            {
                "enable_validator_runtime_ecr_mirror": True,
                "enable_validator_client_ecr_mirror": True,
                "enable_vault_audit_relay_repository": True,
                "manage_config_recorder": True,
            },
        )
        values["manage_config_recorder"] = False
        path.write_text(json.dumps(values))
        with self.assertRaises(infra.InfrastructureError):
            infra.prepare_inputs(self.bundle, self.destination, DISCOVERY, ROLE)

    def test_existing_config_recorder_is_preserved_by_generated_inputs(self):
        observed = {**DISCOVERY, "configuration_recorder": {
            "result": "existing_recorder_verified", "existing_count": 1,
            "manage_config_recorder": False, "existing_recorder_adoption": "not_authorized",
        }}
        infra.prepare_inputs(self.bundle, self.destination, observed, ROLE)
        self.assertIs(json.loads((self.destination / "baseline.tfvars.json").read_text())["manage_config_recorder"], False)

    def test_owned_recorder_resume_retains_original_true_only_after_remote_proof(self):
        infra.prepare_inputs(self.bundle, self.destination, DISCOVERY, ROLE)
        original = (self.destination / "baseline.tfvars.json").read_bytes()
        observed = {**DISCOVERY, "configuration_recorder": {
            "result": "existing_recorder_verified", "existing_count": 1,
            "manage_config_recorder": False, "existing_recorder_adoption": "not_authorized",
        }}
        with patch.object(infra, "verify_managed_recorder_resume", return_value=True) as verify, patch.object(infra.subprocess, "run") as run:
            infra.prepare_inputs(self.bundle, self.destination, observed, ROLE, self.directory)
        verify.assert_called_once_with(self.bundle, self.directory, self.destination, observed)
        run.assert_not_called()
        self.assertEqual((self.destination / "baseline.tfvars.json").read_bytes(), original)
        with patch.object(infra, "verify_managed_recorder_resume", side_effect=infra.InfrastructureError("unowned")), self.assertRaises(infra.InfrastructureError):
            infra.prepare_inputs(self.bundle, self.destination, observed, ROLE, self.directory)
        self.assertEqual((self.destination / "baseline.tfvars.json").read_bytes(), original)

    def test_remote_recorder_proof_uses_read_only_wrapper_and_rejects_bad_result(self):
        state = self.directory / "state"; state.mkdir(mode=0o700)
        work = state / "terraform-work"; work.mkdir(mode=0o700)
        infra.prepare_inputs(self.bundle, self.destination, DISCOVERY, ROLE)
        observed = {**DISCOVERY, "principal_arn": "arn:aws:iam::123456789012:user/operator", "configuration_recorder": {"result": "existing_recorder_verified", "existing_count": 1, "manage_config_recorder": False, "existing_recorder_adoption": "not_authorized"}}
        release = self.bundle / "source/scripts/release/node-operator-release.sh"; release.write_text("#!/usr/bin/env bash\n"); release.chmod(0o700)
        with patch.dict(os.environ, {"TF_VAR_name": "foreign"}), patch.object(infra, "aws_read", return_value={"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/operator"}), patch.object(infra.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertTrue(infra.verify_managed_recorder_resume(self.bundle, state, self.destination, observed))
        args = run.call_args.args[0]
        self.assertEqual(args[2:4], ["zero", "verify-recorder"])
        self.assertNotIn("apply", args)
        self.assertNotIn("TF_VAR_name", run.call_args.kwargs["env"])
        with patch.object(infra, "aws_read", return_value={"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/operator"}), patch.object(infra.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)), self.assertRaises(infra.InfrastructureError):
            infra.verify_managed_recorder_resume(self.bundle, state, self.destination, observed)

    def test_remote_recorder_proof_uses_reverified_execution_profile(self):
        state = self.directory / "execution-state"; state.mkdir(mode=0o700); (state / "terraform-work").mkdir(mode=0o700)
        infra.prepare_inputs(self.bundle, self.destination, DISCOVERY, ROLE)
        release = self.bundle / "source/scripts/release/node-operator-release.sh"; release.write_text("#!/usr/bin/env bash\n"); release.chmod(0o700)
        observed = {**DISCOVERY, "configuration_recorder": {"result":"existing_recorder_verified","existing_count":1,"manage_config_recorder":False,"existing_recorder_adoption":"not_authorized"}, "backend_role":{"arn":ROLE,"role_id":"AROA123456789012"}, "execution_identity":{"aws_profile":"execution","role_arn":ROLE,"role_id":"AROA123456789012","session_identity":"verified"}}
        with patch.object(infra, "verify_execution_profile") as verify, patch.object(infra.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertTrue(infra.verify_managed_recorder_resume(self.bundle, state, self.destination, observed))
        verify.assert_called_once_with(observed, observed["backend_role"], "execution")
        self.assertEqual(run.call_args.kwargs["env"]["AWS_PROFILE"], "execution")
        with patch.object(infra, "verify_execution_profile", side_effect=infra.PreflightError("changed")), patch.object(infra.subprocess, "run") as run, self.assertRaises(infra.InfrastructureError):
            infra.verify_managed_recorder_resume(self.bundle, state, self.destination, observed)
        run.assert_not_called()

    def test_missing_or_ambiguous_recorder_observation_stops_before_generator(self):
        for recorder in ({}, {"result": "recorder_absent_verified", "existing_count": 0,
                              "manage_config_recorder": False, "existing_recorder_adoption": "not_authorized"},
                         {"result": "recorder_absent_verified", "existing_count": False,
                              "manage_config_recorder": True, "existing_recorder_adoption": "not_authorized"},
                         {"result": "recorder_absent_verified", "existing_count": 0.0,
                              "manage_config_recorder": True, "existing_recorder_adoption": "not_authorized"}):
            with self.subTest(recorder=recorder), patch.object(infra.subprocess, "run") as run, self.assertRaises(infra.InfrastructureError):
                infra.prepare_inputs(self.bundle, self.destination, {**DISCOVERY, "configuration_recorder": recorder}, ROLE)
            run.assert_not_called()

    def test_wrong_account_role_rejected_before_any_command(self):
        with patch.object(infra.subprocess, "run") as run, self.assertRaises(infra.InfrastructureError):
            infra.prepare_inputs(self.bundle, self.destination, DISCOVERY, ROLE.replace("123456789012", "999999999999"))
        run.assert_not_called()
        self.assertFalse(self.destination.exists())

    def test_changed_context_does_not_overwrite_existing_inputs(self):
        infra.prepare_inputs(self.bundle, self.destination, DISCOVERY, ROLE)
        original = (self.destination / "bootstrap-state.tfvars.json").read_bytes()
        with patch.object(infra.subprocess, "run") as run, self.assertRaises(infra.InfrastructureError):
            infra.prepare_inputs(self.bundle, self.destination, DISCOVERY, ROLE + "-other")
        run.assert_not_called()
        self.assertEqual((self.destination / "bootstrap-state.tfvars.json").read_bytes(), original)

    def test_failed_command_is_sanitized_and_staging_is_removed(self):
        failed = subprocess.CompletedProcess([], 1, "secret stdout", "secret stderr")
        with patch.object(infra.subprocess, "run", return_value=failed), self.assertRaises(infra.InfrastructureError) as error:
            infra.prepare_inputs(self.bundle, self.destination, DISCOVERY, ROLE)
        self.assertNotIn("secret", str(error.exception))
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.directory.glob(".infrastructure-inputs-*")), [])

    def test_corrupt_or_extra_input_is_not_accepted(self):
        infra.prepare_inputs(self.bundle, self.destination, DISCOVERY, ROLE)
        path = self.destination / "baseline.tfvars.json"
        path.write_text('{"enable_vault_bootstrap_cluster_admin":true}')
        with self.assertRaises(infra.InfrastructureError):
            infra.prepare_inputs(self.bundle, self.destination, DISCOVERY, ROLE)

    def test_environment_keeps_github_and_binds_selected_aws_profile(self):
        original_run = subprocess.run
        with patch.dict(os.environ, {"GITHUB_TOKEN": "sentinel", "AWS_SECRET_ACCESS_KEY": "private"}), patch.object(infra.subprocess, "run", wraps=original_run) as run:
            infra.prepare_inputs(self.bundle, self.destination, DISCOVERY, ROLE)
            environment = run.call_args.kwargs["env"]
            self.assertEqual(environment["GITHUB_TOKEN"], "sentinel")
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
            self.assertEqual(environment["AWS_PROFILE"], "operator")
            self.assertEqual(os.environ["AWS_SECRET_ACCESS_KEY"], "private")

    def test_destination_created_at_publish_is_preserved(self):
        original = infra.publish_directory
        observed = {}
        def race(source, destination):
            destination.mkdir(mode=0o700)
            observed["inode"] = destination.stat().st_ino
            return original(source, destination)
        with patch.object(infra, "publish_directory", side_effect=race), self.assertRaises(infra.InfrastructureError):
            infra.prepare_inputs(self.bundle, self.destination, DISCOVERY, ROLE)
        self.assertEqual(self.destination.stat().st_ino, observed["inode"])
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertEqual(list(self.directory.glob(".infrastructure-inputs-*")), [])


class InfrastructureApplyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name).resolve()
        self.directory.chmod(0o700)
        self.bundle = self.directory / "release"
        self.contract = self.bundle / "source/release/hoodi-release-contract.json"
        self.contract.parent.mkdir(parents=True)
        self.write(self.contract, {"bootstrap": {"interactive_infrastructure_schema": 1}})
        self.inputs = self.directory / "infrastructure-inputs"
        self.inputs.mkdir(mode=0o700)
        self.discovery = {**DISCOVERY, "principal_arn": "arn:aws:iam::123456789012:user/operator",
            "cluster_name_present": False,
            "backend_collisions": {"account_owned_bucket_conflicts": [], "regional_table_conflicts": []},
            "iam_role_collisions": {"deployment_role_name_conflicts": []},
            "elastic_ip_headroom": {"result": "sufficient_at_observation"},
            "local_prerequisites": {"missing_by_stage": {"infrastructure": []}}}
        for name, value in infra.expected_inputs(self.inputs, self.discovery, ROLE).items():
            self.write(self.inputs / name, value)

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def invoke(self, code=0, account="123456789012"):
        def command(args, **kwargs):
            self.assertEqual(args[2:4], ["zero", "apply"])
            self.assertEqual(kwargs["env"]["AWS_PROFILE"], "operator")
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", kwargs["env"])
            for key in infra.AWS_CREDENTIAL_OVERRIDES:
                self.assertNotIn(key, kwargs["env"])
            self.assertEqual(kwargs["env"]["AWS_EC2_METADATA_DISABLED"], "true")
            self.assertNotIn("TF_VAR_name", kwargs["env"])
            self.assertEqual(kwargs["env"]["GITHUB_TOKEN"], "sentinel")
            work = self.directory / "terraform-work"
            work.mkdir(mode=0o700, exist_ok=True)
            self.write(work / "baseline-output.json", {"deployment_account_id": {"value": account}, "cluster_name": {"value": "test-node"}})
            return subprocess.CompletedProcess(args, code)
        with patch.dict(os.environ, {**dict.fromkeys(infra.AWS_CREDENTIAL_OVERRIDES, "unexpected-provider"), "GITHUB_TOKEN": "sentinel", "AWS_SECRET_ACCESS_KEY": "private", "TF_VAR_name": "wrong"}), patch.object(infra, "aws_read", return_value={"Account": "123456789012", "Arn": self.discovery["principal_arn"]}), patch.object(infra.subprocess, "run", side_effect=command) as run:
            infra.apply_infrastructure(self.bundle, self.directory, self.discovery, ROLE, "operator")
        return run

    def test_apply_uses_selected_profile_and_checks_completion_output(self):
        self.assertEqual(self.invoke().call_count, 1)

    def test_failed_apply_or_wrong_account_never_reports_completion(self):
        for options in ({"code": 1}, {"account": "999999999999"}):
            with self.assertRaises(infra.InfrastructureError):
                self.invoke(**options)

    def test_old_bundle_and_collisions_never_start_command(self):
        self.write(self.contract, {"bootstrap": {}})
        with patch.object(infra.subprocess, "run") as run, self.assertRaises(infra.InfrastructureError):
            infra.apply_infrastructure(self.bundle, self.directory, self.discovery, ROLE, "operator")
        run.assert_not_called()
        self.write(self.contract, {"bootstrap": {"interactive_infrastructure_schema": 1}})
        self.discovery["cluster_name_present"] = True
        with patch.object(infra.subprocess, "run") as run, self.assertRaises(infra.InfrastructureError):
            infra.apply_infrastructure(self.bundle, self.directory, self.discovery, ROLE, "operator")
        run.assert_not_called()

    def test_changed_execution_identity_never_starts_command(self):
        with patch.object(infra, "aws_read", return_value={"Account": "999999999999", "Arn": "other"}), patch.object(infra.subprocess, "run") as run, self.assertRaises(infra.InfrastructureError):
            infra.apply_infrastructure(self.bundle, self.directory, self.discovery, ROLE, "operator")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()

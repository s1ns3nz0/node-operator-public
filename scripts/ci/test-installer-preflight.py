# Check objective: Verify read-only discovery, capacity observations and sanitized failures.
"""Check read-only AWS discovery, identity binding and sanitized failures."""
import importlib.util
import os
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("preflight", Path(__file__).resolve().parents[1] / "release/installer_preflight.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PreflightTests(unittest.TestCase):
    def test_bootstrap_permission_probe_never_claims_full_authorization(self):
        context = {"aws_profile": "operator", "aws_region": "ap-northeast-1", "aws_account_id": "123456789012", "deployment_name": "test-node"}
        role = {"arn": "arn:aws:iam::123456789012:role/apply"}
        for decision, missing, expected in (("allowed", [], "limited_checks_passed"),
                                            ("implicitDeny", ["aws:userid"], "requires_permission_review"),
                                            ("explicitDeny", [], "requires_permission_review")):
            def response(profile, region, args):
                self.assertEqual(profile, "operator")
                self.assertEqual(args[0:2], ["iam", "simulate-principal-policy"])
                entries = json.loads(args[args.index("--context-entries") + 1])
                self.assertEqual({entry["ContextKeyName"] for entry in entries}, {"aws:CurrentTime", "aws:RequestedRegion"})
                targets = {"s3:CreateBucket": "arn:aws:s3:::test-node-tfstate-123456789012-apnortheast1",
                           "dynamodb:CreateTable": "arn:aws:dynamodb:ap-northeast-1:123456789012:table/test-node-terraform-lock",
                           "iam:CreateRole": "arn:aws:iam::123456789012:role/test-node-foundation-flow-logs"}
                self.assertEqual(args[args.index("--resource-arns") + 1], targets[args[args.index("--action-names") + 1]])
                return [{"Action": args[args.index("--action-names") + 1], "Decision": decision, "Missing": missing}]
            with patch.object(module, "aws_read", side_effect=response) as read:
                result = module.bootstrap_permission_probe(context, role)
            self.assertEqual(read.call_count, 3)
            self.assertEqual(result["result"], expected)
            self.assertEqual(result["provisioning_permissions"], "not_verified")
            if missing:
                self.assertTrue(all(check["result"] == "inconclusive" for check in result["checks"]))
        with patch.object(module, "aws_read", side_effect=module.PreflightError("raw sensitive detail")):
            result = module.bootstrap_permission_probe(context, role)
        self.assertTrue(all(check["result"] == "unverified" for check in result["checks"]))
        self.assertNotIn("sensitive", json.dumps(result))
        with patch.object(module, "aws_read", return_value=[]), self.assertRaises(module.PreflightError):
            module.bootstrap_permission_probe(context, role)

    def test_execution_profile_binds_unique_role_id_without_getrole_permission(self):
        context = {"aws_profile": "operator", "aws_region": "ap-northeast-1", "aws_account_id": "123456789012", "deployment_name": "test-node"}
        role = {"arn": "arn:aws:iam::123456789012:role/path/backend", "role_id": "AROA" + "A" * 17}
        identity = {"Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/backend/session", "UserId": role["role_id"] + ":session"}
        with patch.object(module, "aws_read", return_value=identity) as read:
            result = module.verify_execution_profile(context, role, "execution")
        read.assert_called_once_with("execution", "ap-northeast-1", ["sts", "get-caller-identity"])
        self.assertEqual(result["session_identity"], "verified")
        self.assertEqual(result["provisioning_permissions"], "not_verified")
        self.assertNotIn("UserId", result)
        for field, bad in (("Account", "999999999999"), ("UserId", "AROA" + "B" * 17 + ":session"),
                           ("UserId", role["role_id"] + ":other"), ("Arn", "arn:aws:iam::123456789012:user/operator")):
            with patch.object(module, "aws_read", return_value={**identity, field: bad}), self.assertRaises(module.PreflightError):
                module.verify_execution_profile(context, role, "execution")
        other_role = {"Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/other/session",
                      "UserId": "AROA" + "B" * 17 + ":session"}
        with patch.object(module, "aws_read", return_value=other_role), self.assertRaises(module.PreflightError):
            module.verify_execution_profile(context, role, "execution")

    def test_backend_role_lookup_checks_exact_identity_not_permissions(self):
        context = {"aws_profile": "test", "aws_region": "ap-northeast-1", "aws_account_id": "123456789012"}
        arn = "arn:aws:iam::123456789012:role/path/backend"
        with patch.object(module, "aws_read", return_value={"Arn": arn, "RoleId": "AROA" + "A" * 17}) as read:
            result = module.verify_backend_role(context, arn)
        self.assertEqual(read.call_args.args, ("test", "ap-northeast-1", ["iam", "get-role", "--role-name", "backend", "--query", "Role.{Arn:Arn,RoleId:RoleId}"]))
        self.assertEqual(result["existence"], "verified")
        self.assertEqual(result["backend_permissions"], "not_verified")

    def test_backend_role_missing_wrong_account_or_malformed_is_rejected(self):
        context = {"aws_profile": "test", "aws_region": "ap-northeast-1", "aws_account_id": "123456789012"}
        arn = "arn:aws:iam::123456789012:role/backend"
        for observed in (None, {}, {"Arn": arn, "RoleId": "invalid"}, {"Arn": arn + "wrong", "RoleId": "AROA" + "A" * 17}):
            with patch.object(module, "aws_read", return_value=observed), self.assertRaises(module.PreflightError):
                module.verify_backend_role(context, arn)
        with patch.object(module, "aws_read") as read, self.assertRaises(module.PreflightError):
            module.verify_backend_role(context, arn.replace("123456789012", "999999999999"))
        read.assert_not_called()
        with patch.object(module, "aws_read", side_effect=module.PreflightError("sensitive raw error")), self.assertRaisesRegex(module.PreflightError, "iam:GetRole") as caught:
            module.verify_backend_role(context, arn)
        self.assertNotIn("sensitive", str(caught.exception))

    def test_missing_tools_are_aggregated_without_executing_or_installing(self):
        with patch.object(module.shutil, "which", side_effect=lambda tool: "/bin/" + tool if tool in {"aws", "jq"} else None), patch.object(module.subprocess, "run") as run:
            result = module.local_prerequisites()
        run.assert_not_called()
        self.assertEqual(result["missing_by_stage"]["infrastructure"], ["terraform", "shasum", "grep"])
        self.assertIn("session-manager-plugin", result["missing_by_stage"]["ops_access"])
        self.assertIn("vault", result["missing_by_stage"]["vault"])
        self.assertEqual(result["versions"], "not_verified")

    def test_installed_tools_do_not_imply_runtime_readiness(self):
        with patch.object(module.shutil, "which", return_value="/bin/tool"):
            result = module.local_prerequisites()
        self.assertTrue(all(not missing for missing in result["missing_by_stage"].values()))
        self.assertEqual(result["runtime_health"], "not_verified")

    def test_discovery_does_not_claim_apply_permission(self):
        responses = [{"Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/operator/session"},
                     {"AvailabilityZones": [{"ZoneName": "ap-northeast-1c", "State": "available"}, {"ZoneName": "ap-northeast-1a", "State": "available"}]},
                     {"clusters": ["test-node"]}, [], [], [], ["test-node-foundation-flow-logs", "test-node-baseline-eks-cluster", "unrelated-role"],
                     {"Quota": {"QuotaCode": "L-0263D0A3", "ServiceCode": "ec2", "Value": 5}}, []]
        with patch.object(module, "aws_read", side_effect=responses) as read:
            result = module.discover("test", "ap-northeast-1", "test-node")
        self.assertEqual(result["availability_zones"], ["ap-northeast-1a", "ap-northeast-1c"])
        self.assertTrue(result["cluster_name_present"])
        self.assertEqual(result["provisioning_permissions"], "not_verified")
        self.assertEqual(result["iam_role_collisions"]["deployment_role_name_conflicts"], ["test-node-baseline-eks-cluster", "test-node-foundation-flow-logs"])
        self.assertEqual(result["configuration_recorder"], {"result": "recorder_absent_verified", "existing_count": 0, "manage_config_recorder": True, "existing_recorder_adoption": "not_authorized"})
        self.assertEqual(result["iam_role_collisions"]["iam_permissions"], "not_verified")
        self.assertEqual([c.args[2][0] for c in read.call_args_list], ["sts", "ec2", "eks", "configservice", "s3api", "dynamodb", "iam", "service-quotas", "ec2"])

    def test_configuration_recorder_observation_is_read_only_and_fail_closed(self):
        with patch.object(module, "aws_read", return_value=["node-operator-baseline-config"]) as read:
            existing = module.configuration_recorder_observation("test", "ap-northeast-2")
        self.assertEqual(existing, {"result": "existing_recorder_verified", "existing_count": 1, "manage_config_recorder": False, "existing_recorder_adoption": "not_authorized"})
        self.assertEqual(read.call_args.args[2], ["configservice", "describe-configuration-recorders", "--query", "ConfigurationRecorders[].name"])
        with patch.object(module, "aws_read", return_value=[]):
            absent = module.configuration_recorder_observation("test", "ap-northeast-2")
        self.assertTrue(absent["manage_config_recorder"])
        for response in (None, {}, ["one", "two"], ["bad/name"]):
            with self.subTest(response=response), patch.object(module, "aws_read", return_value=response), self.assertRaises(module.PreflightError):
                module.configuration_recorder_observation("test", "ap-northeast-2")
        with patch.object(module, "aws_read", side_effect=module.PreflightError("denied detail")), self.assertRaisesRegex(module.PreflightError, "could not be read") as error:
            module.configuration_recorder_observation("test", "ap-northeast-2")
        self.assertNotIn("denied detail", str(error.exception))

    def test_elastic_ip_headroom_and_exhaustion_never_mutate(self):
        for allocated, expected in [(0, "sufficient_at_observation"), (4, "sufficient_at_observation"), (5, "requires_capacity_review")]:
            quota = {"Quota": {"QuotaCode": "L-0263D0A3", "ServiceCode": "ec2", "Value": 5.0}}
            with patch.object(module, "aws_read", side_effect=[quota, [f"eipalloc-{i:08x}" for i in range(allocated)]]) as read:
                result = module.elastic_ip_headroom("test", "ap-northeast-1")
            self.assertEqual(result["result"], expected)
            self.assertEqual(result["headroom_lower_bound"], 5 - allocated)
            self.assertFalse(result["reservation_created"])
            self.assertEqual([call.args[2][1] for call in read.call_args_list], ["get-service-quota", "describe-addresses"])

    def test_malformed_quota_or_inventory_is_not_capacity(self):
        for quota in ({}, {"Quota": []}, {"Quota": {"Value": 5}}, {"Quota": {"QuotaCode": "other", "ServiceCode": "ec2", "Value": 5}}):
            with patch.object(module, "aws_read", return_value=quota), self.assertRaises(module.PreflightError):
                module.elastic_ip_headroom("test", "ap-northeast-1")
        for value in (None, True, -1, 1.5, float("nan"), float("inf"), "5"):
            quota = {"Quota": {"QuotaCode": "L-0263D0A3", "ServiceCode": "ec2", "Value": value}}
            with patch.object(module, "aws_read", return_value=quota), self.assertRaises(module.PreflightError):
                module.elastic_ip_headroom("test", "ap-northeast-1")
        quota = {"Quota": {"QuotaCode": "L-0263D0A3", "ServiceCode": "ec2", "Value": 5}}
        for addresses in (None, {}, [None], ["eipalloc-1", "eipalloc-1"]):
            with patch.object(module, "aws_read", side_effect=[quota, addresses]), self.assertRaises(module.PreflightError):
                module.elastic_ip_headroom("test", "ap-northeast-1")

    def test_iam_role_collisions_keep_only_deployment_namespaces(self):
        roles = ["test-node-foundation-flow-logs", "test-node-baseline-vault", "test-node-baseline", "test-node-foundation-flow-logs-extra", "another-baseline-vault"]
        with patch.object(module, "aws_read", return_value=roles) as read:
            result = module.iam_role_collisions("test", "ap-northeast-1", "test-node")
        self.assertEqual(result["deployment_role_name_conflicts"], ["test-node-baseline-vault", "test-node-foundation-flow-logs"])
        self.assertEqual(result["checked_role_namespaces"], {"foundation_flow_logs": "test-node-foundation-flow-logs", "baseline_prefix": "test-node-baseline-"})
        self.assertEqual(result["role_policies"], "not_verified")
        self.assertEqual(read.call_args.args[2], ["iam", "list-roles", "--query", "Roles[].RoleName"])
        self.assertNotIn("--no-paginate", read.call_args.args[2])

    def test_invalid_iam_role_inventory_fails_closed_without_leaking_result(self):
        for response in [None, {}, "role", ["valid-role", 1], ["bad/role"]]:
            with patch.object(module, "aws_read", return_value=response), self.assertRaises(module.PreflightError) as error:
                module.iam_role_collisions("test", "ap-northeast-1", "test-node")
            self.assertEqual(str(error.exception), "AWS IAM role inventory is incomplete; no role name is considered available.")

    def test_backend_collision_does_not_authorize_adoption(self):
        bucket = "test-node-tfstate-123456789012-apnortheast1"
        with patch.object(module, "aws_read", side_effect=[[bucket], ["test-node-terraform-lock"]]):
            result = module.backend_collisions("test", "ap-northeast-1", "test-node", "123456789012")
        self.assertEqual(result["account_owned_bucket_conflicts"], [bucket])
        self.assertEqual(result["regional_table_conflicts"], ["test-node-terraform-lock"])
        self.assertEqual(result["existing_resource_adoption"], "not_authorized")
        self.assertEqual(result["global_bucket_availability"], "not_verified")

    def test_invalid_backend_inventory_is_not_treated_as_empty(self):
        for response in [None, {}, [123], ""]:
            with patch.object(module, "aws_read", side_effect=[response, []]), self.assertRaises(module.PreflightError):
                module.backend_collisions("test", "ap-northeast-1", "test-node", "123456789012")

    def test_invalid_inputs_never_call_aws(self):
        for profile, region, name in [("bad profile", "ap-northeast-1", "test"), ("ok", "us-east-1", "test"), ("ok", "ap-northeast-1", "../bad")]:
            with patch.object(module, "aws_read") as read, self.assertRaises(module.PreflightError):
                module.discover(profile, region, name)
            read.assert_not_called()

    def test_wrong_account_and_root_rejected(self):
        for arn in ["arn:aws:iam::999999999999:role/operator", "arn:aws:iam::123456789012:root"]:
            with patch.object(module, "aws_read", return_value={"Account": "123456789012", "Arn": arn}), self.assertRaises(module.PreflightError):
                module.discover("test", "ap-northeast-1", "test-node")

    def test_profile_is_explicit_and_errors_do_not_leak(self):
        with patch.dict(os.environ, {**dict.fromkeys(module.AWS_CREDENTIAL_OVERRIDES, "unexpected-provider"), "GITHUB_TOKEN": "sentinel", "AWS_SECRET_ACCESS_KEY": "private"}), patch.object(module.shutil, "which", return_value="aws"), patch.object(module.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "secret", "private")) as run:
            with self.assertRaises(module.PreflightError) as error:
                module.aws_read("test", "ap-northeast-1", ["sts", "get-caller-identity"])
            self.assertNotIn("secret", str(error.exception))
            self.assertNotIn("private", str(error.exception))
            self.assertEqual(run.call_args.kwargs["env"]["GITHUB_TOKEN"], "sentinel")
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", run.call_args.kwargs["env"])
            for key in module.AWS_CREDENTIAL_OVERRIDES:
                self.assertNotIn(key, run.call_args.kwargs["env"])
            self.assertEqual(run.call_args.kwargs["env"]["AWS_EC2_METADATA_DISABLED"], "true")
            self.assertEqual(os.environ["AWS_SECRET_ACCESS_KEY"], "private")
            self.assertEqual(run.call_args.args[0][1:5], ["--profile", "test", "--region", "ap-northeast-1"])


if __name__ == "__main__":
    unittest.main()

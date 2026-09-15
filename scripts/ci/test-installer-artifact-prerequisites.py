#!/usr/bin/env python3
# Check objective: Validate installer artifact prerequisites.
"""Offline contract tests for installer_artifact_prerequisites.py."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HELPER_PATH = ROOT / "scripts/release/installer_artifact_prerequisites.py"
SPEC = importlib.util.spec_from_file_location("installer_artifact_prerequisites", HELPER_PATH)
assert SPEC and SPEC.loader
helper = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = helper
SPEC.loader.exec_module(helper)

ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
DEPLOYMENT = "node-operator"
FINGERPRINT = "a" * 64
GITHUB_IDENTITY = ("operator/release", "101", "102")
GITOPS_IDENTITY = ("operator/gitops", "103", "104")


def tags(resource_name: str) -> dict[str, str]:
    return {"Project": "node-operator", "Deployment": DEPLOYMENT,
            "DeploymentRegion": REGION, "ManagedBy": "terraform", "Name": resource_name}


def plan_fixture() -> dict[str, object]:
    repositories, keys, allowed = helper._expected(DEPLOYMENT)
    config, changes = [], []
    for address in sorted(allowed):
        config_row: dict[str, object] = {"address": address, "expressions": {}}
        after: dict[str, object] = {}
        if address in repositories:
            repository_name, kms_label = repositories[address]
            after = {"name": repository_name, "image_tag_mutability": "IMMUTABLE", "tags": tags(repository_name),
                     "image_scanning_configuration": [{"scan_on_push": True}],
                     "encryption_configuration": [{"encryption_type": "KMS" if kms_label else "AES256"}]}
            if kms_label:
                config_row["kms_reference"] = f"aws_kms_key.{kms_label}[0]"
            unknown = {"arn": True, "repository_url": True}
            if kms_label:
                unknown["encryption_configuration"] = [{"kms_key": True}]
        elif address in keys:
            label = keys[address]
            after = {"enable_key_rotation": True, "deletion_window_in_days": 30,
                     "tags": tags(f"{DEPLOYMENT}-baseline-{label.replace('_', '-')}")}
            unknown = {"arn": True}
        elif address == "aws_iam_role.kms_administrator":
            after = {"name": f"{DEPLOYMENT}-baseline-kms-administrator",
                     "tags": tags(f"{DEPLOYMENT}-baseline-kms-administrator")}
            unknown = {"arn": True}
        else:
            config_row["repository_reference"] = address.replace("aws_ecr_lifecycle_policy", "aws_ecr_repository")
            after = {"repository": "known-at-apply"}
            unknown = {}
        config.append(config_row)
        changes.append({"address": address, "mode": "managed", "change": {"actions": ["create"], "after": after, "after_unknown": unknown}})
    return {"format_version": "1.2", "variables": {
        "github_repository": {"value": GITHUB_IDENTITY[0]}, "github_owner_id": {"value": GITHUB_IDENTITY[1]}, "github_repository_id": {"value": GITHUB_IDENTITY[2]},
        "gitops_client_github_repository": {"value": GITOPS_IDENTITY[0]}, "gitops_client_github_owner_id": {"value": GITOPS_IDENTITY[1]}, "gitops_client_github_repository_id": {"value": GITOPS_IDENTITY[2]},
    }, "configuration": {"root_module": {"resources": config, "data_resources": []}},
            "resource_changes": changes, "resource_drift": []}


def state_fixture() -> dict[str, object]:
    repositories, keys, _ = helper._expected(DEPLOYMENT)
    rows: list[dict[str, object]] = []
    kms_arns: dict[str, str] = {}
    for number, (address, label) in enumerate(sorted(keys.items()), 1):
        arn = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/00000000-0000-4000-8000-{number:012d}"
        kms_arns[label] = arn
        rows.append({"address": address, "mode": "managed", "type": "aws_kms_key", "values": {
            "arn": arn, "enable_key_rotation": True, "deletion_window_in_days": 30,
            "tags": tags(f"{DEPLOYMENT}-baseline-{label.replace('_', '-')}")}})
    rows.append({"address": "aws_iam_role.kms_administrator", "mode": "managed", "type": "aws_iam_role", "values": {
        "arn": f"arn:aws:iam::{ACCOUNT}:role/{DEPLOYMENT}-baseline-kms-administrator",
        "name": f"{DEPLOYMENT}-baseline-kms-administrator",
        "tags": tags(f"{DEPLOYMENT}-baseline-kms-administrator")}})
    for address, (repository_name, kms_label) in sorted(repositories.items()):
        encryption = {"encryption_type": "AES256"} if kms_label is None else {"encryption_type": "KMS", "kms_key": kms_arns[kms_label]}
        rows.append({"address": address, "mode": "managed", "type": "aws_ecr_repository", "values": {
            "name": repository_name, "repository_url": f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{repository_name}",
            "arn": f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/{repository_name}", "image_tag_mutability": "IMMUTABLE",
            "image_scanning_configuration": [{"scan_on_push": True}], "encryption_configuration": [encryption],
            "tags": tags(repository_name)}})
    _, _, allowed = helper._expected(DEPLOYMENT)
    for address in sorted(item for item in allowed if item.startswith("aws_ecr_lifecycle_policy.")):
        repository_address = address.replace("aws_ecr_lifecycle_policy", "aws_ecr_repository")
        rows.append({"address": address, "mode": "managed", "type": "aws_ecr_lifecycle_policy", "values": {
            "repository": repositories[repository_address][0], "policy": '{"rules":[]}'}})
    # State may legitimately have foundation resources outside this slice.
    rows.append({"address": "aws_vpc.main", "mode": "managed", "type": "aws_vpc", "values": {"id": "vpc-ignored"}})
    return {"format_version": "1.0", "values": {"root_module": {"resources": rows}}}


def owned_existing_plan(action: str = "no-op") -> dict[str, object]:
    plan = plan_fixture()
    state_rows = state_fixture()["values"]["root_module"]["resources"]
    values = {row["address"]: copy.deepcopy(row["values"]) for row in state_rows if row["address"] != "aws_vpc.main"}
    for change in plan["resource_changes"]:
        change["change"]["actions"] = [action]
        change["change"]["before"] = copy.deepcopy(values[change["address"]])
        change["change"]["after"] = copy.deepcopy(values[change["address"]])
        change["change"]["after_unknown"] = {}
    return plan


class PrerequisiteTests(unittest.TestCase):
    def test_long_publisher_role_names_are_bounded_without_renaming_legacy(self):
        legacy = "node-operator-baseline-github-validator-log-collector-mirror"
        self.assertEqual(helper._publisher_role_name(legacy), legacy)
        first = "node-operator-example-baseline-github-validator-log-collector-mirror"
        second = "node-operator-another-baseline-github-validator-log-collector-mirror"
        self.assertEqual(len(helper._publisher_role_name(first)), 64)
        self.assertNotEqual(helper._publisher_role_name(first), helper._publisher_role_name(second))

    def assert_rejected(self, value: dict[str, object], state: bool = False) -> None:
        with self.assertRaises(helper.PrerequisiteError):
            if state:
                helper.projection(value, ACCOUNT, REGION, DEPLOYMENT, FINGERPRINT)
            else:
                helper.validate_plan(value, ACCOUNT, REGION, DEPLOYMENT)

    def test_valid_plan_permits_exact_targets_and_unrelated_noop(self) -> None:
        plan = plan_fixture()
        plan["resource_changes"].append({"address": "aws_vpc.main", "mode": "managed", "change": {"actions": ["no-op"], "after": {}}})
        helper.validate_plan(plan, ACCOUNT, REGION, DEPLOYMENT)

    def test_existing_owned_noop_and_update_are_accepted(self) -> None:
        helper.validate_plan(owned_existing_plan("no-op"), ACCOUNT, REGION, DEPLOYMENT)
        helper.validate_plan(owned_existing_plan("update"), ACCOUNT, REGION, DEPLOYMENT)

    def test_optional_publisher_closure_requires_exact_roles_and_policies(self) -> None:
        plan = plan_fixture()
        for address, suffix in helper.PUBLISHER_RESOURCES.items():
            row = {"address": address, "expressions": {}}
            if address.startswith("aws_iam_role."):
                subject_key = "StringLike" if suffix in {"github-vault-audit-relay-publisher", "github-gitops-client-ecr-publisher"} else "StringEquals"
                condition = {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}
                condition.setdefault(subject_key, {})["token.actions.githubusercontent.com:sub"] = helper._publisher_subjects(suffix, GITHUB_IDENTITY, GITOPS_IDENTITY)[0]
                if suffix in {"github-vault-audit-relay-publisher", "github-gitops-client-ecr-publisher"}: condition["StringEquals"]["token.actions.githubusercontent.com:repository"] = GITOPS_IDENTITY[0] if suffix == "github-gitops-client-ecr-publisher" else GITHUB_IDENTITY[0]
                after = {"name": f"{DEPLOYMENT}-baseline-{suffix}", "tags": {key: value for key, value in tags("unused").items() if key != "Name"}, "assume_role_policy": json.dumps({"Statement": [{"Effect":"Allow", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": {"Federated": f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"}, "Condition": condition}]})}
            else:
                role_suffix = "github-validator-client-mirror" if "signer_identity_probe" in address else suffix
                resources = [f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/{DEPLOYMENT}-baseline-{item}" for item in helper.PUBLISHER_REPOSITORIES[address]]
                token = {"Effect": "Allow", "Action": ["ecr:GetAuthorizationToken"], "Resource": ["*"]}
                if "signer_identity_probe" in address:
                    statements = [{"Effect":"Allow", "Action":sorted(helper.ECR_PUSH), "Resource":resources}]
                elif address == "aws_iam_role_policy.github_validator_client_mirror[0]":
                    push = [item for item in resources if not item.endswith("validator-signer-identity-probe")]
                    statements = [token, {"Effect":"Allow", "Action":sorted(helper.ECR_PUSH), "Resource":push}, {"Effect":"Allow", "Action":sorted(helper.ECR_READ), "Resource":resources}]
                else:
                    actions = helper.ECR_PUSH | (helper.ECR_READ if address in {"aws_iam_role_policy.github_vault_audit_relay_publisher[0]", "aws_iam_role_policy.github_gitops_client_ecr_publisher[0]"} else frozenset())
                    statements = [token, {"Effect":"Allow", "Action":sorted(actions), "Resource":resources}]
                after = {"name": f"{DEPLOYMENT}-baseline-{suffix}", "role": f"{DEPLOYMENT}-baseline-{role_suffix}", "policy": json.dumps({"Statement": statements})}
            plan["configuration"]["root_module"]["resources"].append(row)
            plan["resource_changes"].append({"address": address, "mode": "managed", "change": {"actions": ["create"], "after": after, "after_unknown": {}}})
        helper.validate_plan(plan, ACCOUNT, REGION, DEPLOYMENT, include_publishers=True)
        # Existing publishers must remain resumable; no-op/update is not adoption.
        for action in ("no-op", "update"):
            resumed = copy.deepcopy(plan)
            for change in resumed["resource_changes"]:
                if change["address"] in helper.PUBLISHER_RESOURCES:
                    change["change"]["before"] = copy.deepcopy(change["change"]["after"])
                    change["change"]["actions"] = [action]
            helper.validate_plan(resumed, ACCOUNT, REGION, DEPLOYMENT, include_publishers=True)
        # Fresh role IDs can be unknown only through the role expression.
        fresh = copy.deepcopy(plan)
        policy_address = "aws_iam_role_policy.github_validator_client_mirror[0]"
        change = next(item for item in fresh["resource_changes"] if item["address"] == policy_address)
        change["change"]["after"]["role"] = None
        change["change"]["after_unknown"]["role"] = True
        row = next(item for item in fresh["configuration"]["root_module"]["resources"] if item["address"] == policy_address)
        row["expressions"] = {"role": {"references": ["aws_iam_role.github_validator_client_mirror[0].id"]}}
        helper.validate_plan(fresh, ACCOUNT, REGION, DEPLOYMENT, include_publishers=True)
        row["expressions"]["role"]["references"] += ["aws_iam_role.github_validator_client_mirror[0]", "aws_iam_role.github_validator_client_mirror"]
        helper.validate_plan(fresh, ACCOUNT, REGION, DEPLOYMENT, include_publishers=True)
        row["expressions"]["role"]["references"].append("aws_iam_role.foreign.id")
        with self.assertRaises(helper.PrerequisiteError):
            helper.validate_plan(fresh, ACCOUNT, REGION, DEPLOYMENT, include_publishers=True)
        row["expressions"]["role"]["references"].pop()
        row["expressions"]["unrelated"] = row["expressions"].pop("role")
        with self.assertRaises(helper.PrerequisiteError):
            helper.validate_plan(fresh, ACCOUNT, REGION, DEPLOYMENT, include_publishers=True)
        # Read-back verification must inspect publisher trust, not just ECR.
        state = state_fixture()
        for item in plan["resource_changes"]:
            if item["address"] in helper.PUBLISHER_RESOURCES:
                state["values"]["root_module"]["resources"].append({"address": item["address"], "mode": "managed", "type": item["address"].split(".")[0], "values": copy.deepcopy(item["change"]["after"])})
        helper.projection(state, ACCOUNT, REGION, DEPLOYMENT, FINGERPRINT, include_publishers=True, github_identity=GITHUB_IDENTITY, gitops_identity=GITOPS_IDENTITY)
        role = next(item for item in state["values"]["root_module"]["resources"] if item["address"] == "aws_iam_role.github_validator_client_mirror[0]")
        role["values"]["assume_role_policy"] = '{"Statement":[]}'
        with self.assertRaises(helper.PrerequisiteError):
            helper.projection(state, ACCOUNT, REGION, DEPLOYMENT, FINGERPRINT, include_publishers=True, github_identity=GITHUB_IDENTITY, gitops_identity=GITOPS_IDENTITY)
        plan["resource_changes"][-1]["change"]["after"]["policy"] = json.dumps({"Statement": [{"Action": "iam:PassRole", "Resource": "*"}]})
        with self.assertRaises(helper.PrerequisiteError):
            helper.validate_plan(plan, ACCOUNT, REGION, DEPLOYMENT, include_publishers=True)
        broad = plan_fixture(); broad["configuration"]["root_module"]["resources"] = plan["configuration"]["root_module"]["resources"][:-1]; broad["resource_changes"] = plan["resource_changes"][:-1]
        trust = next(change for change in broad["resource_changes"] if change["address"] == "aws_iam_role.github_validator_client_mirror[0]")
        trust["change"]["after"]["assume_role_policy"] = json.dumps({"Statement":[{"Effect":"Allow","Action":"sts:AssumeRoleWithWebIdentity","Principal":{"Federated":"*"},"Condition":{}}]})
        with self.assertRaises(helper.PrerequisiteError): helper.validate_plan(broad, ACCOUNT, REGION, DEPLOYMENT, include_publishers=True)

    def test_selected_plan_identity_binds_publisher_trust_and_rejects_wrong_trust(self) -> None:
        plan = plan_fixture()
        plan["variables"] = {
            "github_repository": {"value": "destination-owner/destination-repo"},
            "github_owner_id": {"value": "991"},
            "github_repository_id": {"value": "992"},
            "gitops_client_github_repository": {"value": "gitops-owner/gitops-repo"},
            "gitops_client_github_owner_id": {"value": "993"},
            "gitops_client_github_repository_id": {"value": "994"},
        }
        github, gitops = helper._plan_identities(plan)
        self.assertEqual(github, ("destination-owner/destination-repo", "991", "992"))
        self.assertEqual(gitops, ("gitops-owner/gitops-repo", "993", "994"))
        suffix = "github-gitops-client-ecr-publisher"
        condition = {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:repository": gitops[0]}, "StringLike": {"token.actions.githubusercontent.com:sub": helper._publisher_subjects(suffix, github, gitops)[0]}}
        trust = json.dumps({"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": {"Federated": f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"}, "Condition": condition}]})
        helper._validate_publisher_trust(trust, suffix, ACCOUNT, github, gitops)
        with self.assertRaises(helper.PrerequisiteError):
            helper._validate_publisher_trust(trust, suffix, ACCOUNT, GITHUB_IDENTITY, GITOPS_IDENTITY)
        plan["variables"]["github_owner_id"] = {"value": ""}
        with self.assertRaises(helper.PrerequisiteError):
            helper._plan_identities(plan)

    def test_plan_rejects_foreign_before_and_create_adoption(self) -> None:
        foreign = owned_existing_plan("update")
        key = next(change for change in foreign["resource_changes"] if change["address"] == "aws_kms_key.validator_runtime_ecr[0]")
        key["change"]["before"]["tags"]["Deployment"] = "foreign-deployment"
        self.assert_rejected(foreign)
        foreign_after = owned_existing_plan("update")
        repository = next(change for change in foreign_after["resource_changes"] if change["address"] == 'aws_ecr_repository.validator_runtime["validator-runtime-postgres"]')
        repository["change"]["after"]["encryption_configuration"][0]["kms_key"] = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/00000000-0000-4000-8000-999999999999"
        self.assert_rejected(foreign_after)
        adoption = plan_fixture()
        adoption["resource_changes"][0]["change"]["before"] = {}
        self.assert_rejected(adoption)

    def test_collector_prerequisite_missing_wrong_or_foreign_is_rejected(self) -> None:
        missing = plan_fixture()
        missing["resource_changes"] = [change for change in missing["resource_changes"]
                                       if change["address"] != "aws_ecr_repository.validator_log_collector[0]"]
        self.assert_rejected(missing)
        wrong = plan_fixture()
        repository = next(change for change in wrong["resource_changes"]
                          if change["address"] == "aws_ecr_repository.validator_log_collector[0]")
        repository["change"]["after"]["name"] = "node-operator-baseline-foreign-collector"
        self.assert_rejected(wrong)
        foreign = owned_existing_plan("update")
        repository = next(change for change in foreign["resource_changes"]
                          if change["address"] == "aws_ecr_repository.validator_log_collector[0]")
        repository["change"]["before"]["encryption_configuration"][0]["kms_key"] = (
            f"arn:aws:kms:{REGION}:{ACCOUNT}:key/00000000-0000-4000-8000-999999999999"
        )
        self.assert_rejected(foreign)

    def test_plan_rejects_malformed_foreign_disallowed_and_delete(self) -> None:
        malformed = plan_fixture()
        malformed["configuration"] = []
        self.assert_rejected(malformed)
        foreign = plan_fixture()
        repository_change = next(change for change in foreign["resource_changes"] if change["address"].startswith("aws_ecr_repository."))
        repository_change["change"]["after"]["tags"]["DeploymentRegion"] = "us-east-1"
        self.assert_rejected(foreign)
        disallowed = plan_fixture()
        disallowed["resource_changes"].append({"address": "aws_vpc.main", "mode": "managed", "change": {"actions": ["create"], "after": {}}})
        self.assert_rejected(disallowed)
        deletion = plan_fixture()
        deletion["resource_changes"][0]["change"]["actions"] = ["delete"]
        self.assert_rejected(deletion)

    def test_projection_concrete_binding_and_foreign_rejection(self) -> None:
        state = state_fixture()
        result = helper.projection(state, ACCOUNT, REGION, DEPLOYMENT, FINGERPRINT)
        self.assertEqual(result["state_key"], helper.STATE_KEY)
        self.assertEqual(len(result["repositories"]), len(helper._expected(DEPLOYMENT)[0]))
        foreign = copy.deepcopy(state)
        foreign["values"]["root_module"]["resources"][0]["values"]["arn"] = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001"
        self.assert_rejected(foreign, state=True)

    def test_cli_atomic_private_output_and_no_unsafe_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            state_path = root / "state.json"
            output = root / "artifact-prerequisites.json"
            state_path.write_text(json.dumps(state_fixture()), encoding="utf-8")
            command = [sys.executable, str(HELPER_PATH), "state", "--state", str(state_path), "--account", ACCOUNT,
                       "--region", REGION, "--name", DEPLOYMENT, "--fingerprint", FINGERPRINT, "--output", str(output)]
            self.assertEqual(subprocess.run(command, capture_output=True, text=True).returncode, 0)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            projection = json.loads(output.read_text(encoding="utf-8"))
            self.assertNotIn("values", projection)
            self.assertEqual(subprocess.run(command, capture_output=True, text=True).returncode, 0)
            changed = command.copy(); changed[changed.index("--fingerprint") + 1] = "b" * 64
            self.assertNotEqual(subprocess.run(changed, capture_output=True, text=True).returncode, 0)
            output.unlink()
            output.symlink_to(state_path)
            self.assertNotEqual(subprocess.run(command, capture_output=True, text=True).returncode, 0)

    def test_load_projection_binds_fixed_receipt_inputs_and_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory).resolve()
            work_dir = state_dir / "terraform-work"; work_dir.mkdir(mode=0o700)
            inputs_dir = state_dir / "infrastructure-inputs"; inputs_dir.mkdir(mode=0o700)
            bundle_root = state_dir / "bundle"; bundle_root.mkdir(mode=0o700)
            for filename in ("bootstrap-state.tfvars.json", "foundation-network.tfvars.json", "baseline.tfvars.json"):
                item = inputs_dir / filename; item.write_text('{"fixture":true}', encoding="utf-8"); item.chmod(0o600)
            manifest = bundle_root / "bundle-manifest.json"; manifest.write_text('{"schema_version":"v1"}', encoding="utf-8"); manifest.chmod(0o600)
            fingerprint = helper._projection_fingerprint(inputs_dir, bundle_root)
            checkpoint = work_dir / "zero-inputs.sha256"; checkpoint.write_text(fingerprint, encoding="ascii"); checkpoint.chmod(0o600)
            receipt = helper.projection(state_fixture(), ACCOUNT, REGION, DEPLOYMENT, fingerprint)
            path = work_dir / "artifact-prerequisites.json"
            helper._safe_output(path, receipt)
            discovery = {"aws_account_id": ACCOUNT, "aws_region": REGION, "deployment_name": DEPLOYMENT}
            self.assertEqual(helper.load_projection(path, work_dir, bundle_root, discovery, inputs_dir), receipt)
            tampered = copy.deepcopy(receipt); tampered["repositories"][next(iter(tampered["repositories"]))]["url"] = "foreign"
            path.unlink(); helper._safe_output(path, tampered)
            with self.assertRaises(helper.PrerequisiteError):
                helper.load_projection(path, work_dir, bundle_root, discovery, inputs_dir)


if __name__ == "__main__":
    unittest.main(verbosity=2)

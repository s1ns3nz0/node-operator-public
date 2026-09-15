#!/usr/bin/env python3
# Check objective: Verify validator log collector image rebinding policy.
"""Test exact image rebinding; these fixtures do not prove live admission."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("collector_policy", ROOT / "scripts/release/validator_log_collector_policy.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(module)
OLD = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-fluent-bit@sha256:a5761fa961cb22dd0875883a4d446b1acd99d4935d77358aa9f50ee177e44fe2"
NEW = "123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/other-node-baseline-validator-fluent-bit@" + OLD.split("@")[1]


def fixture():
    return {"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy",
            "metadata": {"name": "node-operator-project-workload-baseline"},
            "spec": {"validationFailureAction": "Enforce", "background": True, "rules": [
                {"name": "restrict-validator-log-collector-hostpath", "validate": {"deny": {"conditions": {"any": [
                    {"key": module.HOST_KEY, "operator": "AnyNotIn", "value": [OLD]},
                    {"key": "other-hostpath-rule", "operator": "NotEquals", "value": 1}]}}}},
                {"name": "require-effective-restricted-runtime-security-context", "validate": {"foreach": [
                    {"list": "request.object.spec.containers[]", "deny": {"conditions": {"all": [
                        {"key": module.ROOT_PREFIX + OLD + module.ROOT_SUFFIX, "operator": "NotEquals", "value": True}]}}}]}},
                {"name": "unrelated-rule", "validate": {"pattern": {"spec": {"hostNetwork": False}}}},
                {"name": "require-private-ecr-image-digest", "validate": {
                    "message": "Containers must use a private ap-northeast-2 ECR image pinned to a SHA-256 digest.",
                    "foreach": [{"list": name, "pattern": {"image": OLD.split("/")[0] + "/*@sha256:" + "?" * 64}}
                                for name in ("request.object.spec.containers[]", "request.object.spec.initContainers || `[]`")]}}
            ]}}


class Rebinding(unittest.TestCase):
    def test_only_two_image_locations_change_without_mutating_input(self):
        original = fixture()
        before = copy.deepcopy(original)
        actual = module.render(original, NEW)
        self.assertEqual(original, before)
        expected = json.loads(json.dumps(before).replace(OLD, NEW).replace(OLD.split("/")[0], NEW.split("/")[0]).replace("private ap-northeast-2 ECR", "private ap-northeast-1 ECR"))
        self.assertEqual(actual, expected)
        self.assertEqual(json.dumps(actual).count(NEW), 2)
        self.assertEqual(module.render(original, OLD), original)

    def test_different_digest_and_non_exact_destinations_are_rejected(self):
        for image in (NEW[:-1] + "0", NEW.split("@")[0] + ":latest", "*", NEW.replace("-baseline-validator-fluent-bit", "-other")):
            with self.subTest(image=image), self.assertRaises(module.CollectorPolicyError):
                module.render(fixture(), image)

    def test_enforcement_ambiguity_and_unexpected_exceptions_are_rejected(self):
        cases = []
        value = fixture(); value["spec"]["validationFailureAction"] = "Audit"; cases.append(value)
        value = fixture(); value["spec"]["rules"].append(copy.deepcopy(value["spec"]["rules"][0])); cases.append(value)
        value = fixture(); value["metadata"]["extra"] = OLD; cases.append(value)
        value = fixture(); value["spec"]["rules"][0]["validate"]["deny"]["conditions"]["any"][0]["value"].append("*"); cases.append(value)
        value = fixture(); value["spec"]["rules"][1]["validate"]["foreach"][0]["deny"]["conditions"]["all"][0]["key"] = "{{ true }}"; cases.append(value)
        value = fixture(); value["spec"]["rules"][1]["validate"]["foreach"][0]["deny"]["conditions"]["all"][0]["value"] = 1; cases.append(value)
        value = fixture(); value["spec"]["rules"][-1]["validate"]["foreach"][0]["pattern"]["image"] = "*@sha256:*"; cases.append(value)
        for value in cases + [{}, None]:
            with self.subTest(value=value), self.assertRaises(module.CollectorPolicyError):
                module.render(value, NEW)

    def test_fixture_tracks_reviewed_source_image_and_expression(self):
        # Drift signal only. The real installer parses and checks the complete
        # release-owned policy before applying; this is not a YAML parser test.
        source = (ROOT / "deploy/kyverno/policies/node-operator-project-workload-baseline.yaml").read_text()
        self.assertEqual(source.count(OLD), 2)
        self.assertIn(module.HOST_KEY, source)
        self.assertIn(module.ROOT_PREFIX + OLD + module.ROOT_SUFFIX, source)


if __name__ == "__main__":
    unittest.main()

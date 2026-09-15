#!/usr/bin/env python3
"""Check objective: Bound KMS discovery without suppressing target read failures."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "reconcile", Path(__file__).resolve().parents[1] / "release/reconcile-bootstrap-state.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
REGION = "ap-northeast-2"
ACCOUNT = "123456789012"
ARN = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/owned"
TAGS = {"Project": "node-operator", "Deployment": "test", "DeploymentRegion": REGION,
        "ManagedBy": "terraform", "Purpose": "terraform-state-bootstrap"}


class Discovery(unittest.TestCase):
    def run_discovery(self, discovery=None, denied=None, tags=None, metadata_arn=ARN):
        calls = []

        def aws(region, *args):
            self.assertEqual(region, REGION)
            calls.append(args)
            if args[:2] == ("resourcegroupstaggingapi", "get-resources"):
                self.assertEqual(args[2:5], ("--resource-type-filters", "kms:key", "--tag-filters"))
                self.assertEqual(json.loads(args[5]),
                                 [{"Key": key, "Values": [value]} for key, value in sorted(TAGS.items())])
                if denied == "discovery":
                    raise MODULE.AwsError("AccessDenied")
                return discovery if discovery is not None else {"ResourceTagMappingList": [{"ResourceARN": ARN}]}
            self.assertEqual(args[0], "kms")
            self.assertIn(args[1], ("describe-key", "list-resource-tags"))
            self.assertEqual(args[2:], ("--key-id", ARN))
            if denied == args[1]:
                raise MODULE.AwsError("AccessDenied")
            if args[1] == "describe-key":
                return {"KeyMetadata": {"Arn": metadata_arn, "KeyId": "owned",
                                        "KeyState": "Enabled", "KeyManager": "CUSTOMER"}}
            return {"Tags": [{"TagKey": key, "TagValue": value}
                             for key, value in (TAGS if tags is None else tags).items()]}

        with patch.object(MODULE, "aws", side_effect=aws):
            result = MODULE.kms_keys_with_tags(REGION, TAGS, ACCOUNT)
        return result, calls

    def test_only_filtered_owned_key_is_read(self):
        result, calls = self.run_discovery()
        self.assertEqual(result, [{"arn": ARN, "id": "owned"}])
        self.assertEqual(len(calls), 3)  # No account-wide ListKeys or foreign DescribeKey.

    def test_absent_resources(self):
        result, calls = self.run_discovery({"ResourceTagMappingList": []})
        self.assertEqual(result, [])
        self.assertEqual(len(calls), 1)

    def test_target_and_discovery_denials_are_fatal(self):
        for denied in ("discovery", "describe-key", "list-resource-tags"):
            with self.subTest(denied=denied), self.assertRaises(MODULE.AwsError):
                self.run_discovery(denied=denied)

    def test_malformed_incomplete_foreign_and_changed_ownership_rejected(self):
        for discovery in ({}, {"ResourceTagMappingList": None},
                          {"ResourceTagMappingList": [], "PaginationToken": "more"},
                          {"ResourceTagMappingList": [{"ResourceARN": ARN.replace(ACCOUNT, "999999999999")}]}):
            with self.subTest(discovery=discovery), self.assertRaises(MODULE.AwsError):
                self.run_discovery(discovery)
        with self.assertRaises(MODULE.AwsError):
            self.run_discovery(tags={"Project": "foreign"})
        with self.assertRaises(MODULE.AwsError):
            self.run_discovery(metadata_arn=ARN + "-other")

    def test_multiple_candidates_are_not_silently_collapsed(self):
        result, _ = self.run_discovery({"ResourceTagMappingList": [{"ResourceARN": ARN}] * 2})
        self.assertEqual(len(result), 2)  # Main rejects ambiguity rather than choosing one.


if __name__ == "__main__":
    unittest.main()

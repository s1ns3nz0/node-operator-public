#!/usr/bin/env python3
# Check objective: Verify the isolated Vault recovery KMS grant helper with synthetic dependencies.
"""Mocked unit tests for the isolated vault recovery KMS grant helper."""
from __future__ import annotations

import datetime as dt
import importlib.util
import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import subprocess
from unittest.mock import patch

sys.dont_write_bytecode = True

SCRIPT = Path(__file__).parents[1] / "ops" / "manage-isolated-vault-recovery-grant.py"
POLICY = Path(__file__).parents[2] / "deploy" / "vault" / "bootstrap" / "isolated-recovery-grant-session-policy.json"
SPEC = importlib.util.spec_from_file_location("recovery_grant", SCRIPT)
assert SPEC and SPEC.loader
grant = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(grant)


def grant_id(character: str = "a") -> str:
    return character * 64


def approved(identifier: str = "a") -> dict:
    return {"GrantId": grant_id(identifier), "Name": grant.NAME, "GranteePrincipal": grant.GRANTEE, "Operations": list(grant.OPERATIONS), "Constraints": {}}


class GrantLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.identity = {"Account": grant.ACCOUNT, "Arn": grant.IDENTITY_PREFIX + "unit-test"}
        self.grants: list[dict] = []
        self.clock = patch.object(grant, "now_utc", return_value=grant.EXPIRY - dt.timedelta(seconds=1))
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def fake_json(self, _profile: str, *args: str) -> dict:
        if args[:2] == ("sts", "get-caller-identity"):
            return self.identity
        if args[:2] == ("kms", "list-grants"):
            return {"Grants": self.grants}
        raise AssertionError(args)

    def fake_aws(self, _profile: str, *args: str) -> str:
        self.calls.append(args)
        if args[:2] == ("kms", "create-grant"):
            return grant_id("b") + "\n"
        if args[:2] == ("kms", "revoke-grant"):
            return ""
        raise AssertionError(args)

    def run_main(self, args: list[str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            result = grant.main(args)
        return result, out.getvalue(), err.getvalue()

    def test_wrong_identity_and_account_refuse_mutation(self) -> None:
        self.identity["Arn"] = "arn:aws:sts::123456789012:assumed-role/wrong/session"
        with patch.object(grant, "aws_json", self.fake_json), patch.object(grant, "aws", self.fake_aws):
            code, _out, err = self.run_main(["--profile", "admin", "--mode", "create"])
        self.assertEqual(code, 1); self.assertIn("required KMS-administrator", err); self.assertEqual(self.calls, [])
        self.identity = {"Account": "000000000000", "Arn": grant.IDENTITY_PREFIX + "x"}
        with patch.object(grant, "aws_json", self.fake_json), patch.object(grant, "aws", self.fake_aws):
            self.assertEqual(self.run_main(["--profile", "admin", "--mode", "revoke"])[0], 1)
        self.assertEqual(self.calls, [])

    def test_expired_refuses_before_identity_or_mutation(self) -> None:
        with patch.object(grant, "now_utc", return_value=grant.EXPIRY), patch.object(grant, "aws_json", self.fake_json), patch.object(grant, "aws", self.fake_aws):
            code, _out, err = self.run_main(["--profile", "admin", "--mode", "create"])
        self.assertEqual(code, 1); self.assertIn("expired", err); self.assertEqual(self.calls, [])

    def test_wrong_grantee_or_operations_refuse_reuse(self) -> None:
        bad_grantee = approved(); bad_grantee["GranteePrincipal"] = "arn:aws:iam::123456789012:role/other"
        bad_ops = approved(); bad_ops["Operations"] = ["Decrypt"]
        for item in (bad_grantee, bad_ops):
            self.grants = [item]
            with patch.object(grant, "aws_json", self.fake_json), patch.object(grant, "aws", self.fake_aws):
                code, _out, err = self.run_main(["--profile", "admin", "--mode", "create"])
            self.assertEqual(code, 1); self.assertIn("does not match", err); self.assertEqual(self.calls, [])

    def test_create_idempotency_and_lost_response_recovery(self) -> None:
        self.grants = [approved("c")]
        with patch.object(grant, "aws_json", self.fake_json), patch.object(grant, "aws", self.fake_aws):
            code, out, _err = self.run_main(["--profile", "admin", "--mode", "create"])
        self.assertEqual((code, self.calls), (0, [])); self.assertIn(grant_id("c"), out)
        responses = [[], [approved("d")]]
        def lists(_profile: str, *args: str) -> dict:
            if args[:2] == ("sts", "get-caller-identity"): return self.identity
            return {"Grants": responses.pop(0)}
        with patch.object(grant, "aws_json", lists), patch.object(grant, "aws", side_effect=grant.SafeError("AWS CLI command failed")):
            code, out, _err = self.run_main(["--profile", "admin", "--mode", "create"])
        self.assertEqual(code, 0); self.assertIn(grant_id("d"), out)

    def test_create_refuses_multiple_matching_named_grants(self) -> None:
        self.grants = [approved("a"), approved("b")]
        with patch.object(grant, "aws_json", self.fake_json), patch.object(grant, "aws", self.fake_aws):
            code, _out, err = self.run_main(["--profile", "admin", "--mode", "create"])
        self.assertEqual(code, 1); self.assertIn("multiple approved grants", err); self.assertEqual(self.calls, [])
        responses = [[], [approved("c"), approved("d")]]
        def lists(_profile: str, *args: str) -> dict:
            if args[:2] == ("sts", "get-caller-identity"): return self.identity
            return {"Grants": responses.pop(0)}
        with patch.object(grant, "aws_json", lists), patch.object(grant, "aws", side_effect=grant.SafeError("AWS CLI command failed")):
            code, _out, err = self.run_main(["--profile", "admin", "--mode", "create"])
        self.assertEqual(code, 1); self.assertIn("multiple approved grants", err)

    def test_plan_default_is_dry_run(self) -> None:
        with patch.object(grant, "aws_json", self.fake_json), patch.object(grant, "aws", self.fake_aws):
            code, out, _err = self.run_main(["--profile", "admin"])
        self.assertEqual(code, 0); self.assertIn("no mutation", out); self.assertEqual(self.calls, [])

    def test_revoke_only_exact_named_ids_and_no_secret_errors(self) -> None:
        self.grants = [approved("1"), approved("2"), {**approved("3"), "Name": "unrelated"}]
        with patch.object(grant, "aws_json", self.fake_json), patch.object(grant, "aws", self.fake_aws):
            code, _out, _err = self.run_main(["--profile", "admin", "--mode", "revoke"])
        self.assertEqual(code, 0)
        self.assertEqual([call[-1] for call in self.calls], [grant_id("1"), grant_id("2")])
        self.grants = [approved("4")]
        raw_failure = subprocess.CalledProcessError(1, ["aws"], stderr="token=secret")
        with patch.object(grant, "aws_json", self.fake_json), patch.object(grant.subprocess, "run", side_effect=raw_failure):
            code, _out, err = self.run_main(["--profile", "admin", "--mode", "revoke"])
        self.assertEqual(code, 1); self.assertNotIn("secret", err); self.assertIn("AWS CLI command failed", err)

    def test_malformed_identity_grant_id_or_truncated_listing_refuse_mutation(self) -> None:
        self.identity["Arn"] = grant.IDENTITY_PREFIX
        with patch.object(grant, "aws_json", self.fake_json), patch.object(grant, "aws", self.fake_aws):
            self.assertEqual(self.run_main(["--profile", "admin", "--mode", "revoke"])[0], 1)
        self.identity["Arn"] = grant.IDENTITY_PREFIX + "session"
        malformed = approved("5"); malformed["GrantId"] = "not-a-grant-id"
        self.grants = [malformed]
        with patch.object(grant, "aws_json", self.fake_json), patch.object(grant, "aws", self.fake_aws):
            self.assertEqual(self.run_main(["--profile", "admin", "--mode", "revoke"])[0], 1)
        def truncated(_profile: str, *args: str) -> dict:
            if args[:2] == ("sts", "get-caller-identity"): return self.identity
            return {"Grants": [], "NextMarker": "more"}
        with patch.object(grant, "aws_json", truncated), patch.object(grant, "aws", self.fake_aws):
            self.assertEqual(self.run_main(["--profile", "admin", "--mode", "revoke"])[0], 1)
        self.assertEqual(self.calls, [])

    def test_pinned_endpoint_and_timeout_are_used(self) -> None:
        completed = subprocess.CompletedProcess(["aws"], 0, stdout="{}", stderr="")
        with patch.object(grant.subprocess, "run", return_value=completed) as run:
            self.assertEqual(grant.aws("admin", "kms", "list-grants"), "{}")
        command = run.call_args.args[0]
        self.assertIn("https://kms.ap-northeast-2.amazonaws.com", command)
        self.assertEqual(run.call_args.kwargs["timeout"], grant.AWS_TIMEOUT_SECONDS)

    def test_session_policy_has_only_approved_key_actions_and_create_constraints(self) -> None:
        policy = json.loads(POLICY.read_text())
        statements = {statement["Sid"]: statement for statement in policy["Statement"]}
        inspect = statements["InspectAndRevokeOnlyReviewedSealKeyGrants"]
        create = statements["CreateOnlyReviewedRecoveryHostGrant"]
        self.assertEqual(inspect["Resource"], grant.KEY_ARN)
        self.assertEqual(set(inspect["Action"]), {"kms:DescribeKey", "kms:ListGrants", "kms:RevokeGrant"})
        self.assertEqual(create["Resource"], grant.KEY_ARN)
        self.assertEqual(create["Action"], "kms:CreateGrant")
        self.assertEqual(create["Condition"]["StringEquals"]["kms:GranteePrincipal"], grant.GRANTEE)
        self.assertEqual(set(create["Condition"]["ForAllValues:StringEquals"]["kms:GrantOperations"]), set(grant.OPERATIONS))
        self.assertEqual(create["Condition"]["DateLessThan"]["aws:CurrentTime"], "2026-09-10T12:00:00Z")
        all_actions = {action for statement in policy["Statement"] for action in ([statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"])}
        self.assertEqual(all_actions, {"kms:DescribeKey", "kms:ListGrants", "kms:RevokeGrant", "kms:CreateGrant"})


if __name__ == "__main__":
    unittest.main()

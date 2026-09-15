#!/usr/bin/env python3
# Check objective: Verify the isolated Vault recovery-grant administration session with mocks.
"""Mocked tests for the isolated vault recovery-grant session wrapper."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).parents[1] / "ops" / "with-isolated-vault-grant-admin.py"
SPEC = importlib.util.spec_from_file_location("grant_admin", SCRIPT)
assert SPEC and SPEC.loader
admin = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(admin)


def credentials() -> dict[str, str]:
    return {"AccessKeyId": "ASIA" + "A" * 16, "SecretAccessKey": "s" * 40, "SessionToken": "t" * 32}


class IsolatedGrantAdminTests(unittest.TestCase):
    def run_main(self, args: list[str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = admin.main(args)
        return code, out.getvalue(), err.getvalue()

    def fake_source(self, _profile: str, *arguments: str) -> dict:
        if arguments[0] == "get-caller-identity":
            return {"Account": admin.ACCOUNT, "Arn": "arn:aws:iam::123456789012:user/test"}
        if arguments[0] == "assume-role":
            return {"Credentials": credentials()}
        raise AssertionError(arguments)

    def test_policy_and_assume_request_are_exact(self) -> None:
        calls: list[tuple[str, tuple[str, ...]]] = []
        def source(profile: str, *arguments: str) -> dict:
            calls.append((profile, arguments))
            return self.fake_source(profile, *arguments)
        with patch.object(admin, "source_aws_json", source), patch.object(admin, "invoke_helper", return_value="plan: none; no mutation performed; expiry=2026-09-10T12:00:00Z"):
            self.assertEqual(self.run_main([])[0], 0)
        self.assertEqual(calls[0], ("default", ("get-caller-identity",)))
        assume = calls[1][1]
        self.assertEqual(assume[:8], ("assume-role", "--role-arn", admin.ROLE_ARN, "--role-session-name", admin.ROLE_SESSION_NAME, "--duration-seconds", "900", "--policy"))
        self.assertEqual(assume[8], admin.SESSION_POLICY.read_text(encoding="utf-8"))

    def test_wrong_account_never_assumes_or_runs_child(self) -> None:
        with patch.object(admin, "source_aws_json", return_value={"Account": "000000000000"}) as source, patch.object(admin, "invoke_helper") as child:
            code, _out, err = self.run_main([])
        self.assertEqual(code, 1); self.assertIn("approved AWS account", err)
        self.assertEqual(source.call_count, 1); child.assert_not_called()

    def test_absent_or_invalid_credentials_never_run_child(self) -> None:
        for response in ({}, {"Credentials": {}}, {"Credentials": {**credentials(), "SessionToken": "bad"}}):
            with patch.object(admin, "source_aws_json", side_effect=[{"Account": admin.ACCOUNT}, response]), patch.object(admin, "invoke_helper") as child:
                code, _out, err = self.run_main([])
            self.assertEqual(code, 1); self.assertIn("invalid credentials", err); child.assert_not_called()

    def test_mode_passthrough_and_default_plan(self) -> None:
        for args, mode in (([], "plan"), (["--mode", "create"], "create"), (["--mode", "revoke", "--source-profile", "source"], "revoke")):
            with patch.object(admin, "source_aws_json", self.fake_source), patch.object(admin, "invoke_helper", return_value="safe") as child:
                self.assertEqual(self.run_main(args)[0], 0)
            self.assertEqual(child.call_args.args[0], mode)

    def test_child_env_permissions_and_cleanup(self) -> None:
        seen: dict[str, object] = {}
        with TemporaryDirectory() as parent:
            scratch = Path(parent) / "scratch"
            def fake_mkdtemp(**_kwargs: object) -> str:
                scratch.mkdir()
                return str(scratch)
            def child_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                env = kwargs["env"]; assert isinstance(env, dict)
                credential_file = Path(str(env["AWS_SHARED_CREDENTIALS_FILE"]))
                config_file = Path(str(env["AWS_CONFIG_FILE"]))
                seen.update({"command": command, "env": env, "credential_file": credential_file, "config_file": config_file, "dir_mode": stat.S_IMODE(scratch.stat().st_mode), "credentials_mode": stat.S_IMODE(credential_file.stat().st_mode), "config_mode": stat.S_IMODE(config_file.stat().st_mode), "content": credential_file.read_text()})
                return subprocess.CompletedProcess(command, 0, "plan: none; no mutation performed; expiry=2026-09-10T12:00:00Z\n", "raw error secret")
            ambient = {"AWS_ACCESS_KEY_ID": "ambient", "AWS_SECRET_ACCESS_KEY": "ambient-secret", "AWS_ROLE_ARN": "role", "AWS_WEB_IDENTITY_TOKEN_FILE": "token", "AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://bad", "AWS_ENDPOINT_URL": "http://bad", "AWS_DEBUG": "1"}
            with patch.dict(os.environ, ambient, clear=False), patch.object(admin.tempfile, "mkdtemp", fake_mkdtemp), patch.object(admin.subprocess, "run", child_run):
                self.assertEqual(admin.invoke_helper("plan", {"aws_access_key_id": credentials()["AccessKeyId"], "aws_secret_access_key": credentials()["SecretAccessKey"], "aws_session_token": credentials()["SessionToken"]}), "plan: none; no mutation performed; expiry=2026-09-10T12:00:00Z")
            self.assertFalse(scratch.exists())
        env = seen["env"]; assert isinstance(env, dict)
        self.assertEqual(seen["command"][2:], ["--profile", admin.RECOVERY_PROFILE, "--mode", "plan"])
        self.assertEqual((seen["dir_mode"], seen["credentials_mode"], seen["config_mode"]), (0o700, 0o600, 0o600))
        self.assertNotIn("ambient-secret", seen["content"])
        for key in ambient:
            self.assertNotIn(key, env)
        self.assertEqual(env["AWS_EC2_METADATA_DISABLED"], "true")

    def test_raw_helper_output_and_errors_are_withheld(self) -> None:
        result = subprocess.CompletedProcess(["helper"], 1, "AKIASECRET\n", "token=very-secret")
        with patch.object(admin, "source_aws_json", side_effect=admin.SafeError("AWS source-profile command failed")):
            code, out, err = self.run_main([])
        self.assertEqual(out, "")
        self.assertNotIn("very-secret", err)
        self.assertNotIn("AKIASECRET", err)
        with TemporaryDirectory() as parent:
            scratch = Path(parent) / "scratch"
            def fake_mkdtemp(**_kwargs: object) -> str:
                scratch.mkdir()
                return str(scratch)
            with patch.object(admin.tempfile, "mkdtemp", fake_mkdtemp), patch.object(admin.subprocess, "run", return_value=result):
                with self.assertRaises(admin.SafeError) as raised:
                    admin.invoke_helper("plan", {"aws_access_key_id": credentials()["AccessKeyId"], "aws_secret_access_key": credentials()["SecretAccessKey"], "aws_session_token": credentials()["SessionToken"]})
        self.assertNotIn("very-secret", str(raised.exception))

    def test_source_endpoint_or_debug_override_is_rejected(self) -> None:
        with patch.dict(os.environ, {"AWS_ENDPOINT_URL_STS": "http://bad"}, clear=False):
            with self.assertRaises(admin.SafeError): admin.reject_unsafe_source_environment()
        with patch.dict(os.environ, {"AWS_DEBUG": "1"}, clear=False):
            with self.assertRaises(admin.SafeError): admin.reject_unsafe_source_environment()

    def test_safe_summary_whitelist(self) -> None:
        self.assertEqual(admin.safe_helper_summary("create", "create: GrantId=" + "a" * 64), "create: GrantId=" + "a" * 64)
        with self.assertRaises(admin.SafeError): admin.safe_helper_summary("plan", "plan: none; no mutation performed; expiry=2026-09-10T12:00:00Z\nsecret")

    def test_source_credentials_cannot_override_selected_profile(self) -> None:
        ambient = {"AWS_ACCESS_KEY_ID": "unexpected", "AWS_SECRET_ACCESS_KEY": "do-not-print", "AWS_SESSION_TOKEN": "unexpected", "AWS_ROLE_ARN": "unexpected", "AWS_WEB_IDENTITY_TOKEN_FILE": "unexpected", "AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://unexpected", "AWS_CONFIG_FILE": "/unexpected"}
        with patch.dict(os.environ, ambient, clear=True), patch.object(admin.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "{}")) as run:
            admin.source_aws("default", "get-caller-identity")
        env = run.call_args.kwargs["env"]
        for key in ambient:
            self.assertNotIn(key, env)
        self.assertIn("--profile", run.call_args.args[0])

    def test_cleanup_failure_never_reports_success(self) -> None:
        with TemporaryDirectory() as parent:
            scratch = Path(parent) / "scratch"
            scratch.mkdir()
            material = {"aws_access_key_id": credentials()["AccessKeyId"], "aws_secret_access_key": credentials()["SecretAccessKey"], "aws_session_token": credentials()["SessionToken"]}
            with patch.object(admin.tempfile, "mkdtemp", return_value=str(scratch)), patch.object(admin, "write_private_session_files", return_value=(scratch / "credentials", scratch / "config")), patch.object(admin.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "plan: none; no mutation performed; expiry=2026-09-10T12:00:00Z")), patch.object(admin.shutil, "rmtree", side_effect=OSError("secret error content")):
                with self.assertRaisesRegex(admin.SafeError, "cleanup failed") as raised:
                    admin.invoke_helper("plan", material)
                self.assertNotIn("secret error content", str(raised.exception))

    def test_ceremony_session_is_fixed_command_without_terminal_transcripts(self) -> None:
        document = json.loads((admin.ROOT / "deploy/vault/bootstrap/isolated-recovery-session-document.json").read_text())
        self.assertEqual(document["sessionType"], "Standard_Stream")
        self.assertNotIn("parameters", document)
        inputs = document["inputs"]
        self.assertEqual(inputs["s3BucketName"], "")
        self.assertEqual(inputs["cloudWatchLogGroupName"], "")
        self.assertFalse(inputs["cloudWatchStreamingEnabled"])
        self.assertEqual(inputs["shellProfile"]["linux"], "exec sudo -n /usr/bin/python3 -B /opt/node-operator-isolated-recovery/rehearse-isolated-vault-restore.py --execute")


if __name__ == "__main__":
    unittest.main()

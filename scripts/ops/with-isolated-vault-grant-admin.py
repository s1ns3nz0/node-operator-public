#!/usr/bin/env python3
"""Run the isolated recovery-grant helper with a short, restricted STS session.

The default is the helper's read-only ``plan`` mode.  A recovery grant is not
automatically revoked when this process exits: run this wrapper with
``--mode revoke`` explicitly after the recovery window.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import resource
import signal
import shutil
import subprocess
import sys
import tempfile
from typing import Any

ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
ROLE_ARN = "arn:aws:iam::123456789012:role/node-operator-baseline-kms-administrator"
ROLE_SESSION_NAME = "recovery-grant-admin"
SESSION_DURATION_SECONDS = 900
RECOVERY_PROFILE = "recovery-grant-admin"
AWS_TIMEOUT_SECONDS = 30
HELPER_TIMEOUT_SECONDS = 90
ROOT = Path(__file__).resolve().parents[2]
HELPER = Path(__file__).with_name("manage-isolated-vault-recovery-grant.py")
SESSION_POLICY = ROOT / "deploy" / "vault" / "bootstrap" / "isolated-recovery-grant-session-policy.json"
STS_ENDPOINT = f"https://sts.{REGION}.amazonaws.com"
GRANT_ID_RE = re.compile(r"^[0-9a-f]{64}$")
ACCESS_KEY_RE = re.compile(r"^ASIA[A-Z0-9]{16}$")
SECRET_RE = re.compile(r"^[A-Za-z0-9/+=]{40}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9/+=._-]{16,}$")
PLAN_RE = re.compile(r"^plan: (?:none|[1-9][0-9]* approved named grant\(s\)); no mutation performed; expiry=2026-09-10T12:00:00Z$")
REVOKE_RE = re.compile(r"^(?:revoke: no matching grant found; no mutation performed|revoke: requested revocation for [1-9][0-9]* approved grant\(s\); eventual consistency applies)$")


class SafeError(RuntimeError):
    """A message safe to display without AWS output or credential material."""


def reject_unsafe_source_environment(env: dict[str, str] | None = None) -> None:
    env = os.environ if env is None else env
    if any(key == "AWS_DEBUG" or key.startswith("AWS_ENDPOINT_URL") for key in env):
        raise SafeError("unsafe AWS endpoint or debug environment setting is present")


def source_aws(profile: str, *arguments: str) -> str:
    """Use the selected source profile against only the regional STS endpoint."""
    reject_unsafe_source_environment()
    command = [
        "aws", "--no-cli-pager", "--profile", profile, "--region", REGION,
        "--endpoint-url", STS_ENDPOINT, "sts", *arguments,
    ]
    try:
        env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}
        env.update(AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION, AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off", AWS_EC2_METADATA_DISABLED="true")
        return subprocess.run(command, check=True, text=True, capture_output=True, timeout=AWS_TIMEOUT_SECONDS, env=env).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise SafeError("AWS source-profile command failed") from exc


def source_aws_json(profile: str, *arguments: str) -> dict[str, Any]:
    try:
        data = json.loads(source_aws(profile, *arguments, "--output", "json"))
    except json.JSONDecodeError as exc:
        raise SafeError("AWS source-profile command returned invalid JSON") from exc
    if not isinstance(data, dict):
        raise SafeError("AWS source-profile command returned unexpected JSON")
    return data


def validate_source_identity(profile: str) -> None:
    identity = source_aws_json(profile, "get-caller-identity")
    if identity.get("Account") != ACCOUNT:
        raise SafeError("source profile is not in the approved AWS account")


def assume_restricted_session(profile: str) -> dict[str, str]:
    try:
        policy = SESSION_POLICY.read_text(encoding="utf-8")
    except OSError as exc:
        raise SafeError("restricted session policy is unavailable") from exc
    response = source_aws_json(
        profile, "assume-role", "--role-arn", ROLE_ARN,
        "--role-session-name", ROLE_SESSION_NAME,
        "--duration-seconds", str(SESSION_DURATION_SECONDS), "--policy", policy,
    )
    credentials = response.get("Credentials")
    if not isinstance(credentials, dict):
        raise SafeError("assumed role returned invalid credentials")
    access_key = credentials.get("AccessKeyId")
    secret_key = credentials.get("SecretAccessKey")
    session_token = credentials.get("SessionToken")
    if not (isinstance(access_key, str) and ACCESS_KEY_RE.fullmatch(access_key)
            and isinstance(secret_key, str) and SECRET_RE.fullmatch(secret_key)
            and isinstance(session_token, str) and TOKEN_RE.fullmatch(session_token)):
        raise SafeError("assumed role returned invalid credentials")
    return {
        "aws_access_key_id": access_key,
        "aws_secret_access_key": secret_key,
        "aws_session_token": session_token,
    }


def isolated_child_environment(credentials_file: Path, config_file: Path) -> dict[str, str]:
    """Remove ambient AWS credential providers and retain only the scratch profile."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}
    env.update({
        "AWS_SHARED_CREDENTIALS_FILE": str(credentials_file),
        "AWS_CONFIG_FILE": str(config_file),
        "AWS_PROFILE": RECOVERY_PROFILE,
        "AWS_DEFAULT_REGION": REGION,
        "AWS_REGION": REGION,
        "AWS_PAGER": "",
        "AWS_CLI_AUTO_PROMPT": "off",
        "AWS_EC2_METADATA_DISABLED": "true",
    })
    return env


def write_private_session_files(directory: Path, credentials: dict[str, str]) -> tuple[Path, Path]:
    credentials_file = directory / "credentials"
    config_file = directory / "config"
    credentials_text = (
        "[recovery-grant-admin]\n"
        f"aws_access_key_id = {credentials['aws_access_key_id']}\n"
        f"aws_secret_access_key = {credentials['aws_secret_access_key']}\n"
        f"aws_session_token = {credentials['aws_session_token']}\n"
    )
    # Create both files private from their first inode; chmod below also
    # protects against an unexpectedly permissive inherited umask/platform.
    credentials_fd = os.open(credentials_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    config_fd = os.open(config_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(credentials_fd, "w", encoding="utf-8") as handle:
        handle.write(credentials_text)
    with os.fdopen(config_fd, "w", encoding="utf-8"):
        pass
    os.chmod(credentials_file, 0o600)
    os.chmod(config_file, 0o600)
    return credentials_file, config_file


def safe_helper_summary(mode: str, stdout: str) -> str:
    lines = stdout.splitlines()
    if len(lines) != 1:
        raise SafeError("recovery grant helper returned an unsafe response")
    line = lines[0]
    if mode == "plan" and PLAN_RE.fullmatch(line):
        return line
    if mode == "create":
        prefix = "create: GrantId="
        if line.startswith(prefix) and GRANT_ID_RE.fullmatch(line[len(prefix):]):
            return line
    if mode == "revoke" and REVOKE_RE.fullmatch(line):
        return line
    raise SafeError("recovery grant helper returned an unsafe response")


def invoke_helper(mode: str, credentials: dict[str, str]) -> str:
    directory = Path(tempfile.mkdtemp(prefix="node-operator-recovery-grant-"))
    credentials_file: Path | None = None
    config_file: Path | None = None
    try:
        os.chmod(directory, 0o700)
        credentials_file, config_file = write_private_session_files(directory, credentials)
        try:
            result = subprocess.run(
                [sys.executable, str(HELPER), "--profile", RECOVERY_PROFILE, "--mode", mode],
                check=False, text=True, capture_output=True, timeout=HELPER_TIMEOUT_SECONDS,
                env=isolated_child_environment(credentials_file, config_file),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SafeError("recovery grant helper failed") from exc
        if result.returncode != 0:
            raise SafeError("recovery grant helper failed")
        return safe_helper_summary(mode, result.stdout)
    finally:
        # This directory is created by this process and contains only its two
        # credential files. Never leave session material after any failure.
        try:
            shutil.rmtree(directory)
        except OSError:
            raise SafeError("temporary session cleanup failed; no success reported") from None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Use a restricted STS session for isolated vault recovery-grant administration.")
    parser.add_argument("--source-profile", default="default", help="AWS CLI source profile used only to assume the restricted session")
    parser.add_argument("--mode", choices=("plan", "create", "revoke"), default="plan", help="plan is read-only; revoke must be run explicitly after recovery")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    previous_handler = signal.getsignal(signal.SIGTERM)
    def interrupted(_signum, _frame):
        raise SafeError("session operation interrupted")
    try:
        args = parse_args(argv)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        signal.signal(signal.SIGTERM, interrupted)
        validate_source_identity(args.source_profile)
        credentials = assume_restricted_session(args.source_profile)
        print(invoke_helper(args.mode, credentials))
        return 0
    except SafeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, OSError):
        print("error: session operation failed or was interrupted", file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous_handler)


if __name__ == "__main__":
    raise SystemExit(main())

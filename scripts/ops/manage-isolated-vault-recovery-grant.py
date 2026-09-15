#!/usr/bin/env python3
"""Plan, create, or revoke the narrowly scoped vault recovery KMS grant.

This tool deliberately does not obtain credentials or assume roles.  An
already configured, key-administrator AWS CLI profile is required for every
mode.  The IAM deny boundary is not an expiry mechanism: run ``--mode revoke``
after the recovery window; AWS grant visibility is eventually consistent.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
from typing import Any

ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
KEY_ARN = "arn:aws:kms:ap-northeast-2:123456789012:key/3bc15229-161c-4172-8a61-8ba0149f4890"
GRANTEE = "arn:aws:iam::123456789012:role/node-operator-baseline-vault-recovery"
NAME = "node-operator-vault-recovery-20260909"
EXPIRY = dt.datetime(2026, 9, 10, 12, 0, 0, tzinfo=dt.timezone.utc)
OPERATIONS = ("Encrypt", "Decrypt", "DescribeKey")
IDENTITY_PREFIX = "arn:aws:sts::123456789012:assumed-role/node-operator-baseline-kms-administrator/"
GRANT_ID_RE = re.compile(r"^[0-9a-f]{64}$")
AWS_TIMEOUT_SECONDS = 30


class SafeError(RuntimeError):
    """An error that is safe to print (never contains AWS CLI output)."""


def reject_unsafe_environment(env: dict[str, str] | None = None) -> None:
    env = os.environ if env is None else env
    unsafe = sorted(key for key in env if key == "AWS_DEBUG" or key.startswith("AWS_ENDPOINT_URL"))
    if unsafe:
        raise SafeError("unsafe AWS endpoint or debug environment setting is present")


def aws(profile: str, *arguments: str) -> str:
    """Run the AWS CLI with fixed account-independent transport options.

    stderr is intentionally not surfaced; AWS errors can contain request or
    credential-adjacent details.
    """
    reject_unsafe_environment()
    if not arguments or arguments[0] not in {"sts", "kms"}:
        raise SafeError("unsupported AWS service")
    endpoint = f"https://{arguments[0]}.{REGION}.amazonaws.com"
    command = ["aws", "--no-cli-pager", "--profile", profile, "--region", REGION, "--endpoint-url", endpoint, *arguments]
    try:
        return subprocess.run(command, check=True, text=True, capture_output=True, timeout=AWS_TIMEOUT_SECONDS).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise SafeError("AWS CLI command failed") from exc


def aws_json(profile: str, *arguments: str) -> dict[str, Any]:
    try:
        value = json.loads(aws(profile, *arguments, "--output", "json"))
    except json.JSONDecodeError as exc:
        raise SafeError("AWS CLI returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise SafeError("AWS CLI returned an unexpected JSON value")
    return value


def validate_identity(profile: str) -> None:
    identity = aws_json(profile, "sts", "get-caller-identity")
    arn = identity.get("Arn")
    if identity.get("Account") != ACCOUNT or not isinstance(arn, str) or not arn.startswith(IDENTITY_PREFIX) or not arn[len(IDENTITY_PREFIX):]:
        raise SafeError("profile is not the required KMS-administrator assumed role in the approved account")


def named_grants(profile: str) -> list[dict[str, Any]]:
    response = aws_json(profile, "kms", "list-grants", "--key-id", KEY_ARN)
    # The CLI auto-paginates. A marker here means an incomplete response was
    # returned despite that contract, so never make a decision from it.
    if response.get("NextMarker") or response.get("Truncated") is True:
        raise SafeError("KMS returned an incomplete grants response")
    grants = response.get("Grants")
    if not isinstance(grants, list) or not all(isinstance(grant, dict) for grant in grants):
        raise SafeError("KMS returned an unexpected grants response")
    return [grant for grant in grants if grant.get("Name") == NAME]


def exact_grant(grant: dict[str, Any]) -> bool:
    # Constraints must be absent or empty: recovery access has no hidden
    # encryption-context or other conditions to accidentally broaden/narrow.
    return (
        isinstance(grant.get("GrantId"), str)
        and bool(GRANT_ID_RE.fullmatch(grant["GrantId"]))
        and grant.get("Name") == NAME
        and grant.get("GranteePrincipal") == GRANTEE
        and isinstance(grant.get("Operations"), list)
        and all(isinstance(operation, str) for operation in grant["Operations"])
        and set(grant["Operations"]) == set(OPERATIONS)
        and len(grant["Operations"]) == len(OPERATIONS)
        and grant.get("Constraints") in (None, {})
    )


def validated_named_grants(profile: str) -> list[dict[str, Any]]:
    grants = named_grants(profile)
    if any(not exact_grant(grant) for grant in grants):
        raise SafeError("an existing grant with the recovery name does not match the approved scope")
    return grants


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def create(profile: str) -> str:
    if now_utc() >= EXPIRY:
        raise SafeError("recovery grant window has expired; refusing to create")
    validate_identity(profile)
    existing = validated_named_grants(profile)
    if len(existing) > 1:
        raise SafeError("multiple approved grants share the recovery name; refusing to select one")
    if existing:
        return str(existing[0]["GrantId"])
    try:
        # The CLI query limits its stdout to GrantId, so CreateGrant's
        # GrantToken is never printed, logged, or returned to the caller.
        grant_id = aws(
            profile, "kms", "create-grant", "--key-id", KEY_ARN,
            "--grantee-principal", GRANTEE, "--operations", *OPERATIONS,
            "--name", NAME, "--query", "GrantId", "--output", "text",
        ).strip()
    except SafeError:
        # A timed-out/lost response might still have created the named grant.
        recovered = validated_named_grants(profile)
        if len(recovered) > 1:
            raise SafeError("multiple approved grants share the recovery name; refusing to select one")
        if recovered:
            return str(recovered[0]["GrantId"])
        raise
    if not GRANT_ID_RE.fullmatch(grant_id):
        raise SafeError("CreateGrant returned no GrantId")
    return grant_id


def revoke(profile: str) -> list[str]:
    validate_identity(profile)
    grants = validated_named_grants(profile)
    for grant in grants:
        aws(profile, "kms", "revoke-grant", "--key-id", KEY_ARN, "--grant-id", str(grant["GrantId"]))
    return [str(grant["GrantId"]) for grant in grants]


def plan(profile: str) -> int:
    validate_identity(profile)
    grants = validated_named_grants(profile)
    state = "none" if not grants else f"{len(grants)} approved named grant(s)"
    print(f"plan: {state}; no mutation performed; expiry={EXPIRY.isoformat().replace('+00:00', 'Z')}")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage the bounded isolated vault recovery KMS grant.")
    parser.add_argument("--profile", required=True, help="existing AWS CLI KMS-administrator profile (credentials are not inspected)")
    parser.add_argument("--mode", choices=("plan", "create", "revoke"), default="plan", help="plan is the read-only default")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.mode == "plan":
            return plan(args.profile)
        if args.mode == "create":
            grant_id = create(args.profile)
            # Do not print tokens or raw AWS responses.
            print(f"create: GrantId={grant_id}")
            return 0
        revoked = revoke(args.profile)
        print("revoke: no matching grant found; no mutation performed" if not revoked else f"revoke: requested revocation for {len(revoked)} approved grant(s); eventual consistency applies")
        return 0
    except SafeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

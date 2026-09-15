"""Read-only target discovery. Success is not proof of provisioning permission."""
from __future__ import annotations

import json
import hashlib
import math
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone


class PreflightError(RuntimeError):
    """A non-sensitive actionable preflight failure."""


AWS_CREDENTIAL_OVERRIDES = (
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
    "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_DEFAULT_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
)


def local_prerequisites() -> dict:
    """Report missing stage tools together, without installing or executing them.

    Presence is not a version or runtime-health check. Keep optional custody
    tools separate so a node-only installation need not generate a validator.
    """
    stages = {
        "infrastructure": ("aws", "terraform", "jq", "shasum", "grep"),
        "ops_access": ("aws", "session-manager-plugin", "kubectl", "nc", "mktemp", "unlink"),
        "vault": ("vault", "openssl", "kubectl"),
        "custody": ("curl", "shasum", "tar", "mkdir", "chmod", "find", "gh"),
    }
    available = {tool: shutil.which(tool) is not None
                 for tool in sorted({tool for tools in stages.values() for tool in tools})}
    return {
        "missing_by_stage": {stage: [tool for tool in tools if not available[tool]]
                             for stage, tools in stages.items()},
        "versions": "not_verified",
        "runtime_health": "not_verified",
    }


def validate_inputs(profile: str, region: str, name: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", profile):
        raise PreflightError("Use an AWS profile name containing letters, digits, dots, underscores or hyphens.")
    if region not in {"ap-northeast-1", "ap-northeast-2"}:
        raise PreflightError("Choose ap-northeast-1 or ap-northeast-2.")
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,18}[a-z0-9]", name):
        raise PreflightError("Deployment name must be 3-20 lowercase DNS characters.")


def verify_backend_role(discovery: dict, principal: str) -> dict:
    """Read the exact IAM role identity, without assuming it or reading secrets.

    Existence is not proof of trust, backend access or provisioning authority.
    Keep policy documents and credential material out of the returned evidence.
    """
    account = discovery["aws_account_id"]
    if not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account):
        raise PreflightError("Backend role account is invalid.")
    prefix = f"arn:aws:iam::{account}:role/"
    if not isinstance(principal, str) or not principal.startswith(prefix):
        raise PreflightError("Backend role must belong to the selected AWS account.")
    role_name = principal.rsplit("/", 1)[-1]
    if not re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", role_name):
        raise PreflightError("Backend role name is invalid.")
    try:
        observed = aws_read(discovery["aws_profile"], discovery["aws_region"],
                            ["iam", "get-role", "--role-name", role_name,
                             "--query", "Role.{Arn:Arn,RoleId:RoleId}"])
    except PreflightError as error:
        raise PreflightError("Backend role could not be verified. Check that it exists and the selected profile permits iam:GetRole; no role was created or assumed.") from error
    if (not isinstance(observed, dict) or observed.get("Arn") != principal
            or not isinstance(observed.get("RoleId"), str)
            or not re.fullmatch(r"AROA[A-Z0-9]{12,124}", observed["RoleId"])):
        raise PreflightError("AWS backend role identity does not match the selected role.")
    return {"arn": principal, "role_id": observed["RoleId"],
            "existence": "verified", "assume_role": "not_verified",
            "backend_permissions": "not_verified", "provisioning_permissions": "not_verified"}


def verify_execution_profile(discovery: dict, role: dict, profile: str) -> dict:
    """Bind an existing execution profile to the role verified by discovery.

    STS UserId's role ID binds this session even when it cannot call GetRole.
    No credential values are returned; AWS CLI owns its normal profile cache.
    """
    validate_inputs(profile, discovery["aws_region"], discovery["deployment_name"])
    identity = aws_read(profile, discovery["aws_region"], ["sts", "get-caller-identity"])
    account = discovery["aws_account_id"]
    role_id = role.get("role_id")
    if not isinstance(role_id, str) or not re.fullmatch(r"AROA[A-Z0-9]{12,124}", role_id):
        raise PreflightError("Execution profile requires a previously verified role identity.")
    role_arn = role.get("arn", "")
    if not isinstance(role_arn, str) or not role_arn.startswith(f"arn:aws:iam::{account}:role/"):
        raise PreflightError("Execution role does not belong to the selected account.")
    arn_prefix = f"arn:aws:sts::{account}:assumed-role/{role_arn.rsplit('/', 1)[-1]}/"
    if (not isinstance(identity, dict) or identity.get("Account") != account
            or not isinstance(identity.get("UserId"), str)
            or not identity["UserId"].startswith(role_id + ":")
            or not isinstance(identity.get("Arn"), str)
            or not identity["Arn"].startswith(arn_prefix)
            or not identity["Arn"][len(arn_prefix):]
            or identity["UserId"][len(role_id) + 1:] != identity["Arn"][len(arn_prefix):]):
        raise PreflightError("Execution profile is not a session of the verified deployment role.")
    return {"aws_profile": profile, "role_arn": role_arn, "role_id": role_id,
            "session_identity": "verified", "provisioning_permissions": "not_verified"}


def bootstrap_permission_probe(discovery: dict, role: dict) -> dict:
    """Screen three prerequisite creates, never certify full AWS authorization.

    Supply current time so expired temporary allows cannot appear current.
    Missing IAM context is inconclusive, not a demonstrated effective denial.
    """
    profile, region, name, account = (discovery[key] for key in
        ("aws_profile", "aws_region", "deployment_name", "aws_account_id"))
    validate_inputs(profile, region, name)
    principal = role.get("arn", "")
    if not isinstance(principal, str) or not principal.startswith(f"arn:aws:iam::{account}:role/"):
        raise PreflightError("Permission probe requires the selected same-account role.")
    context = [{"ContextKeyName": "aws:CurrentTime", "ContextKeyValues": [datetime.now(timezone.utc).isoformat()], "ContextKeyType": "date"},
               {"ContextKeyName": "aws:RequestedRegion", "ContextKeyValues": [region], "ContextKeyType": "string"}]
    checks = []
    targets = [("s3:CreateBucket", f"arn:aws:s3:::{name}-tfstate-{account}-{region.replace('-', '')}"),
               ("dynamodb:CreateTable", f"arn:aws:dynamodb:{region}:{account}:table/{name}-terraform-lock"),
               ("iam:CreateRole", f"arn:aws:iam::{account}:role/{name}-foundation-flow-logs")]
    for action, resource in targets:
        try:
            response = aws_read(profile, region, ["iam", "simulate-principal-policy", "--policy-source-arn", principal,
                "--action-names", action, "--resource-arns", resource, "--context-entries", json.dumps(context),
                "--query", "EvaluationResults[].{Action:EvalActionName,Decision:EvalDecision,Missing:MissingContextValues}"])
        except PreflightError:
            checks.append({"action": action, "resource": resource, "result": "unverified", "reason": "simulation_unavailable"})
            continue
        if (not isinstance(response, list) or len(response) != 1 or not isinstance(response[0], dict)
                or response[0].get("Action") != action
                or response[0].get("Decision") not in ("allowed", "implicitDeny", "explicitDeny")
                or not isinstance(response[0].get("Missing"), list)
                or not all(isinstance(item, str) for item in response[0]["Missing"])):
            raise PreflightError("IAM simulation returned an invalid prerequisite result.")
        value = response[0]
        result = "inconclusive" if value["Missing"] else ("allowed_in_simulation" if value["Decision"] == "allowed" else "denied_in_simulation")
        checks.append({"action": action, "resource": resource, "result": result,
                       "decision": value["Decision"], "missing_context": sorted(set(value["Missing"]))})
    return {"checks": checks, "result": "limited_checks_passed" if all(check["result"] == "allowed_in_simulation" for check in checks) else "requires_permission_review",
            "provisioning_permissions": "not_verified", "scope": "three prerequisite creates only; resource policies, session policies and complete deployment actions not verified"}


def backend_collisions(profile: str, region: str, name: str, account: str) -> dict:
    """Check deterministic backend names; never treat foreign S3 names as free.

    AWS CLI pagination must stay enabled. This checks account-owned buckets,
    not global S3 availability, and cannot authorize adoption on resume.
    """
    bucket = f"{name}-tfstate-{account}-{region.replace('-', '')}"
    logs = f"{bucket[:48]}-{hashlib.sha256(bucket.encode()).hexdigest()[:8]}-logs"
    table = f"{name}-terraform-lock"
    buckets = aws_read(profile, region, ["s3api", "list-buckets", "--query", "Buckets[].Name"])
    tables = aws_read(profile, region, ["dynamodb", "list-tables", "--query", "TableNames"])
    for values in (buckets, tables):
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise PreflightError("AWS backend inventory is incomplete; no resource name is considered available.")
    return {
        "account_owned_bucket_conflicts": sorted({bucket, logs}.intersection(buckets)),
        "regional_table_conflicts": [table] if table in tables else [],
        "global_bucket_availability": "not_verified",
        "existing_resource_adoption": "not_authorized",
    }


def iam_role_collisions(profile: str, region: str, name: str) -> dict:
    """Inventory only role names Terraform can derive for this deployment.

    IAM has no role-name-prefix filter, so the AWS CLI's default paginator reads
    list-roles pages and this function retains only the two deployment
    namespaces.  This neither inventories policy attachments nor verifies that
    the caller has every IAM permission required for an apply.
    """
    foundation_flow_logs = f"{name}-foundation-flow-logs"
    baseline_prefix = f"{name}-baseline-"
    roles = aws_read(profile, region, ["iam", "list-roles", "--query", "Roles[].RoleName"])
    if (not isinstance(roles, list)
            or not all(isinstance(role, str)
                       and re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", role)
                       for role in roles)):
        raise PreflightError("AWS IAM role inventory is incomplete; no role name is considered available.")
    return {
        "deployment_role_name_conflicts": sorted({role for role in roles
                                                   if role == foundation_flow_logs
                                                   or role.startswith(baseline_prefix)}),
        "checked_role_namespaces": {
            "foundation_flow_logs": foundation_flow_logs,
            "baseline_prefix": baseline_prefix,
        },
        "role_policies": "not_verified",
        "iam_permissions": "not_verified",
    }


def elastic_ip_headroom(profile: str, region: str) -> dict:
    """Check capacity for the fresh foundation's one NAT Elastic IP.

    Conservatively count every allocated EIP, including customer pools that AWS
    may exclude from this quota. A shortfall therefore requires operator review,
    not automatic deletion or a quota-increase request. No address is printed.
    """
    quota = aws_read(profile, region, ["service-quotas", "get-service-quota",
                     "--service-code", "ec2", "--quota-code", "L-0263D0A3"])
    value = quota.get("Quota", {}) if isinstance(quota, dict) else {}
    if not isinstance(value, dict):
        raise PreflightError("Elastic IP quota response is incomplete; capacity was not verified.")
    limit = value.get("Value")
    if (value.get("QuotaCode") != "L-0263D0A3" or value.get("ServiceCode") != "ec2"
            or type(limit) not in (int, float) or not math.isfinite(limit)
            or limit < 0 or int(limit) != limit):
        raise PreflightError("Elastic IP quota response is incomplete; capacity was not verified.")
    addresses = aws_read(profile, region, ["ec2", "describe-addresses", "--query", "Addresses[].AllocationId"])
    if (not isinstance(addresses, list)
            or not all(isinstance(item, str) and re.fullmatch(r"eipalloc-[0-9a-f]+", item) for item in addresses)
            or len(set(addresses)) != len(addresses)):
        raise PreflightError("Elastic IP allocation inventory is incomplete; capacity was not verified.")
    remaining = int(limit) - len(addresses)
    return {"quota_code": "L-0263D0A3", "limit": int(limit),
            "allocated_upper_bound": len(addresses), "required_for_fresh_foundation": 1,
            "headroom_lower_bound": remaining,
            "result": "sufficient_at_observation" if remaining >= 1 else "requires_capacity_review",
            "reservation_created": False, "other_quotas": "not_verified"}


def configuration_recorder_observation(profile: str, region: str) -> dict:
    """Observe the regional Config recorder without adopting or changing it.

    AWS permits one recorder per Region. A verified existing recorder means the
    baseline must not attempt a second one; an unreadable or malformed
    inventory is never interpreted as absence.
    """
    try:
        recorders = aws_read(profile, region,
                             ["configservice", "describe-configuration-recorders",
                              "--query", "ConfigurationRecorders[].name"])
    except PreflightError as error:
        raise PreflightError("AWS Config recorder inventory could not be read; no recorder ownership was assumed.") from error
    if (not isinstance(recorders, list)
            or len(recorders) > 1
            or not all(isinstance(item, str)
                       and re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", item)
                       for item in recorders)):
        raise PreflightError("AWS Config recorder inventory is incomplete; no recorder ownership was assumed.")
    existing = len(recorders) == 1
    return {
        "result": "existing_recorder_verified" if existing else "recorder_absent_verified",
        "existing_count": len(recorders),
        "manage_config_recorder": not existing,
        "existing_recorder_adoption": "not_authorized",
    }


def aws_read(profile: str, region: str, arguments: list[str]) -> object:
    if shutil.which("aws") is None:
        raise PreflightError("AWS CLI is missing; install it before target discovery.")
    environment = os.environ.copy()
    # Explicit profile must not silently inherit a different credential pair.
    # GitHub credentials and the caller's environment are never modified.
    for key in AWS_CREDENTIAL_OVERRIDES:
        environment.pop(key, None)
    environment["AWS_EC2_METADATA_DISABLED"] = "true"
    environment["AWS_PAGER"] = ""
    environment["AWS_CLI_AUTO_PROMPT"] = "off"
    try:
        result = subprocess.run(
            ["aws", "--profile", profile, "--region", region, "--no-cli-pager", *arguments, "--output", "json"],
            env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=45, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PreflightError("AWS discovery timed out or could not start; check CLI connectivity and retry.") from exc
    if result.returncode:
        raise PreflightError("AWS read-only discovery failed; check the selected profile login and the requested service read permissions. No resources were created.")
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise PreflightError("AWS returned an invalid discovery response.") from exc


def discover(profile: str, region: str, name: str) -> dict:
    validate_inputs(profile, region, name)
    identity = aws_read(profile, region, ["sts", "get-caller-identity"])
    if not isinstance(identity, dict) or not re.fullmatch(r"[0-9]{12}", str(identity.get("Account", ""))):
        raise PreflightError("AWS identity did not provide a valid account ID.")
    account = identity["Account"]
    arn = identity.get("Arn", "")
    if not isinstance(arn, str) or not arn.startswith((f"arn:aws:iam::{account}:", f"arn:aws:sts::{account}:")):
        raise PreflightError("AWS identity account and principal do not match.")
    if arn.endswith(":root"):
        raise PreflightError("Do not deploy using the AWS root identity; select a scoped operator profile.")
    zones = aws_read(profile, region, ["ec2", "describe-availability-zones", "--filters", "Name=state,Values=available"])
    if not isinstance(zones, dict) or not isinstance(zones.get("AvailabilityZones"), list):
        raise PreflightError("AWS availability-zone response is incomplete.")
    available = sorted({z["ZoneName"] for z in zones["AvailabilityZones"]
                        if isinstance(z, dict) and z.get("State") == "available"
                        and re.fullmatch(re.escape(region) + r"[a-z]", str(z.get("ZoneName", "")))})
    if len(available) < 2:
        raise PreflightError("At least two available standard availability zones are required.")
    clusters = aws_read(profile, region, ["eks", "list-clusters"])
    if not isinstance(clusters, dict) or not isinstance(clusters.get("clusters"), list) or not all(isinstance(c, str) for c in clusters["clusters"]):
        raise PreflightError("AWS cluster inventory is incomplete.")
    return {"aws_account_id": account, "aws_profile": profile, "aws_region": region,
            "principal_arn": arn,
            "deployment_name": name, "availability_zones": available[:2],
            "cluster_name_present": name in clusters["clusters"],
            "configuration_recorder": configuration_recorder_observation(profile, region),
            "local_prerequisites": local_prerequisites(),
            "backend_collisions": backend_collisions(profile, region, name, account),
            "iam_role_collisions": iam_role_collisions(profile, region, name),
            "elastic_ip_headroom": elastic_ip_headroom(profile, region),
            "provisioning_permissions": "not_verified", "quotas": "not_verified",
            "other_resource_collisions": "not_verified"}

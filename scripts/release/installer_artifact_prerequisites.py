#!/usr/bin/env python3
"""Fail-closed validator for the pre-EKS artifact Terraform slice.

It intentionally understands only the repository/KMS closure emitted by the
release input generator.  It is not a general Terraform-plan validator.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any


ACCOUNT = re.compile(r"^[0-9]{12}$")
REGION = re.compile(r"^[a-z]{2}-[a-z0-9-]+-[0-9]+$")
NAME = re.compile(r"^[a-z][a-z0-9-]{1,18}[a-z0-9]$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
KMS_ARN = re.compile(r"^arn:aws:kms:([a-z0-9-]+):([0-9]{12}):key/[A-Za-z0-9-]+$")
STATE_KEY = "node-operator/baseline/terraform.tfstate"
PLAN_DATA_READS = {
    "data.aws_iam_policy_document.kms_key_administrator",
    "data.aws_iam_policy_document.validator_client_ecr_key[0]",
    "data.aws_iam_policy_document.validator_log_collector_ecr_key[0]",
    "data.aws_iam_policy_document.validator_runtime_ecr_key[0]",
    "data.aws_iam_policy_document.vault_audit_relay_ecr_key[0]",
}
PRIVATE_GITOPS = {
    "argocd": "gitops-argocd", "argocd_chart": "gitops-argocd/argo-cd",
    "charts": "gitops-charts", "nodes": "gitops-nodes", "vault": "gitops-vault",
    "cert_manager": "gitops-cert-manager", "vault_chart": "gitops-vault/vault",
    "cert_manager_chart": "gitops-cert-manager/cert-manager",
}
PUBLISHER_RESOURCES = {
    "aws_iam_role.github_validator_client_mirror[0]": "github-validator-client-mirror",
    "aws_iam_role.github_validator_log_collector_mirror[0]": "github-validator-log-collector-mirror",
    "aws_iam_role.github_vault_audit_relay_publisher[0]": "github-vault-audit-relay-publisher",
    "aws_iam_role.github_gitops_client_ecr_publisher[0]": "github-gitops-client-ecr-publisher",
    "aws_iam_role_policy.github_validator_client_mirror[0]": "github-validator-client-mirror",
    "aws_iam_role_policy.github_validator_signer_identity_probe_mirror[0]": "github-validator-signer-identity-probe-mirror",
    "aws_iam_role_policy.github_validator_log_collector_mirror[0]": "github-validator-log-collector-mirror",
    "aws_iam_role_policy.github_vault_audit_relay_publisher[0]": "github-vault-audit-relay-publisher",
    "aws_iam_role_policy.github_gitops_client_ecr_publisher[0]": "github-gitops-client-ecr-publisher",
}
PUBLISHER_ENVIRONMENTS = {
    "github-validator-client-mirror": "validator-client-ecr-mirror",
    "github-validator-log-collector-mirror": "validator-log-collector-ecr-mirror",
    "github-vault-audit-relay-publisher": "vault-audit-relay-ecr-publish",
    "github-gitops-client-ecr-publisher": "gitops-client-ecr-publish",
}
PUBLISHER_REPOSITORIES = {
    "aws_iam_role_policy.github_validator_client_mirror[0]": {"validator-prysm", "validator-fence", "validator-signer-identity-probe"},
    "aws_iam_role_policy.github_validator_signer_identity_probe_mirror[0]": {"validator-signer-identity-probe"},
    "aws_iam_role_policy.github_validator_log_collector_mirror[0]": {"validator-fluent-bit"},
    "aws_iam_role_policy.github_vault_audit_relay_publisher[0]": {"vault-audit-relay"},
    "aws_iam_role_policy.github_gitops_client_ecr_publisher[0]": {"gitops-client/node-operator-client"},
}
ECR_PUSH = frozenset({"ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:CompleteLayerUpload", "ecr:DescribeImages", "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart"})
ECR_READ = frozenset({"ecr:GetDownloadUrlForLayer"})


def _publisher_subjects(suffix: str, github_identity: tuple[str, str, str], gitops_identity: tuple[str, str, str]) -> tuple[str, ...]:
    repository, owner_id, repository_id = gitops_identity if suffix == "github-gitops-client-ecr-publisher" else github_identity
    owner, name = repository.split("/", 1)
    return (f"repo:{owner}@{owner_id}/{name}@{repository_id}:environment:{PUBLISHER_ENVIRONMENTS[suffix]}",)


class PrerequisiteError(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PrerequisiteError("duplicate JSON key")
        result[key] = value
    return result


def _read(path: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
            raise PrerequisiteError("input is unsafe")
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle, object_pairs_hook=_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, PrerequisiteError) as error:
        raise PrerequisiteError("Terraform JSON input is unsafe") from error
    if not isinstance(value, dict):
        raise PrerequisiteError("Terraform JSON root is invalid")
    return value


def _context(account: str, region: str, name: str) -> None:
    if not ACCOUNT.fullmatch(account) or not REGION.fullmatch(region) or not NAME.fullmatch(name):
        raise PrerequisiteError("selected deployment identity is invalid")


def _expected(name: str) -> tuple[dict[str, tuple[str, str | None]], dict[str, str], set[str]]:
    prefix = f"{name}-baseline-"
    repositories: dict[str, tuple[str, str | None]] = {
        f'aws_ecr_repository.private_gitops["{key}"]': (prefix + suffix, None)
        for key, suffix in PRIVATE_GITOPS.items()
    }
    repositories.update({
        "aws_ecr_repository.gitops_client[0]": (prefix + "gitops-client", None),
        "aws_ecr_repository.gitops_client_chart[0]": (prefix + "gitops-client/node-operator-client", None),
        'aws_ecr_repository.validator_runtime["validator-runtime-web3signer"]': (prefix + "validator-runtime-web3signer", "validator_runtime_ecr"),
        'aws_ecr_repository.validator_runtime["validator-runtime-postgres"]': (prefix + "validator-runtime-postgres", "validator_runtime_ecr"),
        "aws_ecr_repository.validator_client[0]": (prefix + "validator-prysm", "validator_client_ecr"),
        "aws_ecr_repository.validator_signing_fence[0]": (prefix + "validator-fence", "validator_client_ecr"),
        "aws_ecr_repository.validator_signer_identity_probe[0]": (prefix + "validator-signer-identity-probe", "validator_client_ecr"),
        "aws_ecr_repository.validator_log_collector[0]": (prefix + "validator-fluent-bit", "validator_log_collector_ecr"),
        "aws_ecr_repository.vault_audit_relay[0]": (prefix + "vault-audit-relay", "vault_audit_relay_ecr"),
    })
    keys = {
        "aws_kms_key.validator_runtime_ecr[0]": "validator_runtime_ecr",
        "aws_kms_key.validator_client_ecr[0]": "validator_client_ecr",
        "aws_kms_key.validator_log_collector_ecr[0]": "validator_log_collector_ecr",
        "aws_kms_key.vault_audit_relay_ecr[0]": "vault_audit_relay_ecr",
    }
    lifecycle = {address.replace("aws_ecr_repository", "aws_ecr_lifecycle_policy") for address in repositories if "private_gitops" in address}
    lifecycle.update({"aws_ecr_lifecycle_policy.gitops_client[0]", "aws_ecr_lifecycle_policy.gitops_client_chart[0]"})
    allowed = set(repositories) | set(keys) | lifecycle | {"aws_iam_role.kms_administrator"}
    return repositories, keys, allowed


def _identity(value: Any, label: str) -> tuple[str, str, str]:
    if not isinstance(value, dict) or set(value) != {"repository", "owner_id", "repository_id"}:
        raise PrerequisiteError(f"Terraform plan {label} identity is invalid")
    identity = tuple(value.get(key) for key in ("repository", "owner_id", "repository_id"))
    if not all(isinstance(item, str) for item in identity) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", identity[0]):
        raise PrerequisiteError(f"Terraform plan {label} identity is invalid")
    if not all(re.fullmatch(r"[1-9][0-9]*", item) for item in identity[1:]):
        raise PrerequisiteError(f"Terraform plan {label} identity requires exact numeric IDs")
    return identity


def _plan_identities(plan: dict[str, Any]) -> tuple[tuple[str, str, str], tuple[str, str, str]]:
    values = plan.get("variables")
    if not isinstance(values, dict):
        raise PrerequisiteError("Terraform plan lacks explicit publisher identities")
    def value(name: str) -> Any:
        row = values.get(name)
        return row.get("value") if isinstance(row, dict) and set(row) == {"value"} else None
    github = _identity({"repository": value("github_repository"), "owner_id": value("github_owner_id"), "repository_id": value("github_repository_id")}, "GitHub")
    gitops = _identity({"repository": value("gitops_client_github_repository"), "owner_id": value("gitops_client_github_owner_id"), "repository_id": value("gitops_client_github_repository_id")}, "GitOps")
    return github, gitops


def validate_plan(plan: dict[str, Any], account: str, region: str, name: str, include_publishers: bool = False) -> None:
    _context(account, region, name)
    github_identity, gitops_identity = _plan_identities(plan) if include_publishers else (None, None)
    expected_repositories, expected_keys, allowed = _expected(name)
    if include_publishers:
        allowed = allowed | set(PUBLISHER_RESOURCES)
    configuration = plan.get("configuration")
    root = configuration.get("root_module") if isinstance(configuration, dict) else None
    configured = root.get("resources") if isinstance(root, dict) else None
    if plan.get("format_version") is None or not isinstance(plan.get("resource_changes"), list) or not isinstance(configured, list):
        raise PrerequisiteError("Terraform plan schema is invalid")
    if plan.get("resource_drift") not in (None, []):
        raise PrerequisiteError("Terraform plan contains drift")
    config_rows = {row.get("address"): row for row in configured if isinstance(row, dict) and isinstance(row.get("address"), str)}
    required = set(expected_repositories) | set(expected_keys) | {"aws_iam_role.kms_administrator"}
    required.update(address for address in allowed if address.startswith("aws_ecr_lifecycle_policy."))
    if include_publishers:
        required.update(PUBLISHER_RESOURCES)
    before_values = {
        change["address"]: change["change"].get("before")
        for change in plan["resource_changes"]
        if isinstance(change, dict) and isinstance(change.get("address"), str) and isinstance(change.get("change"), dict)
    }
    after_values = {
        change["address"]: change["change"].get("after")
        for change in plan["resource_changes"]
        if isinstance(change, dict) and isinstance(change.get("address"), str) and isinstance(change.get("change"), dict)
    }
    seen: set[str] = set()
    for change in plan["resource_changes"]:
        if not isinstance(change, dict) or not isinstance(change.get("address"), str) or change.get("previous_address") is not None:
            raise PrerequisiteError("Terraform plan change is invalid")
        address = change["address"]
        detail = change.get("change")
        if not isinstance(detail, dict) or detail.get("importing") not in (None, False):
            raise PrerequisiteError("Terraform plan contains an import")
        actions = detail.get("actions")
        if change.get("mode") == "data":
            after = detail.get("after")
            if address not in PLAN_DATA_READS or actions != ["read"] or _source_row(config_rows, address) is None or not isinstance(after, dict):
                raise PrerequisiteError(f"Terraform plan contains an unexpected data read: {address}")
            if address == "data.aws_iam_policy_document.kms_key_administrator":
                if not _contains_string(after, f"arn:aws:iam::{account}:root"):
                    raise PrerequisiteError("Terraform plan KMS policy read is not account-bound")
            elif not (_contains_string(after, account) and _contains_string(after, f"ecr.{region}.amazonaws.com")):
                raise PrerequisiteError("Terraform plan ECR KMS policy read is not deployment-bound")
            continue
        if change.get("mode") != "managed":
            raise PrerequisiteError("Terraform plan change is invalid")
        # A state resumed by the wrapper can contain unrelated foundation
        # resources.  Their no-op records carry no authority to mutate them;
        # any proposed change remains outside this deliberately tiny slice.
        if address not in allowed:
            if actions == ["no-op"]:
                continue
            raise PrerequisiteError("Terraform plan contains a non-artifact resource")
        if actions not in (["no-op"], ["create"], ["update"]):
            raise PrerequisiteError("Terraform plan contains delete, replacement, or an invalid action")
        if actions == ["create"] and detail.get("before") is not None:
            raise PrerequisiteError("Terraform plan create would adopt an existing prerequisite")
        after = detail.get("after")
        if not isinstance(after, dict):
            raise PrerequisiteError("Terraform plan lacks known prerequisite values")
        source = _source_row(config_rows, address)
        if source is None:
            raise PrerequisiteError("Terraform plan prerequisite lacks source configuration")
        seen.add(address)
        if actions in (["no-op"], ["update"]):
            before = detail.get("before")
            if not isinstance(before, dict):
                raise PrerequisiteError("Terraform plan existing prerequisite lacks prior ownership")
            _validate_before(address, before, expected_repositories, expected_keys, before_values, account, region, name, github_identity, gitops_identity)
        if address in expected_repositories:
            repository_name, kms_label = expected_repositories[address]
            if after.get("name") != repository_name or after.get("image_tag_mutability") != "IMMUTABLE":
                raise PrerequisiteError("Terraform plan ECR identity is invalid")
            _tags(after, account, region, name, repository_name)
            expected_arn = f"arn:aws:ecr:{region}:{account}:repository/{repository_name}"
            expected_url = f"{account}.dkr.ecr.{region}.amazonaws.com/{repository_name}"
            _known_or_unknown(detail, "arn", expected_arn)
            _known_or_unknown(detail, "repository_url", expected_url)
            scan = after.get("image_scanning_configuration")
            encryption = after.get("encryption_configuration")
            if not isinstance(scan, list) or len(scan) != 1 or not isinstance(scan[0], dict) or scan[0].get("scan_on_push") is not True or not isinstance(encryption, list):
                raise PrerequisiteError("Terraform plan ECR configuration is invalid")
            if kms_label is None:
                # The GitOps repositories deliberately rely on ECR's AWS
                # default AES256 setting, so an initial plan represents the
                # block as empty.  State validation below requires concrete
                # AES256 after apply; an explicit non-default plan is refused.
                expressions = source.get("expressions") if isinstance(source, dict) else None
                if encryption == []:
                    if not isinstance(expressions, dict) or "encryption_configuration" in expressions:
                        raise PrerequisiteError("Terraform plan ECR default encryption is invalid")
                elif len(encryption) != 1 or not isinstance(encryption[0], dict) or encryption[0].get("encryption_type") != "AES256":
                    raise PrerequisiteError("Terraform plan ECR encryption is invalid")
            elif len(encryption) != 1 or not isinstance(encryption[0], dict) or encryption[0].get("encryption_type") != "KMS":
                raise PrerequisiteError("Terraform plan ECR encryption is invalid")
            if kms_label is not None:
                known_key = encryption[0].get("kms_key") if encryption else None
                if known_key is not None and (not isinstance(known_key, str) or not KMS_ARN.fullmatch(known_key) or not known_key.startswith(f"arn:aws:kms:{region}:{account}:key/")):
                    raise PrerequisiteError("Terraform plan ECR KMS key is foreign")
                expected_key = after_values.get(f"aws_kms_key.{kms_label}[0]")
                if not isinstance(expected_key, dict) or not isinstance(expected_key.get("arn"), str):
                    expected_key = before_values.get(f"aws_kms_key.{kms_label}[0]")
                if known_key is not None and (not isinstance(expected_key, dict) or known_key != expected_key.get("arn")):
                    raise PrerequisiteError("Terraform plan ECR KMS key is not the exact prerequisite")
                if known_key is None and not _nested_unknown(detail.get("after_unknown"), "encryption_configuration", "kms_key"):
                    raise PrerequisiteError("Terraform plan ECR KMS key is not known or unknown")
            if kms_label is not None and not _contains_string(source, f"aws_kms_key.{kms_label}[0]"):
                raise PrerequisiteError("Terraform plan ECR KMS dependency is invalid")
        elif address in expected_keys:
            label = expected_keys[address]
            if after.get("enable_key_rotation") is not True or after.get("deletion_window_in_days") != 30:
                raise PrerequisiteError("Terraform plan KMS configuration is invalid")
            _known_or_unknown(detail, "arn", None, account=account, region=region)
            _tags(after, account, region, name, f"{name}-baseline-{label.replace('_', '-')}")
        elif address == "aws_iam_role.kms_administrator":
            if after.get("name") != f"{name}-baseline-kms-administrator":
                raise PrerequisiteError("Terraform plan KMS administrator identity is invalid")
            _tags(after, account, region, name, f"{name}-baseline-kms-administrator", include_name=False)
            _known_or_unknown(detail, "arn", f"arn:aws:iam::{account}:role/{name}-baseline-kms-administrator")
        elif address in PUBLISHER_RESOURCES:
            _validate_publisher(address, after, detail, source, account, region, name, github_identity, gitops_identity)
        elif address.startswith("aws_ecr_lifecycle_policy."):
            # The exact address allowlist above limits these to a repository
            # lifecycle policy.  The configuration must still refer to its
            # corresponding repository, rather than a free-form name.
            repository_address = address.replace("aws_ecr_lifecycle_policy", "aws_ecr_repository")
            repository_source = re.sub(r"\[[^][]+\]$", "", repository_address)
            if repository_address not in expected_repositories or not (_contains_string(source, repository_address) or _contains_string(source, repository_source)):
                raise PrerequisiteError("Terraform plan lifecycle dependency is invalid")
    if seen != required:
        raise PrerequisiteError("Terraform plan omitted an exact artifact prerequisite")


def _validate_publisher(address: str, after: dict[str, Any], detail: dict[str, Any], source: dict[str, Any], account: str, region: str, name: str, github_identity: tuple[str, str, str] | None, gitops_identity: tuple[str, str, str] | None) -> None:
    if github_identity is None or gitops_identity is None:
        raise PrerequisiteError("publisher identities are required")
    suffix = PUBLISHER_RESOURCES[address]
    expected_name = f"{name}-baseline-{suffix}"
    if address.startswith("aws_iam_role."):
        expected_name = _publisher_role_name(expected_name)
    if after.get("name") != expected_name:
        raise PrerequisiteError("publisher prerequisite name is invalid")
    if address.startswith("aws_iam_role."):
        _tags(after, account, region, name, expected_name, include_name=False)
        _validate_publisher_trust(after.get("assume_role_policy"), suffix, account, github_identity, gitops_identity)
        return
    role = after.get("role")
    expected_role = _publisher_role_name(f"{name}-baseline-github-validator-client-mirror" if "signer_identity_probe" in address else expected_name)
    policy = after.get("policy")
    role_address = "aws_iam_role.github_validator_client_mirror[0]" if "signer_identity_probe" in address else address.replace("aws_iam_role_policy", "aws_iam_role")
    if role is None and isinstance(detail.get("after_unknown"), dict) and detail["after_unknown"].get("role") is True and _exact_reference(source, role_address + ".id"):
        role = expected_role
    if role != expected_role or not isinstance(policy, str):
        raise PrerequisiteError("publisher inline policy is invalid")
    _validate_publisher_policy(policy, address, account, region, name)


def _publisher_role_name(name: str) -> str:
    return name if len(name) <= 64 else name[:55] + "-" + hashlib.sha256(name.encode()).hexdigest()[:8]


def _exact_reference(value: Any, expected: str) -> bool:
    expressions = value.get("expressions") if isinstance(value, dict) else None
    role = expressions.get("role") if isinstance(expressions, dict) else None
    references = role.get("references") if isinstance(role, dict) else None
    instance = expected.removesuffix(".id")
    resource = re.sub(r"\[[^][]+\]$", "", instance)
    allowed = {expected, instance, resource}
    return isinstance(references, list) and all(isinstance(item, str) for item in references) and expected in references and set(references) <= allowed


def _validate_publisher_trust(raw: Any, suffix: str, account: str, github_identity: tuple[str, str, str], gitops_identity: tuple[str, str, str]) -> None:
    try: value = json.loads(raw, object_pairs_hook=_pairs) if isinstance(raw, str) else None
    except (json.JSONDecodeError, PrerequisiteError): value = None
    statements = value.get("Statement") if isinstance(value, dict) and set(value) <= {"Version", "Statement"} and value.get("Version", "2012-10-17") == "2012-10-17" else None
    if not isinstance(statements, list) or len(statements) != 1 or not isinstance(statements[0], dict): raise PrerequisiteError("publisher OIDC trust is unresolved or invalid")
    row = statements[0]; conditions = row.get("Condition")
    if not set(row) <= {"Sid", "Effect", "Action", "Principal", "Condition"} or ("Sid" in row and not isinstance(row["Sid"], str)) or row.get("Effect") != "Allow" or row.get("Action") not in ("sts:AssumeRoleWithWebIdentity", ["sts:AssumeRoleWithWebIdentity"]) or row.get("Principal") != {"Federated": f"arn:aws:iam::{account}:oidc-provider/token.actions.githubusercontent.com"} or not isinstance(conditions, dict): raise PrerequisiteError("publisher OIDC trust is invalid")
    subject_key = "StringLike" if suffix in {"github-vault-audit-relay-publisher", "github-gitops-client-ecr-publisher"} else "StringEquals"
    expected = {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}
    subjects = _publisher_subjects(suffix, github_identity, gitops_identity)
    expected.setdefault(subject_key, {})["token.actions.githubusercontent.com:sub"] = list(subjects) if len(subjects) > 1 else subjects[0]
    repository = gitops_identity[0] if suffix == "github-gitops-client-ecr-publisher" else (github_identity[0] if suffix == "github-vault-audit-relay-publisher" else None)
    if repository: expected["StringEquals"]["token.actions.githubusercontent.com:repository"] = repository
    if conditions != expected: raise PrerequisiteError("publisher OIDC trust is invalid")


def _validate_publisher_policy(raw: Any, address: str, account: str, region: str, name: str) -> None:
    try: value = json.loads(raw, object_pairs_hook=_pairs) if isinstance(raw, str) else None
    except (json.JSONDecodeError, PrerequisiteError): value = None
    statements = value.get("Statement") if isinstance(value, dict) and set(value) <= {"Version", "Statement"} else None
    expected_count = 3 if address == "aws_iam_role_policy.github_validator_client_mirror[0]" else (1 if address == "aws_iam_role_policy.github_validator_signer_identity_probe_mirror[0]" else 2)
    if not isinstance(statements, list) or len(statements) != expected_count: raise PrerequisiteError("publisher inline policy is unresolved or invalid")
    target = frozenset(f"arn:aws:ecr:{region}:{account}:repository/{name}-baseline-{repo}" for repo in PUBLISHER_REPOSITORIES[address])
    normalized: set[tuple[frozenset[str], frozenset[str]]] = set()
    for row in statements:
        if not isinstance(row, dict) or not set(row) <= {"Sid", "Effect", "Action", "Resource"} or row.get("Effect") != "Allow": raise PrerequisiteError("publisher inline policy is invalid")
        actions, resources = row.get("Action"), row.get("Resource")
        actions = actions if isinstance(actions, list) else [actions]; resources = resources if isinstance(resources, list) else [resources]
        if not all(isinstance(x, str) for x in actions + resources): raise PrerequisiteError("publisher inline policy is invalid")
        normalized.add((frozenset(actions), frozenset(resources)))
    token = (frozenset({"ecr:GetAuthorizationToken"}), frozenset({"*"}))
    if address == "aws_iam_role_policy.github_validator_client_mirror[0]":
        push = frozenset(target - {f"arn:aws:ecr:{region}:{account}:repository/{name}-baseline-validator-signer-identity-probe"})
        expected = {token, (ECR_PUSH, push), (ECR_READ, target)}
    elif address == "aws_iam_role_policy.github_validator_signer_identity_probe_mirror[0]": expected = {(ECR_PUSH, target)}
    elif address in {"aws_iam_role_policy.github_vault_audit_relay_publisher[0]", "aws_iam_role_policy.github_gitops_client_ecr_publisher[0]"}: expected = {token, (ECR_PUSH | ECR_READ, target)}
    else: expected = {token, (ECR_PUSH, target)}
    if normalized != expected: raise PrerequisiteError("publisher inline policy is broadened or foreign")


def _tags(values: dict[str, Any], account: str, region: str, name: str, resource_name: str, include_name: bool = True) -> None:
    tags = values.get("tags")
    expected = {"Project": "node-operator", "Deployment": name, "DeploymentRegion": region, "ManagedBy": "terraform"}
    if include_name:
        expected["Name"] = resource_name
    if not isinstance(tags, dict) or any(tags.get(key) != expected_value for key, expected_value in expected.items()):
        raise PrerequisiteError("state resource ownership tags are invalid")


def _contains_string(value: Any, expected: str) -> bool:
    if isinstance(value, str):
        return value == expected
    if isinstance(value, list):
        return any(_contains_string(item, expected) for item in value)
    if isinstance(value, dict):
        return any(_contains_string(item, expected) for item in value.values())
    return False


def _source_row(rows: dict[Any, dict[str, Any]], address: str) -> dict[str, Any] | None:
    """Map a Terraform instance address to its unindexed configuration row."""
    direct = rows.get(address)
    if isinstance(direct, dict):
        return direct
    canonical = re.sub(r"\[[^][]+\]$", "", address)
    source = rows.get(canonical)
    return source if isinstance(source, dict) else None


def _nested_unknown(value: Any, block: str, attribute: str) -> bool:
    return isinstance(value, dict) and isinstance(value.get(block), list) and len(value[block]) == 1 and isinstance(value[block][0], dict) and value[block][0].get(attribute) is True


def _known_or_unknown(detail: dict[str, Any], field: str, expected: str | None, *, account: str | None = None, region: str | None = None) -> None:
    after = detail.get("after")
    value = after.get(field) if isinstance(after, dict) else None
    if value is None:
        if isinstance(detail.get("after_unknown"), dict) and detail["after_unknown"].get(field) is True:
            return
        raise PrerequisiteError("Terraform plan prerequisite identity is not known or unknown")
    if expected is not None:
        if value != expected:
            raise PrerequisiteError("Terraform plan prerequisite identity is foreign")
        return
    match = KMS_ARN.fullmatch(value) if isinstance(value, str) else None
    if not match or match.group(1) != region or match.group(2) != account:
        raise PrerequisiteError("Terraform plan KMS identity is foreign")


def _validate_before(address: str, before: dict[str, Any], repositories: dict[str, tuple[str, str | None]], keys: dict[str, str], all_before: dict[str, Any], account: str, region: str, name: str, github_identity: tuple[str, str, str] | None, gitops_identity: tuple[str, str, str] | None) -> None:
    """Prove a planned update/no-op continues an owned prerequisite, not adoption."""
    if address in repositories:
        repository_name, kms_label = repositories[address]
        if before.get("name") != repository_name or before.get("arn") != f"arn:aws:ecr:{region}:{account}:repository/{repository_name}" or before.get("repository_url") != f"{account}.dkr.ecr.{region}.amazonaws.com/{repository_name}" or before.get("image_tag_mutability") != "IMMUTABLE":
            raise PrerequisiteError("Terraform plan prior ECR identity is foreign")
        _tags(before, account, region, name, repository_name)
        scan = before.get("image_scanning_configuration")
        encryption = before.get("encryption_configuration")
        if not isinstance(scan, list) or len(scan) != 1 or not isinstance(scan[0], dict) or scan[0].get("scan_on_push") is not True or not isinstance(encryption, list) or len(encryption) != 1 or not isinstance(encryption[0], dict):
            raise PrerequisiteError("Terraform plan prior ECR configuration is invalid")
        if kms_label is None:
            if encryption[0].get("encryption_type") != "AES256":
                raise PrerequisiteError("Terraform plan prior GitOps ECR encryption is invalid")
            return
        key_before = all_before.get(f"aws_kms_key.{kms_label}[0]")
        if not isinstance(key_before, dict) or encryption[0].get("encryption_type") != "KMS" or encryption[0].get("kms_key") != key_before.get("arn"):
            raise PrerequisiteError("Terraform plan prior ECR KMS ownership is invalid")
        return
    if address in keys:
        label = keys[address]
        match = KMS_ARN.fullmatch(before.get("arn")) if isinstance(before.get("arn"), str) else None
        if not match or match.group(1) != region or match.group(2) != account or before.get("enable_key_rotation") is not True or before.get("deletion_window_in_days") != 30:
            raise PrerequisiteError("Terraform plan prior KMS identity is foreign")
        _tags(before, account, region, name, f"{name}-baseline-{label.replace('_', '-')}")
        return
    if address == "aws_iam_role.kms_administrator":
        if before.get("arn") != f"arn:aws:iam::{account}:role/{name}-baseline-kms-administrator" or before.get("name") != f"{name}-baseline-kms-administrator":
            raise PrerequisiteError("Terraform plan prior KMS administrator role is foreign")
        _tags(before, account, region, name, f"{name}-baseline-kms-administrator", include_name=False)
        return
    if address in PUBLISHER_RESOURCES:
        _validate_publisher(address, before, {"after_unknown": {}}, {}, account, region, name, github_identity, gitops_identity)
        return
    repository_address = address.replace("aws_ecr_lifecycle_policy", "aws_ecr_repository")
    repository = repositories.get(repository_address)
    if repository is None or before.get("repository") != repository[0] or not isinstance(before.get("policy"), str):
        raise PrerequisiteError("Terraform plan prior lifecycle policy is foreign")


def _one(resources: dict[str, dict[str, Any]], address: str, kind: str) -> dict[str, Any]:
    item = resources.get(address)
    if not isinstance(item, dict) or item.get("address") != address or item.get("mode") != "managed" or item.get("type") != kind or not isinstance(item.get("values"), dict):
        raise PrerequisiteError("state lacks an exact prerequisite resource")
    return item["values"]


def projection(state: dict[str, Any], account: str, region: str, name: str, fingerprint: str, include_publishers: bool = False, github_identity: tuple[str, str, str] | None = None, gitops_identity: tuple[str, str, str] | None = None) -> dict[str, Any]:
    _context(account, region, name)
    if not SHA256.fullmatch(fingerprint):
        raise PrerequisiteError("input fingerprint is invalid")
    if include_publishers and (github_identity is None or gitops_identity is None):
        raise PrerequisiteError("state publisher validation requires explicit identities")
    values = state.get("values")
    root = values.get("root_module") if isinstance(values, dict) else None
    rows = root.get("resources") if isinstance(root, dict) else None
    if not isinstance(rows, list):
        raise PrerequisiteError("Terraform state has no root resources")
    resources: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("address"), str) or row["address"] in resources:
            raise PrerequisiteError("Terraform state resource inventory is invalid")
        resources[row["address"]] = row
    expected_repositories, expected_keys, allowed = _expected(name)
    kms: dict[str, str] = {}
    for address, label in expected_keys.items():
        item = _one(resources, address, "aws_kms_key")
        arn = item.get("arn")
        match = KMS_ARN.fullmatch(arn) if isinstance(arn, str) else None
        if not match or match.group(1) != region or match.group(2) != account or item.get("enable_key_rotation") is not True or item.get("deletion_window_in_days") != 30:
            raise PrerequisiteError("state KMS prerequisite is invalid")
        _tags(item, account, region, name, f"{name}-baseline-{label.replace('_', '-')}")
        kms[label] = arn
    role = _one(resources, "aws_iam_role.kms_administrator", "aws_iam_role")
    if role.get("arn") != f"arn:aws:iam::{account}:role/{name}-baseline-kms-administrator":
        raise PrerequisiteError("state KMS administrator role is invalid")
    _tags(role, account, region, name, f"{name}-baseline-kms-administrator", include_name=False)
    repositories: dict[str, dict[str, str]] = {}
    for address, (repository_name, kms_label) in expected_repositories.items():
        item = _one(resources, address, "aws_ecr_repository")
        expected_url = f"{account}.dkr.ecr.{region}.amazonaws.com/{repository_name}"
        expected_arn = f"arn:aws:ecr:{region}:{account}:repository/{repository_name}"
        if item.get("name") != repository_name or item.get("repository_url") != expected_url or item.get("arn") != expected_arn or item.get("image_tag_mutability") != "IMMUTABLE":
            raise PrerequisiteError("state ECR prerequisite identity is invalid")
        scan = item.get("image_scanning_configuration")
        if not isinstance(scan, list) or len(scan) != 1 or not isinstance(scan[0], dict) or scan[0].get("scan_on_push") is not True:
            raise PrerequisiteError("state ECR scan configuration is invalid")
        encryption = item.get("encryption_configuration")
        if not isinstance(encryption, list) or len(encryption) != 1 or not isinstance(encryption[0], dict):
            raise PrerequisiteError("state ECR encryption configuration is invalid")
        if kms_label is None:
            if encryption[0].get("encryption_type") != "AES256":
                raise PrerequisiteError("state GitOps ECR encryption is invalid")
            encryption_name = "AES256"
        else:
            if encryption[0].get("encryption_type") != "KMS" or encryption[0].get("kms_key") != kms[kms_label]:
                raise PrerequisiteError("state KMS ECR encryption is invalid")
            encryption_name = kms[kms_label]
        _tags(item, account, region, name, repository_name)
        repositories[repository_name] = {"arn": expected_arn, "url": expected_url, "encryption": encryption_name}
    for address in sorted(item for item in allowed if item.startswith("aws_ecr_lifecycle_policy.")):
        repository_address = address.replace("aws_ecr_lifecycle_policy", "aws_ecr_repository")
        repository_name = expected_repositories[repository_address][0]
        policy = _one(resources, address, "aws_ecr_lifecycle_policy")
        if policy.get("repository") != repository_name or not isinstance(policy.get("policy"), str):
            raise PrerequisiteError("state lifecycle prerequisite is invalid")
        try:
            parsed_policy = json.loads(policy["policy"], object_pairs_hook=_pairs)
        except (json.JSONDecodeError, PrerequisiteError):
            raise PrerequisiteError("state lifecycle policy is invalid") from None
        if not isinstance(parsed_policy, dict):
            raise PrerequisiteError("state lifecycle policy is invalid")
    if include_publishers:
        for address in sorted(PUBLISHER_RESOURCES):
            kind = "aws_iam_role" if address.startswith("aws_iam_role.") else "aws_iam_role_policy"
            item = _one(resources, address, kind)
            _validate_publisher(address, item, {"after_unknown": {}}, {}, account, region, name, github_identity, gitops_identity)
    return {"schema_version": 1, "aws_account_id": account, "aws_region": region, "deployment_name": name,
            "input_fingerprint": fingerprint, "state_key": STATE_KEY, "repositories": repositories, "kms_keys": kms}


def _safe_output(path: Path, value: dict[str, Any]) -> None:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise PrerequisiteError("projection output path is not normalized and absolute")
    parent = path.parent
    for ancestor in (parent, *parent.parents):
        try:
            info = ancestor.lstat()
        except OSError as error:
            raise PrerequisiteError("projection output ancestry is unsafe") from error
        if ancestor.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise PrerequisiteError("projection output ancestry is unsafe")
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if path.exists() or path.is_symlink():
        try:
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or path.read_bytes() != encoded:
                raise PrerequisiteError("projection output already exists and differs")
        except OSError as error:
            raise PrerequisiteError("projection output is unsafe") from error
        return
    try:
        fd, temporary = tempfile.mkstemp(prefix=".artifact-prerequisites-", dir=parent)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded); handle.flush(); os.fsync(handle.fileno())
        os.link(temporary, path)
    except OSError as error:
        raise PrerequisiteError("projection output could not be published") from error
    finally:
        try:
            os.unlink(temporary)
        except (FileNotFoundError, UnboundLocalError):
            pass


def _safe_read(path: Path, *, mode: int | None = None, limit: int = 16 * 1024 * 1024) -> bytes:
    """Read one bounded regular file without following its final path component."""
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size > limit or (mode is not None and stat.S_IMODE(info.st_mode) != mode):
            raise PrerequisiteError("receipt input is unsafe")
        return path.read_bytes()
    except (OSError, PrerequisiteError) as error:
        raise PrerequisiteError("receipt input is unsafe") from error


def _safe_directory(path: Path) -> Path:
    resolved = path.resolve()
    # Receipt roots are caller-supplied trust boundaries.  Do not permit an
    # intermediate symlink to redirect a seemingly in-tree receipt/input.
    if not path.is_absolute() or path != resolved or not resolved.is_dir() or path.is_symlink():
        raise PrerequisiteError("receipt directory is unsafe")
    return resolved


def _within(path: Path, parent: Path) -> None:
    try:
        path.relative_to(parent)
    except ValueError as error:
        raise PrerequisiteError("receipt path escapes its expected directory") from error


def _projection_fingerprint(inputs_dir: Path, bundle_root: Path) -> str:
    names = ("bootstrap-state.tfvars.json", "foundation-network.tfvars.json", "baseline.tfvars.json")
    digests = [hashlib.sha256(_safe_read(inputs_dir / item, mode=0o600)).hexdigest() for item in names]
    digests.append(hashlib.sha256(_safe_read(bundle_root / "bundle-manifest.json", mode=0o600)).hexdigest())
    return hashlib.sha256("".join(f"{digest}\n" for digest in digests).encode("ascii")).hexdigest()


def load_projection(path: Path, work_dir: Path, bundle_root: Path, discovery: dict[str, Any], inputs_dir: Path | None = None) -> dict[str, Any]:
    """Load a receipt only when it is bound to this exact installer invocation.

    This verifies local, private pre-EKS evidence.  It deliberately makes no
    AWS/ECR call and must not be used as proof that an image was mirrored.
    """
    if not isinstance(discovery, dict):
        raise PrerequisiteError("deployment discovery is invalid")
    account, region, name = discovery.get("aws_account_id"), discovery.get("aws_region"), discovery.get("deployment_name")
    if not all(isinstance(value, str) for value in (account, region, name)):
        raise PrerequisiteError("deployment discovery is invalid")
    _context(account, region, name)
    safe_work = _safe_directory(work_dir)
    safe_bundle = _safe_directory(bundle_root)
    expected_path = safe_work / "artifact-prerequisites.json"
    supplied = path.resolve(strict=False)
    if supplied != expected_path:
        raise PrerequisiteError("projection path is not the fixed work receipt")
    _within(expected_path, safe_work)
    raw = _safe_read(expected_path, mode=0o600)
    try:
        receipt = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, PrerequisiteError) as error:
        raise PrerequisiteError("projection receipt is malformed") from error
    if not isinstance(receipt, dict):
        raise PrerequisiteError("projection receipt is malformed")
    safe_inputs = _safe_directory(inputs_dir if inputs_dir is not None else safe_work.parent / "infrastructure-inputs")
    _within(safe_inputs, safe_work.parent if inputs_dir is None else safe_inputs.parent)
    checkpoint = safe_work / "zero-inputs.sha256"
    expected_fingerprint = _projection_fingerprint(safe_inputs, safe_bundle)
    try:
        bound_fingerprint = _safe_read(checkpoint, mode=0o600, limit=128).decode("ascii")
    except UnicodeDecodeError as error:
        raise PrerequisiteError("checkpoint binding is malformed") from error
    if not SHA256.fullmatch(bound_fingerprint) or bound_fingerprint != expected_fingerprint:
        raise PrerequisiteError("checkpoint binding does not match current inputs")
    repositories, keys, _ = _expected(name)
    expected_repositories = {repo_name for repo_name, _ in repositories.values()}
    expected_key_labels = set(keys.values())
    required = {"schema_version", "aws_account_id", "aws_region", "deployment_name", "input_fingerprint", "state_key", "repositories", "kms_keys"}
    if set(receipt) != required or receipt.get("schema_version") != 1 or receipt.get("aws_account_id") != account or receipt.get("aws_region") != region or receipt.get("deployment_name") != name or receipt.get("input_fingerprint") != expected_fingerprint or receipt.get("state_key") != STATE_KEY:
        raise PrerequisiteError("projection receipt binding is invalid")
    receipt_keys, receipt_repositories = receipt.get("kms_keys"), receipt.get("repositories")
    if not isinstance(receipt_keys, dict) or set(receipt_keys) != expected_key_labels or not isinstance(receipt_repositories, dict) or set(receipt_repositories) != expected_repositories:
        raise PrerequisiteError("projection receipt inventory is invalid")
    for label, arn in receipt_keys.items():
        match = KMS_ARN.fullmatch(arn) if isinstance(arn, str) else None
        if not match or match.group(1) != region or match.group(2) != account:
            raise PrerequisiteError("projection receipt KMS binding is invalid")
    for _, (repo_name, kms_label) in repositories.items():
        item = receipt_repositories.get(repo_name)
        expected_arn = f"arn:aws:ecr:{region}:{account}:repository/{repo_name}"
        expected_url = f"{account}.dkr.ecr.{region}.amazonaws.com/{repo_name}"
        expected_encryption = "AES256" if kms_label is None else receipt_keys[kms_label]
        if not isinstance(item, dict) or set(item) != {"arn", "url", "encryption"} or item.get("arn") != expected_arn or item.get("url") != expected_url or item.get("encryption") != expected_encryption:
            raise PrerequisiteError("projection receipt repository binding is invalid")
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("plan", "state"):
        part = sub.add_parser(command)
        part.add_argument(f"--{command}", required=True, type=Path)
        part.add_argument("--account", required=True)
        part.add_argument("--region", required=True)
        part.add_argument("--name", required=True)
        part.add_argument("--include-publishers", action="store_true")
        part.add_argument("--github-repository")
        part.add_argument("--github-owner-id")
        part.add_argument("--github-repository-id")
        part.add_argument("--gitops-client-github-repository")
        part.add_argument("--gitops-client-github-owner-id")
        part.add_argument("--gitops-client-github-repository-id")
    state_args = sub.choices["state"]
    state_args.add_argument("--fingerprint", required=True)
    state_args.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        identities = None
        if args.include_publishers:
            identities = (
                _identity({"repository": args.github_repository, "owner_id": args.github_owner_id, "repository_id": args.github_repository_id}, "GitHub"),
                _identity({"repository": args.gitops_client_github_repository, "owner_id": args.gitops_client_github_owner_id, "repository_id": args.gitops_client_github_repository_id}, "GitOps"),
            )
        if args.command == "plan":
            plan = _read(args.plan)
            if identities is not None and _plan_identities(plan) != identities:
                raise PrerequisiteError("Terraform plan publisher identities differ from explicit inputs")
            validate_plan(plan, args.account, args.region, args.name, args.include_publishers)
        else:
            _safe_output(args.output, projection(_read(args.state), args.account, args.region, args.name, args.fingerprint, args.include_publishers, *(identities or (None, None))))
    except PrerequisiteError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

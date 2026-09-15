"""Fail-closed allowlist validation for Vault bootstrap Terraform plans."""
from __future__ import annotations
from collections import Counter
import re

class VaultPlanError(RuntimeError): pass

_PREPARE = {
 "aws_security_group.vault_bootstrap[0]", "aws_vpc_security_group_ingress_rule.cluster_api_from_vault_bootstrap[0]",
 "aws_vpc_security_group_ingress_rule.endpoints_https_from_vault_bootstrap[0]", "aws_iam_role.vault_bootstrap[0]",
 "aws_iam_role_policy.vault_bootstrap[0]", "aws_cloudwatch_log_group.vault_bootstrap[0]",
 "aws_eks_access_entry.vault_bootstrap[0]", "aws_codebuild_project.vault_bootstrap[0]"}
_ADMIN = "aws_eks_access_policy_association.vault_bootstrap_cluster_admin[0]"

def validate_vault_plan(plan: dict, phase: str) -> dict:
    if phase not in {"prepare", "grant", "revoke"}: raise VaultPlanError("Unknown Vault bootstrap phase.")
    # Terraform 1.5.7's `show -json` output omits applyable/complete/errored.
    # The runner must require a successful plan command; when newer Terraform
    # emits those fields, retain their fail-closed meaning instead of guessing.
    required={"format_version","terraform_version","resource_changes"}
    if (not isinstance(plan,dict) or not required <= set(plan)
            or plan["format_version"] != "1.2" or plan["terraform_version"] != "1.5.7"
            or not isinstance(plan["resource_changes"],list)):
        raise VaultPlanError("Vault plan lacks a complete bounded Terraform JSON schema.")
    if ("resource_drift" in plan and (not isinstance(plan["resource_drift"], list) or plan["resource_drift"])
            or "deferred_changes" in plan
            or "applyable" in plan and type(plan["applyable"]) is not bool
            or "complete" in plan and plan["complete"] is not True
            or "errored" in plan and plan["errored"] is not False):
        raise VaultPlanError("Vault plan contains drift, deferred, failed, or incomplete changes.")
    checks = plan.get("checks", [])
    if not isinstance(checks, list) or any(not isinstance(check, dict) or check.get("status") != "pass" for check in checks):
        raise VaultPlanError("Vault plan contains failed or unresolved checks.")
    allowed = _PREPARE if phase == "prepare" else {_ADMIN}
    expected = "create" if phase in {"prepare","grant"} else "delete"
    changed=[]; addresses=[]
    for item in plan["resource_changes"]:
        if not isinstance(item,dict) or item.get("mode") not in {"managed","data"} or not isinstance(item.get("address"),str) or not isinstance(item.get("change"),dict):
            raise VaultPlanError("Vault plan contains an unbounded resource change.")
        change=item["change"]; actions=change.get("actions")
        if not isinstance(actions,list) or any(not isinstance(action,str) for action in actions) or item.get("previous_address") is not None or change.get("importing") is not None:
            raise VaultPlanError("Vault plan contains an import, move, or malformed change.")
        addresses.append(item["address"])
        if item["mode"] == "data":
            if actions not in (["read"], ["no-op"]): raise VaultPlanError("Vault plan contains an unbounded data action.")
            continue
        if actions == ["no-op"]: continue
        if item["address"] not in allowed or actions != [expected]:
            raise VaultPlanError("Vault plan changes a resource outside the approved bootstrap phase.")
        changed.append(item["address"])
    if len(addresses) != len(set(addresses)):
        raise VaultPlanError("Vault plan repeats a managed resource change.")
    if changed and plan.get("applyable") is False: raise VaultPlanError("Vault plan with managed changes is not applyable.")
    return {"phase":phase,"result":"nochange" if not changed else "scope_valid","addresses":sorted(changed),"actions":dict(Counter({expected:len(changed)})) if changed else {}}

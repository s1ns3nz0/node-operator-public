"""Validate a non-secret reviewed Vault prepare-plan receipt."""
from __future__ import annotations
import re
import json
from installer_vault_plan import VaultPlanError, validate_vault_plan

class VaultReceiptError(RuntimeError):
    """Raised when a saved prepare receipt cannot bind the reviewed plan."""

def validate_prepare_receipt(receipt: dict, plan: dict, discovery: dict, reviewed_digest: str) -> None:
    """Require an exact unapplied prepare receipt for the current plan scope."""
    fields={"schema_version","phase","plan_sha256","aws_account_id","aws_region","deployment_name","scope","applied"}
    if not isinstance(discovery, dict) or not (isinstance(discovery.get("aws_account_id"), str) and re.fullmatch(r"[0-9]{12}", discovery["aws_account_id"]) and isinstance(discovery.get("aws_region"), str) and discovery["aws_region"] in {"ap-northeast-1","ap-northeast-2"} and isinstance(discovery.get("deployment_name"), str) and re.fullmatch(r"[a-z][a-z0-9-]{1,18}[a-z0-9]", discovery["deployment_name"])):
        raise VaultReceiptError("Selected deployment identity is invalid.")
    if not isinstance(receipt,dict) or set(receipt)!=fields or type(receipt.get("schema_version")) is not int or receipt["schema_version"]!=1 or receipt.get("phase")!="prepare" or receipt.get("applied") is not False:
        raise VaultReceiptError("Vault prepare receipt has an invalid schema or apply state.")
    if not isinstance(reviewed_digest,str) or re.fullmatch(r"[0-9a-f]{64}",reviewed_digest) is None or receipt.get("plan_sha256") != reviewed_digest:
        raise VaultReceiptError("Vault prepare receipt does not match the reviewed plan digest.")
    if any(receipt.get(key)!=discovery.get(key) for key in ("aws_account_id","aws_region","deployment_name")):
        raise VaultReceiptError("Vault prepare receipt does not match the selected deployment.")
    try: scope=validate_vault_plan(plan,"prepare")
    except VaultPlanError as error: raise VaultReceiptError("Current Vault prepare plan is outside the allowed scope.") from error
    try:
        same_scope = isinstance(receipt.get("scope"), dict) and json.dumps(receipt["scope"], sort_keys=True, separators=(",", ":")) == json.dumps(scope, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        same_scope = False
    if scope.get("result")!="scope_valid" or not same_scope:
        raise VaultReceiptError("Vault prepare receipt scope does not match the current plan.")

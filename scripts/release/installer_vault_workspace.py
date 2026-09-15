"""Read-only validation of the original baseline Terraform workspace."""
from __future__ import annotations
import json, os
from pathlib import Path
import stat
from installer_infrastructure import InfrastructureError, _read_object
from installer_ops_execution import _private, _safe_state

class VaultWorkspaceError(InfrastructureError): pass

def _read(path, message):
 try: return _read_object(path)
 except InfrastructureError as error: raise VaultWorkspaceError(message) from error

def validate_vault_workspace(bundle_root: Path, state_dir: Path, discovery: dict) -> Path:
 try:
  _safe_state(state_dir); work=state_dir/"terraform-work"; _private(work,"Original Terraform work directory is unsafe.")
  module=work/"baseline"; _private(module,"Original baseline module is unsafe.")
 except InfrastructureError as error: raise VaultWorkspaceError("Original baseline workspace is unsafe.") from error
 source=bundle_root/"source/infra/terraform"
 if source.is_symlink() or not source.is_dir(): raise VaultWorkspaceError("Verified release lacks baseline Terraform source.")
 expected={}
 for p in source.rglob("*"):
  if p.is_symlink() or (not p.is_dir() and not p.is_file()) or p.relative_to(source).parts[0]==".terraform":
   raise VaultWorkspaceError("Verified baseline source contains unsafe or mutable cache entries.")
  if p.is_file(): expected[p.relative_to(source)]=p.read_bytes()
 actual=set()
 for p in module.rglob("*"):
  rel=p.relative_to(module)
  if rel.parts[0]==".terraform": continue
  if p.is_symlink() or (not p.is_dir() and not p.is_file()): raise VaultWorkspaceError("Baseline workspace contains unsafe entries.")
  if p.is_file(): actual.add(rel)
 if actual != set(expected)|{Path("foundation-network.auto.tfvars.json")}: raise VaultWorkspaceError("Baseline workspace contains missing or unexpected files.")
 for rel, content in expected.items():
  if (module/rel).read_bytes()!=content: raise VaultWorkspaceError("Baseline module differs from verified release.")
 foundation=_read(work/"foundation-output.json","Foundation output is unsafe.")
 try:
  network={key:foundation[key] for key in ("vpc_id","vpc_cidr","system_subnet_ids","hoodi_subnet_ids","system_route_table_id","hoodi_route_table_id","hoodi_nat_gateway_id","hoodi_nat_public_ip")}
 except (KeyError,TypeError) as error: raise VaultWorkspaceError("Foundation output lacks the required NAT public IP handoff.") from error
 derived={"network_source":"foundation","foundation_network":network}
 for path in (work/"foundation-network.auto.tfvars.json",module/"foundation-network.auto.tfvars.json"):
  if _read(path,"Derived network input is unsafe.") != derived: raise VaultWorkspaceError("Derived network input differs from foundation output.")
 bootstrap=_read(work/"bootstrap-output.json","Bootstrap output is unsafe.")
 cache=module/".terraform"
 if cache.is_symlink() or not cache.is_dir(): raise VaultWorkspaceError("Baseline Terraform cache is unsafe.")
 metadata=cache/"terraform.tfstate"
 if metadata.is_symlink(): raise VaultWorkspaceError("Baseline backend metadata is unsafe.")
 backend=_read(metadata,"Baseline backend metadata is unsafe.")
 config=backend.get("backend",{}).get("config",{}) if isinstance(backend,dict) else {}
 account,region=discovery["aws_account_id"],discovery["aws_region"]
 if not (isinstance(bootstrap.get("bucket"),str) and bootstrap["bucket"] and isinstance(bootstrap.get("dynamodb_table"),str) and bootstrap["dynamodb_table"] and bootstrap.get("region")==region and isinstance(bootstrap.get("kms_key_id"),str) and bootstrap["kms_key_id"].startswith(f"arn:aws:kms:{region}:{account}:key/") and backend.get("backend",{}).get("type")=="s3" and config.get("bucket")==bootstrap["bucket"] and config.get("dynamodb_table")==bootstrap["dynamodb_table"] and config.get("kms_key_id")==bootstrap["kms_key_id"] and config.get("region")==region and config.get("key")=="node-operator/baseline/terraform.tfstate" and config.get("encrypt") is True and config.get("endpoint") in (None,"") and config.get("endpoints") in (None,{}) and config.get("workspace_key_prefix","env:")=="env:"):
  raise VaultWorkspaceError("Baseline backend metadata is not the selected isolated S3 state.")
 env=cache/"environment"
 if env.exists() or env.is_symlink():
  if env.is_symlink() or env.read_text().strip() not in ("","default"): raise VaultWorkspaceError("Baseline Terraform workspace is not default.")
 return module

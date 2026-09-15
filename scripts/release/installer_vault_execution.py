"""Create a fresh, private Vault delta plan workspace; never execute retained cache."""
from __future__ import annotations
import json, os, re, shutil, stat, subprocess, tempfile
from pathlib import Path
from installer_infrastructure import InfrastructureError, _read_object
from installer_ops_execution import _environment, _private, _safe_state, _identity, _hash
from installer_files import publish_directory
from installer_vault_inputs import prepare_vault_inputs
from installer_vault_plan import validate_vault_plan, VaultPlanError
from installer_vault_receipt import validate_prepare_receipt, VaultReceiptError
from installer_vault_workspace import validate_vault_workspace

class VaultExecutionError(InfrastructureError): pass

def prepare_vault_plan_workspace(bundle_root: Path,state_dir: Path,discovery: dict,profile: str,minimum_free: int=2*1024**3,target_name="vault-bootstrap-plan-work")->Path:
 _safe_state(state_dir)
 if target_name not in {
  "vault-bootstrap-plan-work", "vault-bootstrap-apply-work",
  "vault-bootstrap-grant-plan-work", "vault-bootstrap-grant-apply-work",
  "vault-bootstrap-revoke-plan-work", "vault-bootstrap-revoke-apply-work",
  "vault-bootstrap-grant-reconcile-work", "vault-bootstrap-revoke-reconcile-work",
 }:
  raise VaultExecutionError("Vault plan workspace name is not approved.")
 if shutil.disk_usage(state_dir).free < minimum_free: raise VaultExecutionError("Vault plan staging requires at least 2 GiB free private disk space.")
 original=validate_vault_workspace(bundle_root,state_dir,discovery)
 source=bundle_root/"source/infra/terraform"
 if (source/".terraform").exists() or (source/".terraform").is_symlink(): raise VaultExecutionError("Verified Terraform source must not contain a provider cache.")
 target=state_dir/target_name
 if target.exists() or target.is_symlink(): raise VaultExecutionError("Vault plan workspace already exists; preserve it for reviewed apply.")
 stage=Path(tempfile.mkdtemp(prefix=".vault-plan-",dir=state_dir))/"module"
 try:
  shutil.copytree(source,stage,symlinks=True)
  if any(p.is_symlink() for p in stage.rglob("*")): raise VaultExecutionError("Verified Terraform source contains a symlink.")
  shutil.copy2(original/"foundation-network.auto.tfvars.json",stage/"foundation-network.auto.tfvars.json")
  metadata=_read_object(original/".terraform/terraform.tfstate"); config=metadata["backend"]["config"]
  whitelist={key:config[key] for key in ("bucket","key","region","dynamodb_table","kms_key_id","encrypt")}
  backend=stage/"backend.json"; backend.write_text(json.dumps(whitelist,sort_keys=True));os.chmod(backend,0o600)
  result=_run(["terraform",f"-chdir={stage}","init","-input=false","-lockfile=readonly",f"-backend-config={backend}"],_environment(profile,discovery))
  if result.returncode: raise VaultExecutionError("Fresh Vault Terraform initialization failed; no saved plan was retained.")
  publish_directory(stage,target);os.chmod(target,0o700)
 except OSError as error: raise VaultExecutionError("Vault plan workspace could not be prepared safely.") from error
 finally:
  shutil.rmtree(stage.parent,ignore_errors=True)
 return target

def _run(args, environment, *, output=False):
 try:
  return subprocess.run(args,env=environment,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE if output else subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=1800,check=False)
 except (OSError,subprocess.TimeoutExpired) as error:
  raise VaultExecutionError("Vault command failed or timed out; preserve state for reconciliation.") from error

def _baseline_stable(terraform,environment,state_dir):
 baseline=state_dir/"infrastructure-inputs/baseline.tfvars.json"
 result=_run(terraform+["plan","-input=false","-detailed-exitcode",f"-var-file={baseline}"],environment)
 if result.returncode: raise VaultExecutionError("Baseline has drift or could not be reconciled; no Vault delta was planned.")
 result=_run(terraform+["output","-json"],environment,output=True)
 expected=_read_object(state_dir/"terraform-work/baseline-output.json")
 try: current=json.loads(result.stdout) if result.returncode==0 else None
 except (TypeError,ValueError) as error: raise VaultExecutionError("Baseline output could not be reconciled; no Vault delta was planned.") from error
 if json.dumps(current,sort_keys=True)!=json.dumps(expected,sort_keys=True): raise VaultExecutionError("Baseline output changed; no Vault delta was planned.")
 return baseline

def _create_private_json(path,value,message):
 try:
  descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(descriptor,"w",encoding="utf-8") as handle:
   json.dump(value,handle,sort_keys=True);handle.write("\n");handle.flush();os.fsync(handle.fileno())
 except OSError as error: raise VaultExecutionError(message) from error

def plan_vault_prepare(bundle_root,state_dir,discovery,profile,artifacts_path):
 """Caller owns lock and verified release. Plan hash is not apply approval."""
 delta=prepare_vault_inputs(state_dir,discovery,artifacts_path)
 _identity(discovery,profile)
 environment=_environment(profile,discovery)
 plans=state_dir/"vault-plans"
 if plans.exists() or plans.is_symlink(): _private(plans,"Vault plans directory is unsafe.")
 else: plans.mkdir(mode=0o700)
 destination=plans/"prepare"
 if destination.exists() or destination.is_symlink(): raise VaultExecutionError("A saved Vault plan already exists; nothing was overwritten.")
 module=prepare_vault_plan_workspace(bundle_root,state_dir,discovery,profile)
 stage=Path(tempfile.mkdtemp(prefix=".prepare-",dir=plans))
 try:
  terraform=["terraform",f"-chdir={module}"]
  baseline=_baseline_stable(terraform,environment,state_dir)
  saved=stage/"plan.tfplan"; fd=os.open(saved,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
  result=_run(terraform+["plan","-input=false",f"-var-file={baseline}",f"-var-file={delta}",f"-out={saved}"],environment)
  if result.returncode: raise VaultExecutionError("Vault preparation plan failed; no apply attempted.")
  saved.chmod(0o600);digest=_hash(saved)
  result=_run(terraform+["show","-json",str(saved)],environment,output=True)
  if result.returncode: raise VaultExecutionError("Saved Vault plan could not be inspected.")
  inspected=json.loads(result.stdout)
  scope=validate_vault_plan(inspected,"prepare")
  if scope["result"]=="nochange": raise VaultExecutionError("No preparation changes; reconcile readiness instead of applying an empty plan.")
  if _hash(saved)!=digest: raise VaultExecutionError("Saved plan changed during inspection; no plan was published.")
  receipt=stage/"receipt.json"
  receipt.write_text(json.dumps({"schema_version":1,"phase":"prepare","plan_sha256":digest,"aws_account_id":discovery["aws_account_id"],"aws_region":discovery["aws_region"],"deployment_name":discovery["deployment_name"],"scope":scope,"applied":False},sort_keys=True));receipt.chmod(0o600)
  validate_prepare_receipt(_read_object(receipt),inspected,discovery,digest)
  publish_directory(stage,destination)
  return digest
 except (ValueError,VaultPlanError,VaultReceiptError) as error:
  raise VaultExecutionError("Saved Vault plan is malformed or outside preparation scope.") from error
 finally:
  if stage.exists():
   shutil.rmtree(stage)
   shutil.rmtree(module)

def apply_vault_prepare(bundle_root,state_dir,discovery,profile,artifacts_path,expected_sha)->None:
 """Apply only an exactly reviewed Vault prepare plan; caller owns consent."""
 if not isinstance(expected_sha,str) or re.fullmatch(r"[0-9a-f]{64}",expected_sha) is None: raise VaultExecutionError("Reviewed Vault plan digest is invalid.")
 prepare_vault_inputs(state_dir,discovery,artifacts_path)
 _identity(discovery,profile); environment=_environment(profile,discovery)
 plans=state_dir/"vault-plans"
 try:
  _private(plans,"Vault plans directory is unsafe.")
  prepare=plans/"prepare"; _private(prepare,"Reviewed Vault prepare plan directory is unsafe.")
 except InfrastructureError as error: raise VaultExecutionError("Vault saved-plan directory is unsafe.") from error
 saved=prepare/"plan.tfplan"; receipt=prepare/"receipt.json"
 if _hash(saved)!=expected_sha: raise VaultExecutionError("Reviewed Vault plan digest does not match.")
 attempt=plans/"prepare-apply-attempt.json"
 if attempt.exists() or attempt.is_symlink(): raise VaultExecutionError("Vault prepare apply uncertainty exists; do not retry blindly.")
 success=plans/"prepare-success.json"
 if success.exists() or success.is_symlink(): raise VaultExecutionError("Vault prepare success record already exists; no apply was started.")
 module=prepare_vault_plan_workspace(bundle_root,state_dir,discovery,profile,target_name="vault-bootstrap-apply-work")
 try:
  terraform=["terraform",f"-chdir={module}"]
  baseline=_baseline_stable(terraform,environment,state_dir)
  shown=_run(terraform+["show","-json",str(saved)],environment,output=True)
  if shown.returncode: raise VaultExecutionError("Reviewed Vault plan cannot be inspected.")
  try: validate_prepare_receipt(_read_object(receipt),json.loads(shown.stdout),discovery,expected_sha)
  except (InfrastructureError,TypeError,ValueError,VaultReceiptError,VaultPlanError) as error: raise VaultExecutionError("Reviewed Vault receipt or plan is malformed or outside preparation scope.") from error
  if _hash(saved)!=expected_sha: raise VaultExecutionError("Reviewed Vault plan changed before apply.")
  _create_private_json(attempt,{"schema_version":1,"phase":"prepare","plan_sha256":expected_sha},"Vault prepare apply marker could not be created safely.")
  result=_run(terraform+["apply","-input=false",str(saved)],environment)
  if result.returncode: raise VaultExecutionError("Vault prepare apply outcome is uncertain; preserve the attempt marker.")
  _create_private_json(success,{"schema_version":1,"phase":"prepare","plan_sha256":expected_sha,"applied":True},"Vault prepare success record could not be created safely.")
 finally:
  # Once an apply attempt is recorded, retain the fresh workspace for reconciliation.
  if module.exists() and not (attempt.exists() or attempt.is_symlink()): shutil.rmtree(module)

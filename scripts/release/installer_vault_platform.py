"""Start or reconcile one verified private Vault platform CodeBuild run."""
from __future__ import annotations
import hashlib,json,os,re,stat,subprocess
from pathlib import Path
from installer_artifact_mirror import _write,NAMES
from installer_ops_execution import _environment,_private,_safe_state
from installer_vault_authority import reconcile_vault_authority
class PlatformError(RuntimeError): pass
SHA=re.compile(r"[0-9a-f]{64}\Z")
def read(path):
 try:
  x=path.lstat()
  if path.is_symlink() or not stat.S_ISREG(x.st_mode) or stat.S_IMODE(x.st_mode)!=0o600 or x.st_size>4*1024*1024:raise ValueError()
  def hook(pairs):
   seen=set()
   d={}
   for k,v in pairs:
    if k in seen:raise ValueError()
    seen.add(k);d[k]=v
   return d
  v=json.loads(path.read_text(),object_pairs_hook=hook)
 except (OSError,ValueError,json.JSONDecodeError) as e:raise PlatformError("platform evidence is unsafe") from e
 if not isinstance(v,dict):raise PlatformError("platform evidence malformed")
 return v
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def context(v,d):
 if any(v.get(k)!=d[k] for k in ("aws_account_id","aws_region","deployment_name")):raise PlatformError("evidence context mismatch")
def grant(plan_path,success_path,d):
 plan,success=read(plan_path),read(success_path); keys={"schema_version","phase","plan_sha256","aws_account_id","aws_region","deployment_name","scope","applied"}
 if set(plan)!=keys or plan.get("schema_version")!=1 or plan.get("phase")!="grant" or plan.get("applied") is not False or not SHA.fullmatch(plan.get("plan_sha256","")) or not isinstance(plan.get("scope"),dict):raise PlatformError("invalid grant plan receipt")
 context(plan,d)
 if success!={"schema_version":1,"phase":"grant","plan_sha256":plan["plan_sha256"],"applied":True}:raise PlatformError("invalid grant success receipt")
 return plan["plan_sha256"]
def aws(args,env):
 try:v=json.loads(subprocess.run(args,check=True,capture_output=True,text=True,env=env).stdout)
 except (OSError,subprocess.CalledProcessError,json.JSONDecodeError) as e:raise PlatformError("AWS query failed; reconcile outcome") from e
 if not isinstance(v,dict):raise PlatformError("AWS query malformed")
 return v
def output(values,key):
 x=values.get(key) if isinstance(values,dict) else None
 if not isinstance(x,dict) or x.get("sensitive") is not False or "value" not in x:raise PlatformError("refreshed platform output invalid")
 return x["value"]
def artifacts(index_path,mirror_path,baseline,d):
 index,mirror=read(index_path),read(mirror_path)
 from installer_artifact_receipt import validate,ReceiptError
 try: verified,index_hash=validate(index,mirror,baseline,d,index_path.read_bytes())
 except ReceiptError as e: raise PlatformError(str(e)) from e
 boot=index.get("components",{}).get("vault-bootstrap") if isinstance(index.get("components"),dict) else None
 image=boot.get("image_ref") if isinstance(boot,dict) else None; manifest=boot.get("manifest_digest") if isinstance(boot,dict) else None
 if set(index)!={"schema_version","release_revision","components"} or index.get("schema_version")!=1 or set(index.get("components",{}))!=NAMES or not isinstance(image,str) or not re.fullmatch(r"[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}",image) or not isinstance(manifest,str) or not re.fullmatch(r"sha256:[a-f0-9]{64}",manifest):raise PlatformError("invalid artifact index")
 private=verified["vault-bootstrap"]["image_ref"]
 return private,index_hash
def project_check(contract,image,d,env):
 name,role=contract["name"],contract["service_role_arn"]
 projects=aws(["aws","codebuild","batch-get-projects","--names",name,"--region",d["aws_region"]],env).get("projects")
 arn=f"arn:aws:codebuild:{d['aws_region']}:{d['aws_account_id']}:project/{name}"
 if not isinstance(projects,list) or len(projects)!=1:raise PlatformError("project missing or ambiguous")
 x=projects[0]; source=x.get("source") if isinstance(x,dict) else None; e=x.get("environment") if isinstance(x,dict) else None
 if not(isinstance(source,dict) and source.get("type")==contract["source_type"]=="NO_SOURCE" and isinstance(source.get("buildspec"),str) and hashlib.sha256(source["buildspec"].encode()).hexdigest()==contract["buildspec_sha256"] and isinstance(e,dict) and e.get("image")==image==contract["image"] and e.get("imagePullCredentialsType")=="SERVICE_ROLE" and e.get("privilegedMode") is False and x.get("name")==name and x.get("arn")==arn==contract["arn"] and x.get("serviceRole")==role):raise PlatformError("project identity/image/buildspec contract mismatch")
def build_status(build_id,project,d,env):
 builds=aws(["aws","codebuild","batch-get-builds","--ids",build_id,"--region",d["aws_region"]],env).get("builds")
 if not isinstance(builds,list) or len(builds)!=1 or not isinstance(builds[0],dict):raise PlatformError("build status missing")
 b=builds[0]
 if b.get("id")!=build_id or b.get("projectName")!=project or b.get("buildComplete") is not True or not isinstance(b.get("buildStatus"),str):raise PlatformError("build status does not bind exact terminal build")
 return b["buildStatus"]
def run(bundle_root:Path,state_dir:Path,discovery:dict,profile:str)->dict:
 try:_safe_state(state_dir);_private(state_dir,"unsafe")
 except Exception as e:raise PlatformError("platform state unsafe") from e
 grant_plan=state_dir/"vault-authority-plans/grant/receipt.json";grant_success=state_dir/"vault-authority-plans/grant-success.json";artifact_index=bundle_root/"rendered/installer-artifact-index.json";mirror_receipt=state_dir/"vault-artifact-mirror-receipt.json";baseline=state_dir/"terraform-work/baseline-output.json"
 h=grant(grant_plan,grant_success,discovery)
 refreshed=reconcile_vault_authority(bundle_root,state_dir,discovery,profile,state_dir/"vault-artifact-manifest.json","grant")
 image,index_hash=artifacts(artifact_index,mirror_receipt,refreshed,discovery);contract=output(refreshed,"vault_bootstrap_project_contract");keys={"name","arn","service_role_arn","image","source_type","buildspec_sha256","aws_account_id","aws_region"}
 if not isinstance(contract,dict) or set(contract)!=keys or contract.get("aws_account_id")!=discovery["aws_account_id"] or contract.get("aws_region")!=discovery["aws_region"] or not SHA.fullmatch(contract.get("buildspec_sha256","")):raise PlatformError("project contract invalid")
 project=contract["name"]
 env=_environment(profile,discovery)
 if aws(["aws","sts","get-caller-identity","--region",discovery["aws_region"]],env).get("Account")!=discovery["aws_account_id"]:raise PlatformError("profile account mismatch")
 project_check(contract,image,discovery,env)
 intent=state_dir/"vault-platform-intent.json"; build=state_dir/"vault-platform-build.json"; success=state_dir/"vault-platform-success.json"; failure=state_dir/"vault-platform-failure.json"
 contract_hash=hashlib.sha256(json.dumps(contract,sort_keys=True,separators=(",",":")).encode()).hexdigest()
 binding={"schema_version":1,"aws_account_id":discovery["aws_account_id"],"aws_region":discovery["aws_region"],"deployment_name":discovery["deployment_name"],"grant_plan_sha256":h,"artifact_index_sha256":index_hash,"project_contract_sha256":contract_hash,"project":project,"image_ref":image}
 if (success.exists() or success.is_symlink()) and (failure.exists() or failure.is_symlink()):raise PlatformError("conflicting terminal platform receipts")
 if success.exists() or success.is_symlink():
  x=read(success)
  if x.get("status")!="succeeded" or any(x.get(k)!=v for k,v in binding.items()) or not isinstance(x.get("build_id"),str):raise PlatformError("success receipt invalid")
  return x
 if failure.exists() or failure.is_symlink():
  x=read(failure)
  if set(x)!={*binding,"build_id","status"} or any(x.get(k)!=v for k,v in binding.items()) or not isinstance(x.get("build_id"),str) or not x["build_id"].startswith(project+":") or x.get("status") not in {"FAILED","FAULT","STOPPED","TIMED_OUT"}:raise PlatformError("failure receipt invalid")
  if build_status(x["build_id"],project,discovery,env)!=x["status"]:raise PlatformError("failure receipt no longer binds exact terminal build")
  return x
 if intent.exists() or intent.is_symlink():
  if read(intent)!=binding:raise PlatformError("intent differs")
  if not build.exists() or build.is_symlink():raise PlatformError("start may have occurred before ID recording; do not restart")
  x=read(build)
  if set(x)!={*binding,"build_id"} or any(x.get(k)!=v for k,v in binding.items()) or not isinstance(x.get("build_id"),str) or not x["build_id"].startswith(project+":"):raise PlatformError("build record invalid")
  build_id=x["build_id"]
 else:
  if build.exists() or build.is_symlink():raise PlatformError("build record without intent")
  _write(intent,binding); started=aws(["aws","codebuild","start-build","--project-name",project,"--region",discovery["aws_region"]],env); build_id=started.get("build",{}).get("id") if isinstance(started.get("build"),dict) else None
  if not isinstance(build_id,str) or not build_id.startswith(project+":"):raise PlatformError("start returned no build ID")
  _write(build,{**binding,"build_id":build_id})
 status=build_status(build_id,project,discovery,env)
 if status=="SUCCEEDED":
  x={**binding,"build_id":build_id,"status":"succeeded"};_write(success,x);return x
 if status in {"FAILED","FAULT","STOPPED","TIMED_OUT"}:
  x={**binding,"build_id":build_id,"status":status};_write(failure,x);return x
 raise PlatformError("build remains nonterminal; reconcile exact build later")

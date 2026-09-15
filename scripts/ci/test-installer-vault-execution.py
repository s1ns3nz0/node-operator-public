# Check objective: Guard Vault saved-plan apply without running Terraform or Vault.
from __future__ import annotations
import json, os, shutil, sys, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"scripts/release"))
import installer_vault_execution as v
import installer_vault_plan as p

D={"aws_account_id":"123456789012","aws_region":"ap-northeast-1","deployment_name":"test"}

def plan(address=None):
 return {"format_version":"1.2","terraform_version":"1.5.7","resource_changes":[{"address":address or next(iter(p._PREPARE)),"mode":"managed","change":{"actions":["create"]}}]}

class T(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name);os.chmod(self.root,0o700)
  self.state=self.root/"state";self.state.mkdir(mode=0o700)
  work=self.state/"terraform-work";work.mkdir(mode=0o700);self.orig=work/"baseline";self.orig.mkdir(mode=0o700)
  (self.orig/".terraform").mkdir();self.write(self.orig/".terraform/terraform.tfstate",{},0o600)
  self.baseline=work/"baseline-output.json";self.write(self.baseline,{"fixture":{"value":"original"}},0o600)
  foundation={"vpc_id":"vpc-1","vpc_cidr":"10.0.0.0/16","system_subnet_ids":["subnet-1"],"hoodi_subnet_ids":["subnet-2"],"system_route_table_id":"rtb-1","hoodi_route_table_id":"rtb-2","hoodi_nat_gateway_id":"nat-1","hoodi_nat_public_ip":"198.51.100.42"}
  self.write(work/"foundation-output.json",foundation,0o600)
  self.write(work/"bootstrap-output.json",{"bucket":"b","dynamodb_table":"t","region":D["aws_region"],"kms_key_id":"arn:aws:kms:ap-northeast-1:123456789012:key/key"},0o600)
  derived={"network_source":"foundation","foundation_network":foundation}
  self.write(work/"foundation-network.auto.tfvars.json",derived,0o600);self.write(self.orig/"foundation-network.auto.tfvars.json",derived,0o600)
  inputs=self.state/"infrastructure-inputs";inputs.mkdir(mode=0o700);self.write(inputs/"baseline.tfvars.json",{},0o600)
  self.plans=self.state/"vault-plans";self.plans.mkdir(mode=0o700);self.prepare=self.plans/"prepare";self.prepare.mkdir(mode=0o700)
  self.saved=self.prepare/"plan.tfplan";self.saved.write_bytes(b"synthetic plan");os.chmod(self.saved,0o600)
  self.digest=v._hash(self.saved);self.write(self.prepare/"receipt.json",{"schema_version":1,"phase":"prepare","plan_sha256":self.digest,**D,"scope":p.validate_vault_plan(plan(),"prepare"),"applied":False},0o600)
  self.bundle=self.root/"bundle";source=self.bundle/"source/infra/terraform";source.mkdir(parents=True);(source/"main.tf").write_text("x");(self.orig/"main.tf").write_text("x")
  self.write(self.orig/".terraform/terraform.tfstate",{"backend":{"type":"s3","config":{"bucket":"b","key":"node-operator/baseline/terraform.tfstate","region":"ap-northeast-1","dynamodb_table":"t","kms_key_id":"arn:aws:kms:ap-northeast-1:123456789012:key/key","encrypt":True}}},0o600)
  self.fresh=self.state/"vault-bootstrap-apply-work";self.fresh.mkdir(mode=0o700)
 def tearDown(self):self.t.cleanup()
 def write(self,path,value,mode):path.write_text(json.dumps(value));os.chmod(path,mode)
 def invoke(self,failure=None,shown=None,digest=None,receipt=None):
  calls=[]
  if receipt is not None:self.write(self.prepare/"receipt.json",receipt,0o600)
  def run(args,environment,*,output=False):
   calls.append(args)
   if "-detailed-exitcode" in args:return SimpleNamespace(returncode=2 if failure=="drift" else 0)
   if "output" in args:return SimpleNamespace(returncode=0,stdout=b"{}" if failure=="output" else self.baseline.read_bytes())
   if "show" in args:return SimpleNamespace(returncode=0,stdout=json.dumps(shown or plan()).encode())
   if "apply" in args:return SimpleNamespace(returncode=1 if failure=="apply" else 0)
   raise AssertionError(args)
  with patch.object(v,"prepare_vault_inputs",return_value=self.state/"delta.json"),patch.object(v,"prepare_vault_plan_workspace",return_value=self.fresh),patch.object(v,"_identity"),patch.object(v,"_environment",return_value={}),patch.object(v,"_run",side_effect=run):
   outcome=v.apply_vault_prepare(self.bundle,self.state,D,"profile",self.state/"artifacts",digest or self.digest)
  return outcome,calls
 def test_success_uses_only_fresh_workspace_and_creates_private_records(self):
  _,calls=self.invoke()
  attempt=self.plans/"prepare-apply-attempt.json";success=self.plans/"prepare-success.json"
  self.assertEqual(json.loads(attempt.read_text())["plan_sha256"],self.digest);self.assertTrue(json.loads(success.read_text())["applied"])
  self.assertEqual(attempt.stat().st_mode&0o777,0o600);self.assertEqual(success.stat().st_mode&0o777,0o600)
  self.assertTrue(self.saved.exists());self.assertTrue(self.fresh.exists())
  self.assertTrue(all(f"-chdir={self.fresh}" in call for call in calls));self.assertFalse(any(f"-chdir={self.orig}" in call for call in calls))
  self.assertFalse(any(item in {"vault","helm","codebuild"} for call in calls for item in call))
  with self.assertRaises(v.VaultExecutionError):self.invoke()
 def test_apply_failure_marker_prevents_retry_and_preserves_plan_and_workspace(self):
  with self.assertRaises(v.VaultExecutionError):self.invoke("apply")
  self.assertTrue((self.plans/"prepare-apply-attempt.json").is_file());self.assertFalse((self.plans/"prepare-success.json").exists())
  self.assertTrue(self.saved.exists());self.assertTrue(self.fresh.exists())
  with self.assertRaises(v.VaultExecutionError):self.invoke()
 def test_drift_output_hash_scope_and_receipt_rejections_never_apply(self):
  cases=[("drift",None,None,None),("output",None,None,None),(None,None,"A"*64,None),(None,plan("aws_eks_cluster.private"),None,None),(None,None,None,{"bad":True})]
  for failure,shown,digest,receipt in cases:
   with self.subTest(failure=failure,shown=shown,digest=digest):
    with self.assertRaises(v.VaultExecutionError):self.invoke(failure,shown,digest,receipt)
    self.assertFalse((self.plans/"prepare-apply-attempt.json").exists());self.assertFalse((self.plans/"prepare-success.json").exists())
    self.assertTrue(self.saved.exists())
    if not self.fresh.exists(): self.fresh.mkdir(mode=0o700)
 def test_target_name_and_private_prepare_parent_are_rejected(self):
  with self.assertRaises(v.VaultExecutionError):v.prepare_vault_plan_workspace(self.bundle,self.state,D,"p",target_name="../../outside")
  self.prepare.chmod(0o755)
  with self.assertRaises(v.VaultExecutionError):self.invoke()
 def test_saved_plan_failures_preserve_original(self):
  shutil.rmtree(self.plans)
  for failure in ("init","drift","scope",None):
   with self.subTest(failure=failure):
    calls=[]
    def run(args,environment,*,output=False):
     calls.append(args)
     if "init" in args:return SimpleNamespace(returncode=1 if failure=="init" else 0)
     if "-detailed-exitcode" in args:return SimpleNamespace(returncode=2 if failure=="drift" else 0)
     if "output" in args:return SimpleNamespace(returncode=0,stdout=self.baseline.read_bytes())
     if "show" in args:return SimpleNamespace(returncode=0,stdout=json.dumps(plan("aws_eks_cluster.private" if failure=="scope" else None)).encode())
     Path(next(x[5:] for x in args if x.startswith("-out="))).write_bytes(b"plan");return SimpleNamespace(returncode=0)
    with patch.object(v,"prepare_vault_inputs",return_value=self.state/"delta.json"),patch.object(v,"_identity"),patch.object(v,"_environment",return_value={}),patch.object(v,"_run",side_effect=run),patch.object(v.shutil,"disk_usage",return_value=SimpleNamespace(free=3*1024**3)):
     args=(self.bundle,self.state,D,"profile",self.state/"artifacts")
     if failure:
      with self.assertRaises(v.VaultExecutionError):v.plan_vault_prepare(*args)
      self.assertFalse((self.plans/"prepare").exists());self.assertFalse((self.state/"vault-bootstrap-plan-work").exists())
     else:self.assertEqual(len(v.plan_vault_prepare(*args)),64)
    self.assertTrue((self.orig/".terraform/terraform.tfstate").is_file());self.assertFalse(any(f"-chdir={self.orig}" in call for call in calls));self.assertFalse(any("apply" in call for call in calls))
    if self.plans.exists():shutil.rmtree(self.plans)
 def test_fresh_init_only(self):
  with patch.object(v,"validate_vault_workspace",return_value=self.orig),patch.object(v.shutil,"disk_usage",return_value=SimpleNamespace(free=3*1024**3)),patch.object(v.subprocess,"run",return_value=SimpleNamespace(returncode=0)) as run:
   out=v.prepare_vault_plan_workspace(self.bundle,self.state,D,"profile",target_name="vault-bootstrap-plan-work")
  args=run.call_args[0][0];self.assertTrue(next(x for x in args if x.startswith("-chdir=")).split("=",1)[1].startswith(str(self.state/".vault-plan-")));self.assertIn("-lockfile=readonly",args);self.assertNotIn(str(self.orig)," ".join(args));self.assertFalse((out/".terraform/terraform.tfstate").exists())

if __name__=="__main__":unittest.main()

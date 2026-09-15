# Check objective: Exercise local baseline workspace binding without Terraform or AWS.
from __future__ import annotations
import json,os,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"scripts/release"));import installer_vault_workspace as v
D={"aws_account_id":"123456789012","aws_region":"ap-northeast-1"}
class T(unittest.TestCase):
 def test_verified_source_symlink_is_rejected(self):
  source=self.bundle/"source/infra/terraform"
  (source/"external.tf").symlink_to(self.root/"absent")
  with self.assertRaises(v.VaultWorkspaceError):v.validate_vault_workspace(self.bundle,self.state,D)
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name);os.chmod(self.root,0o700);self.state=self.root/"state";self.state.mkdir(mode=0o700);w=self.state/"terraform-work";w.mkdir(mode=0o700);self.bundle=self.root/"bundle";src=self.bundle/"source/infra/terraform";src.mkdir(parents=True);self.write(src/"main.tf","x",0o600);m=w/"baseline";m.mkdir(mode=0o700);self.write(m/"main.tf","x",0o600)
  f={"vpc_id":"vpc-a","vpc_cidr":"10.0.0.0/16","system_subnet_ids":["subnet-a"],"hoodi_subnet_ids":["subnet-b"],"system_route_table_id":"rtb-a","hoodi_route_table_id":"rtb-b","hoodi_nat_gateway_id":"nat-a","hoodi_nat_public_ip":"198.51.100.42"};self.write(w/"foundation-output.json",f);d={"network_source":"foundation","foundation_network":f};self.write(w/"foundation-network.auto.tfvars.json",d);self.write(m/"foundation-network.auto.tfvars.json",d);self.write(w/"bootstrap-output.json",{"bucket":"b","dynamodb_table":"t","region":"ap-northeast-1","kms_key_id":"arn:aws:kms:ap-northeast-1:123456789012:key/a"});(m/".terraform").mkdir();self.write(m/".terraform/terraform.tfstate",{"backend":{"type":"s3","config":{"bucket":"b","dynamodb_table":"t","kms_key_id":"arn:aws:kms:ap-northeast-1:123456789012:key/a","region":"ap-northeast-1","key":"node-operator/baseline/terraform.tfstate","encrypt":True}}})
 def tearDown(self):self.t.cleanup()
 def write(self,p,x,mode=0o600):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x) if isinstance(x,dict) else x);os.chmod(p,mode)
 def test_valid_and_hostile(self):
  self.assertEqual(v.validate_vault_workspace(self.bundle,self.state,D),self.state/"terraform-work/baseline")
  (self.state/"terraform-work/baseline/extra").write_text("x")
  with self.assertRaises(v.VaultWorkspaceError):v.validate_vault_workspace(self.bundle,self.state,D)
 def test_changed_module_missing_module_and_network_mismatch(self):
  self.write(self.state/"terraform-work/baseline/main.tf","changed")
  with self.assertRaises(v.VaultWorkspaceError):v.validate_vault_workspace(self.bundle,self.state,D)
  self.write(self.state/"terraform-work/baseline/main.tf","x")
  self.write(self.state/"terraform-work/foundation-network.auto.tfvars.json",{})
  with self.assertRaises(v.VaultWorkspaceError):v.validate_vault_workspace(self.bundle,self.state,D)
  (self.state/"terraform-work/baseline").rename(self.state/"terraform-work/moved")
  with self.assertRaises(v.VaultWorkspaceError):v.validate_vault_workspace(self.bundle,self.state,D)
 def test_foreign_backend_and_workspace_rejected(self):
  path=self.state/"terraform-work/baseline/.terraform/terraform.tfstate"; original=json.loads(path.read_text())
  for key,value in (("bucket","foreign"),("region","ap-northeast-2"),("kms_key_id","foreign"),("key","other"),("encrypt",False),("endpoint","https://bad")):
   data=json.loads(json.dumps(original));data["backend"]["config"][key]=value;self.write(path,data)
   with self.subTest(key=key):
    with self.assertRaises(v.VaultWorkspaceError):v.validate_vault_workspace(self.bundle,self.state,D)
  self.write(path,original);self.write(self.state/"terraform-work/baseline/.terraform/environment","other")
  with self.assertRaises(v.VaultWorkspaceError):v.validate_vault_workspace(self.bundle,self.state,D)
 def test_cache_and_metadata_symlinks_rejected(self):
  cache=self.state/"terraform-work/baseline/.terraform"; target=self.state/"target"; target.mkdir()
  cache.rename(target/"cache"); cache.symlink_to(target/"cache",target_is_directory=True)
  with self.assertRaises(v.VaultWorkspaceError):v.validate_vault_workspace(self.bundle,self.state,D)
  cache.unlink(); (target/"cache").rename(cache); metadata=cache/"terraform.tfstate"; victim=self.state/"victim";self.write(victim,{}) ;metadata.unlink();metadata.symlink_to(victim)
  with self.assertRaises(v.VaultWorkspaceError):v.validate_vault_workspace(self.bundle,self.state,D)
 def test_shared_foreign_kms_and_endpoint_map_rejected(self):
  work=self.state/"terraform-work"; boot=work/"bootstrap-output.json"; metadata=work/"baseline/.terraform/terraform.tfstate"
  original=json.loads(boot.read_text()); backend=json.loads(metadata.read_text())
  foreign="arn:aws:kms:ap-northeast-1:999999999999:key/a"
  changed=dict(original,kms_key_id=foreign); config=json.loads(json.dumps(backend));config["backend"]["config"]["kms_key_id"]=foreign
  self.write(boot,changed);self.write(metadata,config)
  with self.assertRaises(v.VaultWorkspaceError):v.validate_vault_workspace(self.bundle,self.state,D)
  self.write(boot,original);config=json.loads(json.dumps(backend));config["backend"]["config"]["endpoints"]={"s3":"https://foreign.invalid"};self.write(metadata,config)
  with self.assertRaises(v.VaultWorkspaceError):v.validate_vault_workspace(self.bundle,self.state,D)
  self.write(metadata,backend);(work/"baseline/.terraform/environment").symlink_to(work/"absent")
  with self.assertRaises(v.VaultWorkspaceError):v.validate_vault_workspace(self.bundle,self.state,D)
if __name__=="__main__":unittest.main()

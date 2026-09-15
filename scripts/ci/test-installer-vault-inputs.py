# Check objective: Exercise local Vault bootstrap input binding and fail-closed artifact scope checks.
from __future__ import annotations
import json, os, sys, tempfile, unittest, hashlib, shutil, base64
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/"scripts/release")); import installer_vault_inputs as vault; import installer_infrastructure as infrastructure
D={"aws_profile":"operator","aws_account_id":"123456789012","aws_region":"ap-northeast-1","deployment_name":"test-node","availability_zones":["ap-northeast-1a","ap-northeast-1c"],"configuration_recorder":{"result":"recorder_absent_verified","existing_count":0,"manage_config_recorder":True,"existing_recorder_adoption":"not_authorized"}}
class Tests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(); self.root=Path(self.t.name); os.chmod(self.root,0o700); self.state=self.root/"state"; self.state.mkdir(mode=0o700); (self.state/"terraform-work").mkdir(mode=0o700)
  self.repo="123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/node-operator-baseline-gitops-vault"; self.image=self.repo+"@sha256:"+"a"*64; self.server_digest="sha256:268bb80aa9c6d13d65fcfa05c0c268caca068952240a8087291a6ce0b66e3a10"; self.injector_digest="sha256:8c18ccc87fd72930fd0c3f12ea444e9e57e83f119b93c546ed047aba29a05c5f"; self.relay_repo="123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/node-operator-baseline-vault-audit-relay"; self.relay_digest="sha256:"+"c"*64
  self.cert_repo="123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/node-operator-baseline-gitops-cert-manager"; self.digest="sha256:"+"a"*64
  baseline={"deployment_account_id":{"value":"123456789012"},"cluster_name":{"value":"test-node"},"vault_unseal_key_arn":{"value":"arn:aws:kms:ap-northeast-1:123456789012:key/abcd"},"vault_role_arn":{"value":"arn:aws:iam::123456789012:role/vault"},"private_subnet_ids":{"value":["subnet-abc"]},"private_gitops_ecr_repository_urls":{"value":{"vault":self.repo,"vault_chart":self.repo+"/vault","cert_manager":self.cert_repo,"cert_manager_chart":self.cert_repo+"/cert-manager"}}}; [item.update(sensitive=False) for item in baseline.values()]; self.write(self.state/"terraform-work/baseline-output.json",baseline)
  inputs=self.state/"infrastructure-inputs"; inputs.mkdir(mode=0o700); values=infrastructure.expected_inputs(inputs,D,"arn:aws:iam::123456789012:role/NodeOperatorTerraformApply"); [self.write(inputs/name,value) for name,value in values.items()]
  self.art=self.root/"artifacts.json"; self.write(self.art,{"schema_version":1,"aws_account_id":D["aws_account_id"],"aws_region":D["aws_region"],"deployment_name":D["deployment_name"],"images":{"bootstrap":self.image,"server":self.repo+"@"+self.server_digest,"agent":self.repo+"@"+self.server_digest,"injector":self.repo+"@"+self.injector_digest,"audit_relay":self.relay_repo+"@"+self.relay_digest},"chart":{"version":"0.31.0","digest":"sha256:"+"b"*64}})
  components={name:{} for name in ("vault-bootstrap","gitops-oci-mirror","vault-chart")}
  components.update({"vault-server":{"manifest_digest":self.server_digest},"vault-injector":{"manifest_digest":self.injector_digest},"vault-audit-relay":{"manifest_digest":self.relay_digest,"verification":{"method":"cosign-and-slsa","status":"passed"}}})
  components.update({name:{"manifest_digest":self.digest} for name in ("cert-manager-controller","cert-manager-webhook","cert-manager-cainjector","cert-manager-startupapicheck")})
  components["cert-manager-chart"]={"expected_oci_manifest_digest":self.digest,"version":"1.21.1"}
  index={"schema_version":1,"release_revision":"c"*40,"components":components}; release=self.state/"release/rendered"; release.mkdir(parents=True,mode=0o700); raw=json.dumps(index).encode(); (release/"installer-artifact-index.json").write_bytes(raw); os.chmod(release/"installer-artifact-index.json",0o600)
  source=self.state/"release/source"; (source/"scripts/release").mkdir(parents=True); (source/".ci/gitops").mkdir(parents=True); shutil.copy2(ROOT/"scripts/release/render-private-vault-values.py",source/"scripts/release/render-private-vault-values.py"); shutil.copy2(ROOT/".ci/gitops/approved-oci-artifacts.json",source/".ci/gitops/approved-oci-artifacts.json")
  artifacts={name:{"image_ref":self.cert_repo+"@"+self.digest,"manifest_digest":self.digest} for name in ("cert-manager-controller","cert-manager-webhook","cert-manager-cainjector","cert-manager-startupapicheck")}
  artifacts["cert-manager-chart"]={"image_ref":self.cert_repo+"/cert-manager@"+self.digest,"manifest_digest":self.digest,"version":"1.21.1"}
  artifacts.update({"vault-bootstrap":{"image_ref":self.image,"manifest_digest":"sha256:"+"a"*64},"vault-server":{"image_ref":self.repo+"@"+self.server_digest,"manifest_digest":self.server_digest},"vault-injector":{"image_ref":self.repo+"@"+self.injector_digest,"manifest_digest":self.injector_digest},"vault-audit-relay":{"image_ref":self.relay_repo+"@"+self.relay_digest,"manifest_digest":self.relay_digest}})
  artifacts["vault-chart"]={"image_ref":self.repo+"/vault@"+self.digest,"manifest_digest":self.digest,"version":"0.31.0"}
  self.write(self.state/"vault-artifact-mirror-receipt.json",{"schema_version":1,"status":"verified","aws_account_id":D["aws_account_id"],"aws_region":D["aws_region"],"deployment_name":D["deployment_name"],"release_revision":"c"*40,"index_sha256":hashlib.sha256(raw).hexdigest(),"artifacts":artifacts})
 def tearDown(self): self.t.cleanup()
 def write(self,p,v): p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(v)); os.chmod(p,0o600)
 def test_valid_idempotent(self):
  result=vault.prepare_vault_inputs(self.state,D,self.art); values=json.loads(result.read_text()); self.assertEqual(result.stat().st_mode&0o777,0o600); self.assertEqual(values["vault_runtime_images"], {"server":self.repo+"@"+self.server_digest,"agent":self.repo+"@"+self.server_digest,"injector":self.repo+"@"+self.injector_digest,"audit_relay":self.relay_repo+"@"+self.relay_digest}); overlay=json.loads(base64.b64decode(values["vault_image_values_overlay_base64"])); self.assertEqual(overlay["server"]["image"]["tag"],self.server_digest[7:]+"@"+self.server_digest); self.assertEqual(values["cert_manager_runtime_images"], {key:self.cert_repo+"@"+self.digest for key in ("controller","webhook","cainjector","startupapicheck")}); self.assertEqual((values["cert_manager_chart_version"],values["cert_manager_chart_manifest_digest"]),("1.21.1",self.digest)); self.assertTrue(vault.prepare_vault_inputs(self.state,D,self.art).exists())
 def test_cert_manager_v_prefix_is_preserved_and_invalid_versions_are_rejected(self):
  receipt_path=self.state/"vault-artifact-mirror-receipt.json"; index_path=self.state/"release/rendered/installer-artifact-index.json"
  receipt=json.loads(receipt_path.read_text()); index=json.loads(index_path.read_text())
  for version, accepted in (("v1.21.1",True),("vv1.21.1",False),("1.21",False),("v1.21.1/other",False),("latest",False),("v1.21.1\n",False)):
   with self.subTest(version=version):
    candidate_receipt=json.loads(json.dumps(receipt)); candidate_index=json.loads(json.dumps(index)); candidate_index["components"]["cert-manager-chart"]["version"]=version; candidate_receipt["artifacts"]["cert-manager-chart"]["version"]=version
    raw=json.dumps(candidate_index).encode(); candidate_receipt["index_sha256"]=hashlib.sha256(raw).hexdigest(); self.write(index_path,candidate_index); self.write(receipt_path,candidate_receipt)
    if accepted:
     result=vault.prepare_vault_inputs(self.state,D,self.art); self.assertEqual(json.loads(result.read_text())["cert_manager_chart_version"],version); shutil.rmtree(self.state/"vault-bootstrap-inputs")
    else:
     with self.assertRaises(vault.VaultInputsError): vault.prepare_vault_inputs(self.state,D,self.art)
    self.write(index_path,index); self.write(receipt_path,receipt)
 def test_cert_manager_receipt_version_does_not_normalize_away_v_prefix(self):
  receipt_path=self.state/"vault-artifact-mirror-receipt.json"; index_path=self.state/"release/rendered/installer-artifact-index.json"; receipt=json.loads(receipt_path.read_text()); index=json.loads(index_path.read_text())
  index["components"]["cert-manager-chart"]["version"]="v1.21.1"; receipt["artifacts"]["cert-manager-chart"]["version"]="1.21.1"; raw=json.dumps(index).encode(); receipt["index_sha256"]=hashlib.sha256(raw).hexdigest(); self.write(index_path,index); self.write(receipt_path,receipt)
  with self.assertRaises(vault.VaultInputsError): vault.prepare_vault_inputs(self.state,D,self.art)
 def test_vault_chart_version_remains_numeric_only(self):
  artifact=json.loads(self.art.read_text()); artifact["chart"]["version"]="v0.31.0"; self.write(self.art,artifact)
  with self.assertRaises(vault.VaultInputsError): vault.prepare_vault_inputs(self.state,D,self.art)
 def test_foreign_and_unexpected_rejected(self):
  data=json.loads(self.art.read_text()); data["images"]["server"]="999999999999.dkr.ecr.ap-northeast-1.amazonaws.com/x@sha256:"+"a"*64; self.write(self.art,data)
  with self.assertRaises(vault.VaultInputsError): vault.prepare_vault_inputs(self.state,D,self.art)
  self.assertFalse((self.state/"vault-bootstrap-inputs").exists())
 def test_existing_destination_is_not_overwritten(self):
  result=vault.prepare_vault_inputs(self.state,D,self.art); result.write_text("changed")
  with self.assertRaises(vault.VaultInputsError): vault.prepare_vault_inputs(self.state,D,self.art)
 def test_original_baseline_config_is_required_and_bound(self):
  path=self.state/"infrastructure-inputs/baseline.tfvars.json"; original=path.read_bytes(); path.unlink()
  with self.assertRaises(vault.VaultInputsError): vault.prepare_vault_inputs(self.state,D,self.art)
  data=json.loads(original); data["enable_vault_bootstrap_cluster_admin"]=True; self.write(path,data)
  with self.assertRaises(vault.VaultInputsError): vault.prepare_vault_inputs(self.state,D,self.art)
  self.assertFalse((self.state/"vault-bootstrap-inputs").exists())
 def test_sensitive_missing_and_foreign_baseline_values_are_rejected(self):
  path=self.state/"terraform-work/baseline-output.json"; original=json.loads(path.read_text())
  for name,field,value in (("vault_unseal_key_arn","sensitive",True),("vault_role_arn","value","arn:aws:iam::999999999999:role/vault"),("private_gitops_ecr_repository_urls","value",{"vault":self.repo,"vault_chart":self.repo+";unsafe"}),("private_subnet_ids","value",[])):
   with self.subTest(name=name):
    data=json.loads(json.dumps(original)); data[name][field]=value; self.write(path,data)
    with self.assertRaises(vault.VaultInputsError): vault.prepare_vault_inputs(self.state,D,self.art)
    self.assertFalse((self.state/"vault-bootstrap-inputs").exists())
  data=json.loads(json.dumps(original)); del data["vault_role_arn"]; self.write(path,data)
  with self.assertRaises(vault.VaultInputsError): vault.prepare_vault_inputs(self.state,D,self.art)
 def test_artifact_symlink_and_unexpected_keys_are_rejected(self):
  original=json.loads(self.art.read_text()); original["unexpected"]="ignored?"; self.write(self.art,original)
  with self.assertRaises(vault.VaultInputsError): vault.prepare_vault_inputs(self.state,D,self.art)
  target=self.root/"target.json"; self.art.rename(target); self.art.symlink_to(target)
  with self.assertRaises(vault.VaultInputsError): vault.prepare_vault_inputs(self.state,D,self.art)
 def test_semantically_identical_artifact_and_changed_input(self):
  result=vault.prepare_vault_inputs(self.state,D,self.art); before=result.read_bytes()
  value=json.loads(self.art.read_text()); self.art.write_text(json.dumps(value,indent=2))
  self.assertEqual(vault.prepare_vault_inputs(self.state,D,self.art).read_bytes(),before)
  value["images"]["server"]=self.repo+"@sha256:"+"c"*64; self.write(self.art,value)
  with self.assertRaises(vault.VaultInputsError): vault.prepare_vault_inputs(self.state,D,self.art)
  self.assertEqual(result.read_bytes(),before)
 def test_mirror_receipt_and_materialized_index_tampering_is_rejected(self):
  receipt_path=self.state/"vault-artifact-mirror-receipt.json"; index_path=self.state/"release/rendered/installer-artifact-index.json"
  original_receipt=json.loads(receipt_path.read_text()); original_index=json.loads(index_path.read_text())
  cases=(
   ("receipt release",lambda r,i:r.update(release_revision="d"*40)),
   ("receipt index",lambda r,i:r.update(index_sha256="0"*64)),
   ("chart ref",lambda r,i:r["artifacts"]["cert-manager-chart"].update(image_ref=self.cert_repo+"/wrong@"+self.digest)),
   ("chart digest",lambda r,i:r["artifacts"]["cert-manager-chart"].update(manifest_digest="sha256:"+"b"*64)),
   ("receipt chart version",lambda r,i:r["artifacts"]["cert-manager-chart"].update(version="1.21.2")),
   ("chart version",lambda r,i:i["components"]["cert-manager-chart"].update(version="latest")),
   ("cert source",lambda r,i:i["components"]["cert-manager-controller"].update(manifest_digest="sha256:"+"b"*64)),
   ("cert destination",lambda r,i:r["artifacts"]["cert-manager-controller"].update(image_ref=self.cert_repo+"/wrong@"+self.digest)),
   ("receipt cert digest",lambda r,i:r["artifacts"]["cert-manager-controller"].update(manifest_digest="sha256:"+"b"*64)),
   ("relay verification",lambda r,i:i["components"]["vault-audit-relay"].update(verification={"method":"input-hash-and-registry-digest","status":"passed"})),
   ("relay source digest",lambda r,i:i["components"]["vault-audit-relay"].update(manifest_digest="sha256:"+"d"*64)),
   ("relay destination",lambda r,i:r["artifacts"]["vault-audit-relay"].update(image_ref=self.relay_repo+"@sha256:"+"d"*64)),
  )
  for name,mutate in cases:
   with self.subTest(name=name):
    receipt=json.loads(json.dumps(original_receipt)); index=json.loads(json.dumps(original_index)); mutate(receipt,index)
    raw=json.dumps(index).encode(); self.write(index_path,json.loads(raw)); self.write(receipt_path,receipt)
    with self.assertRaises(vault.VaultInputsError): vault.prepare_vault_inputs(self.state,D,self.art)
    self.write(index_path,original_index); self.write(receipt_path,original_receipt)
if __name__=="__main__": unittest.main()

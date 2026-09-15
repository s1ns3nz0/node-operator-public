#!/usr/bin/env python3
# Check objective: Validate validator observation context and artifact receipt rules.
"""Exercise observation context with real resume and artifact receipt rules."""
import hashlib, importlib.util, json, os
from pathlib import Path
import shutil, sys, tempfile, unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path); value = importlib.util.module_from_spec(spec); sys.modules[name] = value; spec.loader.exec_module(value); return value
context = load(ROOT / "scripts/release/validator_observation_context.py", "observation_context")
fixture = load(ROOT / "scripts/ci/test-installer-artifact-receipt.py", "artifact_receipt_fixture")
delivery_fixture = load(ROOT / "scripts/ci/test-operational-log-delivery-terraform.py", "delivery_terraform_fixture")

ACCOUNT, REGION, DEPLOYMENT, REVISION = "123456789012", "ap-northeast-1", "hoodi-node", "e" * 40
KEY = "0x" + "a" * 96

class ContextTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name); self.bundle=self.root/"bundle"; self.work=self.root/"work"; self.bundle.mkdir(); self.work.mkdir(mode=0o700)
  (self.bundle/"source/scripts/release").mkdir(parents=True); (self.bundle/"rendered").mkdir()
  for name in ("interactive-hoodi-resume.py","installer_artifact_receipt.py","installer_artifact_mirror.py"): shutil.copy2(ROOT/"scripts/release"/name,self.bundle/"source/scripts/release"/name)
  self.put(self.bundle/"bundle-manifest.json",{"source_revision":REVISION},0o600)
  index,mirror,baseline,_=fixture.authority(); index["release_revision"]=REVISION; raw=json.dumps(index,sort_keys=True,separators=(",",":")).encode(); mirror["deployment_name"]=DEPLOYMENT; mirror["release_revision"]=REVISION; mirror["index_sha256"]=hashlib.sha256(raw).hexdigest(); self.raw=raw; self.mirror=mirror
  baseline.update({"deployment_account_id":{"sensitive":False,"type":"string","value":ACCOUNT},"cluster_name":{"sensitive":False,"type":"string","value":DEPLOYMENT},"validator_audit_bucket_name":{"sensitive":False,"type":"string","value":"node-validator-audit-123"},"validator_audit_prefix":{"sensitive":False,"type":"string","value":"validator/"},"validator_audit_reader_namespace":{"sensitive":False,"type":"string","value":"validator-observability"},"validator_audit_reader_service_account":{"sensitive":False,"type":"string","value":"validator-audit-reader"},"validator_audit_reader_role_arn":{"sensitive":False,"type":"string","value":f"arn:aws:iam::{ACCOUNT}:role/validator-audit-reader"},"validator_audit_kms_key_arn":{"sensitive":False,"type":"string","value":f"arn:aws:kms:{REGION}:{ACCOUNT}:key/12345678-1234-1234-1234-123456789abc"}}); self.baseline=baseline
  self.delivery=delivery_fixture.fixture_contract(ACCOUNT,REGION,DEPLOYMENT)
  baseline["operational_log_delivery"]={"sensitive":False,"type":["object",{}],"value":self.delivery}
  self.put(self.bundle/"rendered/installer-artifact-index.json",index,0o600,raw); self.put(self.work/"deployment-work/baseline-output.json",baseline,0o600); self.put(self.work/"deployment-work/vault-artifact-mirror-receipt.json",mirror,0o600); self.resume()
 def tearDown(self): self.temp.cleanup()
 def put(self,path,value,mode,raw=None): path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(raw if raw is not None else json.dumps(value,sort_keys=True,separators=(",",":")).encode()); os.chmod(path,mode)
 def resume(self):
  inputs=self.work/"inputs/hoodi-zero-release-inputs.json"; self.put(inputs,{"aws_account_id":ACCOUNT,"aws_region":REGION},0o600); keys=self.work/"keys"; keys.mkdir(); deposit=self.work/"custody/deposit.json"; runtime=self.work/"custody-verifier-runtime/receipt.json"; self.put(deposit,{"x":1},0o600); self.put(runtime,{"x":2},0o600)
  ceremony=self.work/"ceremony"; ceremony.mkdir(); signer=ceremony/"signer-ca.crt"; clients=ceremony/"known-clients.txt"; signer.write_text("ca"); clients.write_text("clients")
  completion={"schema_version":1,"operation_id":"b"*32,"validator_set":"hoodi-set","expected_public_key":KEY,"result":"onboarding-complete","public_outputs":{"signer_ca_sha256":hashlib.sha256(signer.read_bytes()).hexdigest(),"known_clients_sha256":hashlib.sha256(clients.read_bytes()).hexdigest()}}; self.put(self.work/"custody/custody-completion.json",completion,0o600)
  evidence=self.work/"evidence"; evidence.mkdir(mode=0o700); activation={"schema_version":1,"result":"activation-post-ready-head-bound","scope":"post-Ready private Beacon head lower bound only; not duty, finalization, signature, or end-to-end proof","validator_set":"hoodi-set","validator_public_key":KEY,"deployment_name":DEPLOYMENT,"release_revision":REVISION,"operation_id":"c"*32,"controllers":{"client_statefulset_uid":"client-controller","fence_deployment_uid":"fence-controller"},"pods":{"client_uid":"client-pod","fence_uid":"fence-pod"},"lease":{"uid":"lease-uid","holder_identity":"fence-pod"},"private_beacon":{"pod_uid":"beacon-pod","validator_index":"12","head_slot":12345}}; self.put(evidence/"activation-receipt.json",activation,0o600)
  audit_dir=self.work/"audit"; audit_dir.mkdir(mode=0o700); audit={"schema_version":1,"result":"socket-audit-challenge-emitted-and-root-revoked","aws_account_id":ACCOUNT,"aws_region":REGION,"deployment_name":DEPLOYMENT,"release_revision":REVISION,"operation_id":"d"*32,"marker_hmac":"hmac-sha256:"+"a"*64,"request_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","after_ms":1}; audit_path=audit_dir/"audit-challenge.json"; self.put(audit_path,audit,0o600)
  continuation={"keystore_dir":str(keys),"keystore_device":keys.stat().st_dev,"keystore_inode":keys.stat().st_ino,"public_key":KEY,"deposit_attestation_rel":"custody/deposit.json","deposit_attestation_sha256":hashlib.sha256(deposit.read_bytes()).hexdigest(),"runtime_receipt_rel":"custody-verifier-runtime/receipt.json","runtime_receipt_sha256":hashlib.sha256(runtime.read_bytes()).hexdigest(),"audit_operation_id":"d"*32,"audit_receipt_rel":"audit/audit-challenge.json","audit_completion_sha256":hashlib.sha256(audit_path.read_bytes()).hexdigest(),"validator_set":"hoodi-set","custody_operation_id":"b"*32,"custody_result_rel":"custody/custody-completion.json","custody_result_sha256":hashlib.sha256((self.work/"custody/custody-completion.json").read_bytes()).hexdigest(),"activation_operation_id":"c"*32,"activation_receipt_rel":"evidence/activation-receipt.json","activation_receipt_sha256":hashlib.sha256((evidence/"activation-receipt.json").read_bytes()).hexdigest()}
  manifest=self.bundle/"bundle-manifest.json"; resume={"schema_version":2,"bundle_manifest_sha256":hashlib.sha256(manifest.read_bytes()).hexdigest(),"release_revision":REVISION,"inputs_sha256":hashlib.sha256(inputs.read_bytes()).hexdigest(),"aws_account_id":ACCOUNT,"aws_region":REGION,"deployment_name":DEPLOYMENT,"inputs_rel":"inputs/hoodi-zero-release-inputs.json","work_rel":"deployment-work","session_rel":"private-eks-session.json","phase":"activated","continuation":continuation}; self.put(self.work/"interactive-resume.json",resume,0o600)
 def mutate(self,path,fn): value=json.loads(path.read_text()); fn(value); self.put(path,value,0o600)
 def test_valid_context_uses_receipt_destination_not_untrusted_index_image(self):
  value=context.load_context(self.bundle,self.work); self.assertEqual(value["identity"],{"validator_set":"hoodi-set","validator_public_key":KEY,"validator_index":"12","deployment_name":DEPLOYMENT,"release_revision":REVISION,"activation_slot":"12345"}); self.assertEqual(value["reader"],{"image":self.mirror["artifacts"]["vault-bootstrap"]["image_ref"],"bucket":"node-validator-audit-123","prefix":"validator/","namespace":"validator-observability","service_account":"validator-audit-reader","role_arn":f"arn:aws:iam::{ACCOUNT}:role/validator-audit-reader","kms_key_arn":f"arn:aws:kms:{REGION}:{ACCOUNT}:key/12345678-1234-1234-1234-123456789abc"}); self.assertEqual((value["aws_account_id"],value["aws_region"],value["deployment_name"],value["cluster_name"]),(ACCOUNT,REGION,DEPLOYMENT,DEPLOYMENT)); self.assertEqual(value["audit_challenge"],{"marker_hmac":"hmac-sha256:"+"a"*64,"after_ms":1,"request_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}); self.assertEqual(value["vault_security_log_group"],f"/aws/eks/{DEPLOYMENT}/validator-security"); self.assertEqual(value["artifact_index_sha256"],hashlib.sha256(self.raw).hexdigest())
 def test_well_formed_other_cluster_is_not_the_selected_deployment(self):
  context.load_context(self.bundle,self.work)
  self.mutate(self.work/"deployment-work/baseline-output.json",lambda x:x["cluster_name"].update(value="another-cluster"))
  self.assertRaises(context.ContextError,context.load_context,self.bundle,self.work)
 def test_operational_destinations_are_required_and_identity_bound(self):
  path=self.work/"deployment-work/baseline-output.json"
  self.assertEqual(context.load_context(self.bundle,self.work)["operational_log_delivery"],self.delivery)
  original=path.read_bytes()
  for change in (lambda x:x.pop("operational_log_delivery"),
                 lambda x:x["operational_log_delivery"]["value"]["cloudwatch"].pop(),
                 lambda x:x["operational_log_delivery"]["value"]["s3"].pop(),
                 lambda x:x["operational_log_delivery"]["value"].update(manage_config_recorder=True),
                 lambda x:x["operational_log_delivery"]["value"].update(account_id="999999999999"),
                 lambda x:x["operational_log_delivery"]["value"].update(region="ap-northeast-2"),
                 lambda x:x["operational_log_delivery"]["value"].update(deployment_name="other-node")):
   try:
    self.mutate(path,change)
    self.assertRaises(context.ContextError,context.load_context,self.bundle,self.work)
   finally: path.write_bytes(original)
 def test_identity_digest_archive_and_path_fail_closed(self):
  cases=(("digest",self.work/"deployment-work/vault-artifact-mirror-receipt.json",lambda x:x["artifacts"]["vault-bootstrap"].update(manifest_digest="sha256:"+"b"*64)),("archive",self.work/"deployment-work/baseline-output.json",lambda x:x["validator_audit_reader_namespace"].update(value="default")),("identity",self.work/"evidence/activation-receipt.json",lambda x:x["private_beacon"].update(validator_index="bad")),("path",self.work/"interactive-resume.json",lambda x:x.update(work_rel="other")),("account",self.work/"deployment-work/baseline-output.json",lambda x:x["deployment_account_id"].update(value="999999999999")),("cluster",self.work/"deployment-work/baseline-output.json",lambda x:x["cluster_name"].update(value="INVALID")),("terraform-shape",self.work/"deployment-work/baseline-output.json",lambda x:x["validator_audit_bucket_name"].pop("type")))
  for label,path,change in cases:
   with self.subTest(label=label):
    self.assertIsNotNone(context.load_context(self.bundle,self.work))
    original=path.read_bytes()
    try:
     self.mutate(path,change); self.assertRaises(context.ContextError,context.load_context,self.bundle,self.work)
    finally:
     path.write_bytes(original); os.chmod(path,0o600)

if __name__ == "__main__": unittest.main()

#!/usr/bin/env python3
# Check objective: Validate the non-Vault pre-EKS artifact copier.
"""Offline contract tests for the non-Vault pre-EKS artifact copier."""
from __future__ import annotations
import base64, importlib.util, json, os, subprocess, sys, tempfile, unittest
from unittest import mock
from pathlib import Path
from contextlib import nullcontext

ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/"scripts/release"))
spec=importlib.util.spec_from_file_location("full",ROOT/"scripts/release/installer_full_artifact_mirror.py"); full=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(full)
SHA="a"*40; DIGEST="sha256:"+"b"*64; ACCOUNT="123456789012"; REGION="ap-northeast-2"; NAME="node-operator"

class FullMirrorTests(unittest.TestCase):
 def test_payload_uses_local_source_without_source_registry_login(self):
  inventory=self.inventory()
  inventory["artifacts"][1]["source"]="999999999999.dkr.ecr.ap-northeast-1.amazonaws.com/deleted-source@"+DIGEST
  full.build_inventory=lambda *a,**k:inventory
  layouts=self.state/"verified-oci"; layouts.mkdir()
  calls,run=self.runner()
  with mock.patch("installer_oci_binding.payload_context", return_value=nullcontext(layouts)), mock.patch.object(full,"_describe",side_effect=[False,True,True]):
   full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=run,payload_dir=self.state,authenticated_bundle_manifest_sha256="a"*64)
  copies=[command for command,_ in calls if command[:2]==["docker","run"]]
  self.assertEqual(len(copies),1)
  self.assertIn("oci:/payload/argo-cd:root-"+DIGEST[7:19],copies[0])
  self.assertIn(str(layouts)+":/payload:ro",copies[0])
  self.assertIn("--preserve-digests",copies[0])
  self.assertFalse(any(value.startswith("docker://ghcr.io") for value in copies[0]))
  logins=[command for command,_ in calls if command[:3]==["aws","ecr","get-login-password"]]
  self.assertEqual(len(logins),1)
  self.assertEqual(logins[0][-1],REGION)
 def test_payload_required_rejection_has_no_runner_calls(self):
  (self.bundle/"rendered").mkdir(); (self.bundle/"rendered/installer-oci-payload-manifest.json").write_text("{}")
  calls,run=self.runner()
  with self.assertRaises(ValueError):
   full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=run)
  self.assertEqual(calls,[])
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.state=Path(self.temp.name)/"state"; self.work=self.state/"terraform-work"; self.inputs=Path(self.temp.name)/"inputs"; self.bundle=Path(self.temp.name)/"bundle"
  self.state.mkdir(mode=0o700); self.work.mkdir(mode=0o700); self.inputs.mkdir(); self.bundle.mkdir(); (self.work/"artifact-prerequisites.json").write_text("{}")
  self.discovery={"aws_account_id":ACCOUNT,"aws_region":REGION,"deployment_name":NAME}; self.repo=f"{NAME}-baseline-gitops-nodes"; self.registry=f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com"
  self.original=(full.build_inventory,full.load_projection,full.verify_pre_eks_vault_mirror)
  full.load_projection=lambda *a,**k:{"repositories":{self.repo:{"url":self.registry+"/"+self.repo}}}
  full.verify_pre_eks_vault_mirror=lambda *a,**k:{"schema_version":1,"status":"verified"}
 def tearDown(self):
  full.build_inventory,full.load_projection,full.verify_pre_eks_vault_mirror=self.original; self.temp.cleanup()
 def inventory(self,complete=True,source=True,two=False):
  image="ghcr.io/example/image@"+DIGEST if source else None
  rows=[{"component":"gitops-oci-mirror","required":True,"source":"ghcr.io/s1ns3nz0/node-operator/gitops-oci-mirror@sha256:"+"c"*64,"destination":None},{"component":"argo-cd","required":True,"source":image,"destination":self.registry+"/"+self.repo+"@"+DIGEST,"destination_tag":"reviewed-tag"}]
  if two: rows.append({"component":"dex","required":True,"source":"ghcr.io/example/dex@"+DIGEST,"destination":self.registry+"/"+self.repo+"-two@"+DIGEST,"destination_tag":"second-tag"})
  return {"complete":complete,"artifacts":rows}
 def runner(self,mode="success"):
  calls=[]
  def run(command,**kw):
   calls.append((command,kw))
   if command[:3]==["aws","sts","get-caller-identity"]: return subprocess.CompletedProcess(command,0,ACCOUNT if mode!="wrong-sts" else "000000000000","")
   if command[:3]==["aws","ecr","get-login-password"]: return subprocess.CompletedProcess(command,0,"password","")
   if command[:3]==["aws","ecr","describe-images"]:
    if mode in ("absent","copy-fails"): return subprocess.CompletedProcess(command,255,"","ImageNotFoundException")
    repo=command[command.index("--repository-name")+1]; tag=command[command.index("--image-ids")+1].split("=",1)[1]; digest=DIGEST
    if mode in ("wrong-digest","conflict"): digest="sha256:"+"d"*64
    tags=[] if mode=="missing-tag" else [tag,tag] if mode=="duplicate-tag" else [tag]
    return subprocess.CompletedProcess(command,0,json.dumps({"imageDetails":[{"registryId":ACCOUNT,"repositoryName":repo,"imageDigest":digest,"imageTags":tags}]}),"")
   if command[:2]==["docker","run"] and mode=="copy-fails": raise subprocess.CalledProcessError(1,command)
   return subprocess.CompletedProcess(command,0,"","")
  return calls,run
 def test_incomplete_or_bad_projection_makes_no_calls_or_marker(self):
  full.build_inventory=lambda *a,**k:self.inventory(False); calls,run=self.runner()
  with self.assertRaises(full.FullMirrorError): full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=run)
  self.assertEqual(calls,[]); self.assertFalse((self.state/"full-artifact-mirror-uncertain.json").exists())
  full.build_inventory=lambda *a,**k:self.inventory(); full.load_projection=lambda *a,**k:{"repositories":{}}
  with self.assertRaises(full.FullMirrorError): full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=run)
  self.assertEqual(calls,[])
 def test_real_malformed_canonical_catalog_makes_no_calls(self):
  full.build_inventory=self.original[0]
  path=self.bundle/"source/.ci/gitops"; path.mkdir(parents=True); (path/"approved-oci-artifacts.json").write_text("{")
  calls,run=self.runner()
  with self.assertRaises(full.FullMirrorError): full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=run)
  self.assertEqual(calls,[])
 def test_sts_copy_and_tag_digest_failures_leave_uncertain_marker(self):
  full.build_inventory=lambda *a,**k:self.inventory()
  for mode in ("wrong-sts","copy-fails","wrong-digest","missing-tag","duplicate-tag","conflict"):
   with self.subTest(mode=mode):
    calls,run=self.runner(mode)
    with self.assertRaises(full.FullMirrorError): full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=run)
    if mode!="wrong-sts":
     self.assertTrue((self.state/"full-artifact-mirror-uncertain.json").exists())
     if mode=="conflict": self.assertFalse(any(command[:2]==["docker","run"] for command,_ in calls))
     (self.state/"full-artifact-mirror-uncertain.json").unlink()
 def test_success_copies_absent_then_binds_tag_and_digest(self):
  full.build_inventory=lambda *a,**k:self.inventory(); calls,run=self.runner("absent")
  # First lookup absent, post-copy lookup present.
  original=run; seen=[False]
  def transition(command,**kw):
   if command[:3]==["aws","ecr","describe-images"] and not seen[0]: seen[0]=True; return subprocess.CompletedProcess(command,255,"","ImageNotFoundException")
   if command[:3]==["aws","ecr","describe-images"]:
    repo=command[command.index("--repository-name")+1]; tag=command[command.index("--image-ids")+1].split("=",1)[1]; return subprocess.CompletedProcess(command,0,json.dumps({"imageDetails":[{"registryId":ACCOUNT,"repositoryName":repo,"imageDigest":DIGEST,"imageTags":[tag]}]}),"")
   return original(command,**kw)
  receipt=full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=transition)
  value=json.loads(receipt.read_text()); self.assertEqual(value["artifacts"][0]["tag"],"reviewed-tag"); self.assertFalse((self.state/"full-artifact-mirror-uncertain.json").exists())
  self.assertTrue(any(command[:2]==["docker","pull"] and kwargs["timeout"]==full.DOCKER_TIMEOUT for command,kwargs in calls))
  self.assertTrue(any(command[:2]==["docker","run"] and kwargs["timeout"]==full.DOCKER_TIMEOUT for command,kwargs in calls))
  self.assertTrue(any(command[:2]==["aws","ecr"] and kwargs["timeout"]==full.TIMEOUT for command,kwargs in calls))
  _,present=self.runner(); self.assertEqual(full.verify(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=present),value)
  resume_calls,resume_runner=self.runner(); self.assertEqual(full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=resume_runner,resume=True),receipt)
  self.assertFalse(any(command[0]=="docker" or command[:3]==["aws","ecr","get-login-password"] for command,_ in resume_calls))
  crash_marker=self.state/"full-artifact-mirror-uncertain.json"; crash_marker.write_text(json.dumps({"crash_window":True}))
  crash_calls,crash_runner=self.runner(); self.assertEqual(full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=crash_runner,resume=True),receipt)
  self.assertTrue(crash_marker.exists()); self.assertFalse(any(command[0]=="docker" for command,_ in crash_calls)); crash_marker.unlink()
  (self.state/".full-artifact-mirror.lock").mkdir()
  with self.assertRaises(full.FullMirrorError): full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=resume_runner,resume=True)
  (self.state/".full-artifact-mirror.lock").rmdir()
  for key, replacement in (("vault_binding_sha256","0"*64),("artifacts",[])):
   broken=dict(value); broken[key]=replacement; receipt.write_text(json.dumps(broken))
   with self.assertRaises(full.FullMirrorError): full.verify(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=present)
  broken=dict(value); broken["extra"]=True; receipt.write_text(json.dumps(broken))
  with self.assertRaises(full.FullMirrorError): full.verify(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=present)
  with self.assertRaises(full.FullMirrorError): full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=present,resume=True)
 def test_bound_partial_marker_resumes_and_altered_or_locked_marker_does_not_call_aws(self):
  full.build_inventory=lambda *a,**k:self.inventory(); _,failed=self.runner("copy-fails")
  with self.assertRaises(full.FullMirrorError): full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=failed)
  marker=self.state/"full-artifact-mirror-uncertain.json"; self.assertTrue(marker.exists()); bound_marker=marker.read_bytes()
  calls,present=self.runner(); receipt=full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=present,resume=True)
  self.assertTrue(receipt.exists()); self.assertFalse(any(command[:2]==["docker","run"] for command,_ in calls))
  receipt.unlink(); marker.write_text(json.dumps({"schema_version":1}))
  calls,bad=self.runner()
  with self.assertRaises(full.FullMirrorError): full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=bad,resume=True)
  self.assertEqual(calls,[])
 def test_two_artifact_partial_resume_skips_first_and_copies_second(self):
  second=self.repo+"-two"; full.load_projection=lambda *a,**k:{"repositories":{self.repo:{"url":self.registry+"/"+self.repo},second:{"url":self.registry+"/"+second}}}; full.build_inventory=lambda *a,**k:self.inventory(two=True)
  copied=[]; present={"reviewed-tag":False,"second-tag":False}; fail_second=[True]
  def run(command,**kw):
   if command[:3]==["aws","sts","get-caller-identity"]: return subprocess.CompletedProcess(command,0,ACCOUNT,"")
   if command[:3]==["aws","ecr","get-login-password"]: return subprocess.CompletedProcess(command,0,"p","")
   if command[:3]==["aws","ecr","describe-images"]:
    tag=command[command.index("--image-ids")+1].split("=",1)[1]; repo=command[command.index("--repository-name")+1]
    if not present[tag]: return subprocess.CompletedProcess(command,255,"","ImageNotFoundException")
    return subprocess.CompletedProcess(command,0,json.dumps({"imageDetails":[{"registryId":ACCOUNT,"repositoryName":repo,"imageDigest":DIGEST,"imageTags":[tag]}]}),"")
   if command[:2]==["docker","run"]:
    tag=command[-1].rsplit(":",1)[1]; copied.append(tag)
    if tag=="second-tag" and fail_second[0]: raise subprocess.CalledProcessError(1,command)
    present[tag]=True
   return subprocess.CompletedProcess(command,0,"","")
  with self.assertRaises(full.FullMirrorError): full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=run)
  self.assertEqual(copied,["reviewed-tag","second-tag"]); fail_second[0]=False
  (self.state/".full-artifact-mirror.lock").mkdir()
  with self.assertRaises(full.FullMirrorError): full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=run,resume=True)
  (self.state/".full-artifact-mirror.lock").rmdir()
  full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=run,resume=True)
  self.assertEqual(copied,["reviewed-tag","second-tag","second-tag"])
 def test_early_failures_release_owned_lock(self):
  full.build_inventory=lambda *a,**k:self.inventory(); original_vault=full.verify_pre_eks_vault_mirror
  full.verify_pre_eks_vault_mirror=lambda *a,**k: (_ for _ in ()).throw(ValueError("fixture"))
  _,run=self.runner()
  with self.assertRaises(full.FullMirrorError): full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=run)
  self.assertFalse((self.state/".full-artifact-mirror.lock").exists())
  full.verify_pre_eks_vault_mirror=original_vault; _,bad_sts=self.runner("wrong-sts")
  with self.assertRaises(full.FullMirrorError): full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=bad_sts)
  self.assertFalse((self.state/".full-artifact-mirror.lock").exists())
  original_temp=full.tempfile.mkdtemp; full.tempfile.mkdtemp=lambda **k: (_ for _ in ()).throw(OSError("fixture"))
  try:
   _,run=self.runner()
   with self.assertRaises(full.FullMirrorError): full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=run)
   self.assertFalse((self.state/".full-artifact-mirror.lock").exists())
  finally: full.tempfile.mkdtemp=original_temp
 def test_private_source_ecr_login_is_cross_region_deduplicated_and_lazy(self):
  source_registry="999999999999.dkr.ecr.ap-southeast-1.amazonaws.com"; full.build_inventory=lambda *a,**k:self.inventory(); inv=self.inventory();inv["artifacts"][1]["source"]=source_registry+"/private/image@"+DIGEST;full.build_inventory=lambda *a,**k:inv
  calls=[]; seen=[False]
  def run(command,**kw):
   calls.append((command,kw))
   if command[:3]==["aws","sts","get-caller-identity"]:return subprocess.CompletedProcess(command,0,ACCOUNT,"")
   if command[:3]==["aws","ecr","describe-images"]:
    if not seen[0]:seen[0]=True;return subprocess.CompletedProcess(command,255,"","ImageNotFoundException")
    repo=command[command.index("--repository-name")+1];tag=command[command.index("--image-ids")+1].split("=",1)[1];return subprocess.CompletedProcess(command,0,json.dumps({"imageDetails":[{"registryId":ACCOUNT,"repositoryName":repo,"imageDigest":DIGEST,"imageTags":[tag]}]}),"")
   return subprocess.CompletedProcess(command,0,"password","")
  full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=run)
  regions=[x[x.index("--region")+1] for x,_ in calls if x[:3]==["aws","ecr","get-login-password"]];self.assertEqual(regions,["ap-southeast-1",REGION])
  receipt=self.state/"full-artifact-mirror-receipt.json";calls.clear();full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=run,resume=True);self.assertFalse(any(x[:3]==["aws","ecr","get-login-password"] for x,_ in calls))
 def test_private_source_login_failure_stops_before_copy(self):
  source="999999999999.dkr.ecr.ap-southeast-1.amazonaws.com/private/image@"+DIGEST;inv=self.inventory();inv["artifacts"][1]["source"]=source;full.build_inventory=lambda *a,**k:inv;calls=[]
  for failure in ('password','login'):
   calls.clear()
   def run(command,**kw):
    calls.append(command)
    if command[:3]==["aws","sts","get-caller-identity"]:return subprocess.CompletedProcess(command,0,ACCOUNT,"")
    if command[:3]==["aws","ecr","describe-images"]:return subprocess.CompletedProcess(command,255,"","ImageNotFoundException")
    if failure=='password' and command[:3]==["aws","ecr","get-login-password"] and command[-1]=='ap-southeast-1':raise subprocess.CalledProcessError(1,command)
    if failure=='login' and command[:3]==["aws","ecr","get-login-password"] and command[-1]=='ap-southeast-1':return subprocess.CompletedProcess(command,0,"","")
    return subprocess.CompletedProcess(command,0,"password","")
   with self.subTest(failure=failure):
    with self.assertRaises(full.FullMirrorError):full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=run)
    self.assertFalse(any(x[:2]==["docker","run"] for x in calls));self.assertTrue((self.state/"full-artifact-mirror-uncertain.json").exists());self.assertFalse((self.state/".full-artifact-mirror.lock").exists());self.assertFalse(any(path.name.startswith('.full-artifact-mirror-') for path in self.state.iterdir()))
    (self.state/"full-artifact-mirror-uncertain.json").unlink()
 def test_private_ecr_login_deduplicates_and_public_source_uses_destination_only(self):
  source_registry="999999999999.dkr.ecr.ap-southeast-1.amazonaws.com"; second=self.repo+"-two";full.load_projection=lambda *a,**k:{"repositories":{self.repo:{"url":self.registry+'/'+self.repo},second:{"url":self.registry+'/'+second}}};inv=self.inventory(two=True);inv["artifacts"][1]["source"]=source_registry+"/private/one@"+DIGEST;inv["artifacts"][2]["source"]=source_registry+"/private/two@"+DIGEST;full.build_inventory=lambda *a,**k:inv;calls=[];present=set()
  auth_snapshots=[]
  def run(command,**kw):
   calls.append((command,kw))
   if command[:3]==["aws","sts","get-caller-identity"]:return subprocess.CompletedProcess(command,0,ACCOUNT,"")
   if command[:3]==["aws","ecr","describe-images"]:
    tag=command[command.index("--image-ids")+1].split('=',1)[1];repo=command[command.index("--repository-name")+1]
    if tag not in present:return subprocess.CompletedProcess(command,255,"","ImageNotFoundException")
    return subprocess.CompletedProcess(command,0,json.dumps({"imageDetails":[{"registryId":ACCOUNT,"repositoryName":repo,"imageDigest":DIGEST,"imageTags":[tag]}]}),"")
   if command[:2]==["docker","run"]:
    volume=command[command.index("--volume")+1]; auth_path=Path(volume.split(":",1)[0])/"config.json"; auth_snapshots.append((json.loads(auth_path.read_text()),auth_path.stat().st_mode & 0o777,auth_path.parent.stat().st_mode & 0o777,auth_path.parent));present.add(command[-1].rsplit(':',1)[1])
   return subprocess.CompletedProcess(command,0,"password","")
  sent={'GITHUB_TOKEN':'sentinel','AWS_ACCESS_KEY_ID':'a','AWS_SECRET_ACCESS_KEY':'b','AWS_SESSION_TOKEN':'c','AWS_SECURITY_TOKEN':'d'}
  with mock.patch.dict(os.environ,sent,clear=False):
   full.mirror(self.state,self.bundle,self.discovery,"fixture",SHA,work_dir=self.work,inputs_dir=self.inputs,runner=run);self.assertEqual(os.environ.get('GITHUB_TOKEN'),'sentinel')
  self.assertFalse(any(x[:2]==['docker','login'] for x,_ in calls));self.assertEqual(len([x for x,_ in calls if x[:2]==['docker','run']]),2)
  fixture_auth=base64.b64encode(b"AWS:" + b"password").decode("ascii")
  expected={source_registry:{"auth":fixture_auth},self.registry:{"auth":fixture_auth}}
  self.assertTrue(all(snapshot[0]=={"auths":expected} and snapshot[1:3]==(0o600,0o700) for snapshot in auth_snapshots));self.assertTrue(all(not snapshot[3].exists() for snapshot in auth_snapshots))
 def test_same_registry_and_public_source_login_behavior(self):
  for source,expected in ((self.registry+'/private/image@'+DIGEST,1),('ghcr.io/example/public@'+DIGEST,1)):
   inv=self.inventory();inv['artifacts'][1]['source']=source;full.build_inventory=lambda *a,**k:inv;calls=[];seen=[False]
   def run(command,**kw):
    calls.append(command)
    if command[:3]==['aws','sts','get-caller-identity']:return subprocess.CompletedProcess(command,0,ACCOUNT,'')
    if command[:3]==['aws','ecr','describe-images']:
     if not seen[0]:seen[0]=True;return subprocess.CompletedProcess(command,255,'','ImageNotFoundException')
     repo=command[command.index('--repository-name')+1];tag=command[command.index('--image-ids')+1].split('=',1)[1];return subprocess.CompletedProcess(command,0,json.dumps({'imageDetails':[{'registryId':ACCOUNT,'repositoryName':repo,'imageDigest':DIGEST,'imageTags':[tag]}]}),'')
    return subprocess.CompletedProcess(command,0,'password','')
   full.mirror(self.state,self.bundle,self.discovery,'fixture',SHA,work_dir=self.work,inputs_dir=self.inputs,runner=run);self.assertEqual(len([x for x in calls if x[:3]==['aws','ecr','get-login-password']]),expected)
   (self.state/'full-artifact-mirror-receipt.json').unlink()

if __name__=="__main__": unittest.main()

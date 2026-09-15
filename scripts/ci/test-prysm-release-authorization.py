#!/usr/bin/env python3
# Check objective: Validate Prysm candidate-to-release authorization consistency.
"""Offline tests for Prysm candidate-to-release authorization consistency."""
from __future__ import annotations
import hashlib, json, shutil, sys, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(ROOT / "scripts/release"))
import prysm_publication_record as record
import prysm_release_authorization as authorization
C = "a" * 40; R = "b" * 40; D = "sha256:" + "c" * 64

class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp = Path(tempfile.mkdtemp()); self.bundle = self.tmp / "bundle"; source = self.bundle / "source"; shutil.copytree(ROOT / ".ci", source / ".ci"); (source / "release").mkdir(parents=True); (self.bundle / "rendered").mkdir(parents=True)
  self.addCleanup(shutil.rmtree, self.tmp, True)
  target = {"aws_account_id":"123456789012","aws_region":"ap-northeast-2","deployment_name":"node-operator","repository":"node-operator-baseline-validator-prysm","image_ref":f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-prysm@{D}","manifest_digest":D}
  self.record = record.create_record(source, release_revision=C, build_revision=C, input_sha256=record.build_input_sha256(source), run_id="42", **target)
  self.write()
 def write(self, stage=True, activation=True):
  rp = self.bundle / authorization.RECORD_PATH; rp.write_text(json.dumps(self.record)); ap = self.bundle / authorization.AUTH_PATH
  auth = {"schema_version":1,"candidate_revision":C,"record_sha256":hashlib.sha256(rp.read_bytes()).hexdigest(),"publication":{"repository":"s1ns3nz0/node-operator","workflow":"image-publish.yml","run_id":"42","artifact_id":"123"},"target":{"image_ref":self.record["target"]["image_ref"],"manifest_digest":D,"input_sha256":self.record["input_sha256"]},"approvals":{"stage_approved":stage,"activation_approved":activation}}
  ap.write_text(json.dumps(auth)); entries=[]
  for path in (authorization.AUTH_PATH, authorization.RECORD_PATH):
   data=(self.bundle/path).read_bytes(); entries.append({"path":path,"sha256":hashlib.sha256(data).hexdigest(),"size":len(data)})
  (self.bundle / "bundle-manifest.json").write_text(json.dumps({"schema_version":"v1","artifact":{"name":"node-operator-release-bundle.tar","media_type":"application/x-tar"},"source_revision":R,"entries":entries}))
 def rehash(self, path):
  manifest=json.loads((self.bundle/"bundle-manifest.json").read_text()); data=(self.bundle/path).read_bytes()
  for entry in manifest["entries"]:
   if entry["path"] == path: entry.update(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
  (self.bundle/"bundle-manifest.json").write_text(json.dumps(manifest))
 def valid(self, use="activation"): return authorization.validate_release_authorization(self.bundle, R, use)
 def test_candidate_can_differ_from_release(self): self.assertEqual(self.valid()["candidate_revision"], C)
 def test_stage_without_activation_is_not_activation(self):
  self.write(activation=False); self.assertEqual(self.valid("stage")["required_use"], "stage")
  with self.assertRaises(authorization.PrysmReleaseAuthorizationError): self.valid("activation")
 def test_tampering_and_missing_inputs_reject(self):
  def bad_run():
   self.record["publication"]["run_id"]="43"; path=self.bundle/authorization.RECORD_PATH; path.write_text(json.dumps(self.record)); self.rehash(authorization.RECORD_PATH)
   auth=json.loads((self.bundle/authorization.AUTH_PATH).read_text()); auth["record_sha256"]=hashlib.sha256(path.read_bytes()).hexdigest(); (self.bundle/authorization.AUTH_PATH).write_text(json.dumps(auth)); self.rehash(authorization.AUTH_PATH)
  def bad_input(): self.record["input_sha256"]="d"*64; (self.bundle/authorization.RECORD_PATH).write_text(json.dumps(self.record)); self.rehash(authorization.RECORD_PATH)
  mutations = [bad_run, bad_input, lambda: json.loads((self.bundle/authorization.AUTH_PATH).read_text()), lambda: (self.bundle/authorization.RECORD_PATH).unlink(), lambda: (self.bundle/"bundle-manifest.json").write_text("{}")]
  for mutate in mutations:
   with self.subTest(mutate=mutate):
    self.setUp(); value=mutate()
    if isinstance(value, dict): value["candidate_revision"]="d"*40; (self.bundle/authorization.AUTH_PATH).write_text(json.dumps(value)); self.rehash(authorization.AUTH_PATH)
    with self.assertRaises(authorization.PrysmReleaseAuthorizationError): self.valid()
 def test_false_boolean_and_symlink_reject(self):
  self.write(stage=1)
  with self.assertRaises(authorization.PrysmReleaseAuthorizationError): self.valid("stage")
  self.setUp(); path=self.bundle/authorization.RECORD_PATH; data=path.read_bytes(); path.unlink(); path.symlink_to(self.bundle/authorization.AUTH_PATH)
  with self.assertRaises(authorization.PrysmReleaseAuthorizationError): self.valid()
 def test_record_hash_artifact_and_release_source_reject(self):
  for field, value in (("record_sha256", "d"*64), ("artifact_id", "other-artifact"), ("artifact_id", "0"), ("artifact_id", "0123"), ("artifact_id", 123), ("artifact_id", True)):
   self.setUp(); auth=json.loads((self.bundle/authorization.AUTH_PATH).read_text())
   if field == "artifact_id": auth["publication"][field]=value
   else: auth[field]=value
   (self.bundle/authorization.AUTH_PATH).write_text(json.dumps(auth))
   self.rehash(authorization.AUTH_PATH)
   with self.assertRaises(authorization.PrysmReleaseAuthorizationError): self.valid()
  self.setUp()
  manifest=json.loads((self.bundle/"bundle-manifest.json").read_text()); manifest["source_revision"]="d"*40; (self.bundle/"bundle-manifest.json").write_text(json.dumps(manifest))
  with self.assertRaises(authorization.PrysmReleaseAuthorizationError): self.valid()
 def test_intermediate_directory_symlinks_reject(self):
  for relative in ("source/release", "rendered"):
   self.setUp(); path=self.bundle/relative; backup=path.with_name(path.name+"-real"); path.rename(backup); path.symlink_to(backup, target_is_directory=True)
   with self.assertRaises(authorization.PrysmReleaseAuthorizationError): self.valid()
if __name__ == "__main__": unittest.main()

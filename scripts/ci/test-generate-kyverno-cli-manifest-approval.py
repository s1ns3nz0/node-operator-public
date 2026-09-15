#!/usr/bin/env python3
"""Exercise clean and residual-risk Kyverno catalog proposals offline."""
import hashlib, json, shutil, subprocess, tempfile, unittest
from pathlib import Path
import importlib.util
ROOT=Path(__file__).resolve().parents[2]; DIGEST="sha256:"+"b"*64; IMAGE="123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-nodes@"+DIGEST
spec=importlib.util.spec_from_file_location("record",ROOT/"scripts/release/kyverno_cli_publication_record.py"); record=importlib.util.module_from_spec(spec); spec.loader.exec_module(record)
class Tests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.work=Path(self.temp.name); self.evidence=self.work/"evidence"; self.evidence.mkdir()
  policy=json.loads((ROOT/".ci/kyverno-cli/risk-acceptance.json").read_text()); raw={"source":{"type":"image","target":{"manifestDigest":DIGEST}},"descriptor":{"name":"grype","version":"0.118.0","db":{"status":{"valid":True,"built":"2026-09-14T00:00:00Z"}},"configuration":{"exclude":[],"only-fixed":False,"only-notfixed":False}},"ignoredMatches":[],"matches":[{"vulnerability":{"id":x["id"],"severity":"Unknown"},"artifact":{"name":x["package"],"version":x["version"]}} for x in policy["accepted_findings"]]}
  self.write("sbom.json",{"bomFormat":"CycloneDX","metadata":{"component":{"version":DIGEST}}}); self.write("grype.json",raw); sbom=self.evidence/"sbom.json"; self.write("scan.json",{"artifact_digest":DIGEST,"sbom_sha256":hashlib.sha256(sbom.read_bytes()).hexdigest(),"status":"blocked","findings":{"critical":0,"high":0,"medium":0,"low":0,"unknown":2}})
  decision=subprocess.check_output(["python3",str(ROOT/"scripts/ci/assess-kyverno-cli-risk-acceptance.py"),str(ROOT),str(self.evidence),record.input_sha256(ROOT)],text=True); self.write("risk-decision.json",json.loads(decision)); self.value=record.create_record(ROOT,release_revision="a"*40,image_ref=IMAGE,manifest_digest=DIGEST,run_id="42",risk_decision=self.evidence/"risk-decision.json")
 def write(self,name,value): (self.evidence/name).write_text(json.dumps(value))
 def render(self,value=None,evidence=True):
  path=self.work/"record.json"; path.write_text(json.dumps(value or self.value)); command=["python3",str(ROOT/"scripts/release/generate-kyverno-cli-manifest-approval.py"),"--source-root",str(ROOT),"--record",str(path)];
  if evidence: command += ["--risk-evidence-dir",str(self.evidence)]
  return subprocess.run(command,text=True,capture_output=True)
 def test_v2_renders_only_with_revalidated_evidence(self):
  result=self.render(); self.assertEqual(result.returncode,0,result.stderr); self.assertEqual(json.loads(result.stdout)["source"],IMAGE); self.assertNotEqual(self.render(evidence=False).returncode,0)
 def test_v2_evidence_tampering_blocks(self):
  for name, mutate in (("risk-decision.json",lambda x:x.update(raw_grype_sha256="0"*64)),("grype.json",lambda x:x.update(matches=[]))):
   with self.subTest(name=name):
    path=self.evidence/name; original=path.read_text()
    try:
     value=json.loads(original); mutate(value); self.write(name,value); self.assertNotEqual(self.render().returncode,0)
    finally: path.write_text(original)
 def test_v2_missing_raw_blocks(self):
  (self.evidence/"grype.json").unlink(); self.assertNotEqual(self.render().returncode,0)
 def test_v2_wrong_record_digest_blocks(self):
  # A record's digest is independently bound to the supplied risk decision.
  forged=json.loads(json.dumps(self.value)); forged["target"]["manifest_digest"]="sha256:"+"c"*64; self.assertNotEqual(self.render(forged).returncode,0)
 def test_expired_policy_blocks_evidence_revalidation(self):
  source=self.work/"expired-source"
  for relative in record.INPUTS:
   target=source/relative; target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(ROOT/relative,target)
  policy=source/".ci/kyverno-cli/risk-acceptance.json"; value=json.loads(policy.read_text()); value["expires_at"]="2020-01-01T00:00:00Z"; policy.write_text(json.dumps(value))
  result=subprocess.run(["python3",str(ROOT/"scripts/ci/assess-kyverno-cli-risk-acceptance.py"),str(source),str(self.evidence),record.input_sha256(source)],text=True,capture_output=True)
  self.assertNotEqual(result.returncode,0); self.assertIn("expired",result.stderr)
if __name__=="__main__": unittest.main()

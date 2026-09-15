#!/usr/bin/env python3
"""Check objective: Reject independent risk mutations using portable synthetic evidence."""
import copy, hashlib, importlib.util, json, shutil, subprocess, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('record',ROOT/'scripts/release/kyverno_cli_publication_record.py')
record=importlib.util.module_from_spec(spec); spec.loader.exec_module(record)
DIGEST='sha256:'+'b'*64

class Tests(unittest.TestCase):
 def setUp(self):
  temporary=tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup); self.root=Path(temporary.name)
  for relative in record.INPUTS:
   path=self.root/relative; path.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(ROOT/relative,path)
  self.evidence=self.root/'evidence'; self.evidence.mkdir()
  self.policy=json.loads((ROOT/'.ci/kyverno-cli/risk-acceptance.json').read_text())
  self.raw={'source':{'type':'image','target':{'manifestDigest':DIGEST}},'descriptor':{'name':'grype','version':'0.118.0','db':{'status':{'valid':True,'built':'2026-09-14T06:38:38Z'}},'configuration':{'exclude':[],'only-fixed':False,'only-notfixed':False}},'ignoredMatches':[],'matches':[{'vulnerability':{'id':f['id'],'severity':'Unknown'},'artifact':{'name':f['package'],'version':f['version']}} for f in self.policy['accepted_findings']]}
  self.write('grype.json',self.raw)
  self.write('sbom.json',{'bomFormat':'CycloneDX','metadata':{'component':{'version':DIGEST}}})
  self.write('scan.json',{'status':'blocked','artifact_digest':DIGEST,'sbom_sha256':hashlib.sha256((self.evidence/'sbom.json').read_bytes()).hexdigest(),'findings':{'critical':0,'high':0,'medium':0,'low':0,'unknown':2}})
 def write(self,name,value): (self.evidence/name).write_text(json.dumps(value))
 def assess(self,extra=()): return subprocess.run(['python3',str(ROOT/'scripts/ci/assess-kyverno-cli-risk-acceptance.py'),str(self.root),str(self.evidence),record.input_sha256(self.root),*extra],text=True,capture_output=True)
 def test_accept_and_record(self):
  result=self.assess(); self.assertEqual(result.returncode,0,result.stderr); decision=json.loads(result.stdout)
  self.assertEqual(decision['raw_scan_summary']['status'],'blocked'); self.write('risk-decision.json',decision)
  value=record.create_record(self.root,release_revision='a'*40,image_ref='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-nodes@'+DIGEST,manifest_digest=DIGEST,run_id='42',risk_decision=self.evidence/'risk-decision.json')
  self.assertFalse(value['verification']['scan_passed'])
 def test_scanner_version_matches_pinned_release_tool(self):
  installer=(ROOT/'scripts/ci/install-release-sca-tool.sh').read_text()
  self.assertIn('version="0.118.0"',installer)
  self.assertEqual(self.raw['descriptor']['version'],'0.118.0')
  self.raw['descriptor']['version']='0.111.0'; self.write('grype.json',self.raw)
  self.assertNotEqual(self.assess().returncode,0)
 def test_raw_mutations(self):
  for path,replacement in [(('descriptor','version'),'9.9.9'),(('source','target','manifestDigest'),'sha256:'+'c'*64),(('descriptor','db','status','valid'),False),(('descriptor','configuration','only-fixed'),True),(('matches',0,'artifact','version'),'v9')]:
   with self.subTest(path=path):
    value=copy.deepcopy(self.raw); target=value
    for key in path[:-1]: target=target[key]
    target[path[-1]]=replacement; self.write('grype.json',value); self.assertNotEqual(self.assess().returncode,0)
 def test_extra_findings(self):
  for severity in ('Unknown','High','Critical'):
   with self.subTest(severity=severity):
    value=copy.deepcopy(self.raw); value['matches'].append({'vulnerability':{'id':'OTHER','severity':severity},'artifact':{'name':'other','version':'v1'}})
    self.write('grype.json',value); self.assertNotEqual(self.assess().returncode,0)
 def test_build_mutation(self):
  path=self.root/'.ci/kyverno-cli/Dockerfile'; path.write_text(path.read_text()+'\n# change\n'); self.assertNotEqual(self.assess().returncode,0)
 def test_expiry(self):
  self.policy['expires_at']='2020-01-01T00:00:00Z'; (self.root/'.ci/kyverno-cli/risk-acceptance.json').write_text(json.dumps(self.policy)); self.assertNotEqual(self.assess().returncode,0)
 def test_summary_mismatch(self):
  value=json.loads((self.evidence/'scan.json').read_text()); value['findings']['critical']=1; self.write('scan.json',value); self.assertNotEqual(self.assess().returncode,0)
 def test_decision_tampering(self):
  result=self.assess(); self.assertEqual(result.returncode,0,result.stderr); value=json.loads(result.stdout); value['raw_grype_sha256']='0'*64
  self.write('risk-decision.json',value); self.assertNotEqual(self.assess(('--verify',str(self.evidence/'risk-decision.json'))).returncode,0)
if __name__=='__main__': unittest.main()

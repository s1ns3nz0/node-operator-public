#!/usr/bin/env python3
import json, subprocess, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; SCRIPT=ROOT/'scripts/release/render-deployment-bound-chart-values.py'
DIGEST='a'*64
def fixture(): return {"aws_account_id":"123456789012","aws_region":"us-east-1","deployment_name":"node-operator-example","chart":{"version":"0.1.42","digest":"sha256:"+DIGEST},"foundation":{"hoodi_nat_public_ip":"198.51.100.42","ebs_kms_key_arn":"arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"},"artifacts":{k:f"123456789012.dkr.ecr.us-east-1.amazonaws.com/node-operator-example-{n}@sha256:{DIGEST}" for k,n in (("nethermindImage","gitops-nodes"),("prysmImage","gitops-nodes"),("vaultAgentImage","baseline-gitops-vault"))}}
class T(unittest.TestCase):
 def invoke(self,v):
  with tempfile.TemporaryDirectory() as d:
   i=Path(d)/'in.json';o=Path(d)/'out.json';i.write_text(json.dumps(v));r=subprocess.run([str(SCRIPT),'--input',str(i),'--output',str(o)],text=True,capture_output=True);return r,json.loads(o.read_text()) if o.exists() else None
 def test_render(self):
  r,o=self.invoke(fixture());self.assertEqual(r.returncode,0);self.assertFalse(o['dast']['enabled']);self.assertEqual(o['clients']['deployment']['prysmP2PHostIp'],'198.51.100.42');self.assertNotIn('baseline-node-runtime',json.dumps(o))
 def test_rejects_missing_baseline_and_cross_scope(self):
  for mutate in (lambda x:x['foundation'].pop('hoodi_nat_public_ip'),lambda x:x['artifacts'].__setitem__('nethermindImage',x['artifacts']['nethermindImage'].replace('node-operator-example-','node-operator-baseline-')),lambda x:x['artifacts'].__setitem__('prysmImage',x['artifacts']['prysmImage'].replace('us-east-1','ap-northeast-2'))):
   x=fixture();mutate(x);r,_=self.invoke(x);self.assertEqual(r.returncode,65)
if __name__=='__main__':unittest.main()

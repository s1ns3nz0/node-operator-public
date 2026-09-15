#!/usr/bin/env python3
import importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]; P=ROOT/'scripts/release/build-deployment-bound-chart-values-input.py'
sys.path.insert(0,str(ROOT/'scripts/release')); S=importlib.util.spec_from_file_location('producer',P);M=importlib.util.module_from_spec(S);S.loader.exec_module(M)
D='a'*64; DISC={'aws_account_id':'123456789012','aws_region':'us-east-1','deployment_name':'node-operator-example'}
def ref(name,d=D):return f"123456789012.dkr.ecr.us-east-1.amazonaws.com/node-operator-example-{name}@sha256:{d}"
class T(unittest.TestCase):
 def call(self,receipt,manifest,capability=None):
  with tempfile.TemporaryDirectory() as directory:
   t=Path(directory); f=t/'f';b=t/'b';o=t/'o';f.write_text(json.dumps({'hoodi_nat_public_ip':'198.51.100.42'}));b.write_text(json.dumps({'ebs_kms_key_arn':{'value':'arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555'}}))
   argv=['x','--bundle',str(t),'--state',str(t),'--work',str(t),'--inputs',str(t),'--profile','p','--release','a'*40,'--account',DISC['aws_account_id'],'--region',DISC['aws_region'],'--deployment',DISC['deployment_name'],'--foundation',str(f),'--baseline',str(b),'--output',str(o)]
   receipt=receipt or {**DISC,'artifacts':[{'component':'nethermind','image_ref':ref('gitops-nodes')},{'component':'prysm-beacon','image_ref':ref('gitops-nodes')},{'component':'node-operator-client-chart','image_ref':ref('baseline-gitops-client/node-operator-client')}]};manifest=manifest or {'manifest':{'images':{'agent':ref('baseline-gitops-vault'),'injector':ref('wrong-injector')}}}
   with patch.object(sys,'argv',argv),patch.object(M,'validate_release_authorization',return_value={'target':{'chart_version':'0.1.42','manifest_digest':'sha256:'+D}}),patch.object(M,'verify',return_value=receipt),patch.object(M,'verify_pre_eks_vault_mirror',return_value=manifest),patch.object(M,'verify_chart_capability',side_effect=capability) as verifier: rc=M.main()
   return rc,json.loads(o.read_text()) if o.exists() else None,verifier.call_args
 def test_server_agent_binding(self):
  rc,v,_=self.call({},{ });self.assertEqual(rc,0);self.assertEqual(v['clients']['vaultAgentImage'],ref('baseline-gitops-vault'))
 def test_missing_receipt_component_fails(self):
  rc,_,_=self.call({**DISC,'artifacts':[]},{});self.assertEqual(rc,65)
 def test_old_chart_capability_rejection_prevents_output(self):
  rc,_,_=self.call({},{ },M.CapabilityError('old chart lacks deployment profile'));self.assertEqual(rc,65)
 def test_selected_profile_overrides_ambient_profile(self):
  with patch.dict(os.environ,{'AWS_PROFILE':'ambient-different-profile'},clear=False): rc,_,call=self.call({},{ })
  self.assertEqual(rc,0);self.assertEqual(call.args[-1],'p')
if __name__=='__main__':unittest.main()

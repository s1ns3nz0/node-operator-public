#!/usr/bin/env python3
# Check objective: Validate client-chart candidate-to-release authorization evidence.
from __future__ import annotations
import base64,hashlib,json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts/release'))
import client_chart_release_authorization as c
R='a'*40;D='sha256:'+'b'*64;A='sha256:'+'c'*64;I=f'123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-client/node-operator-client@{D}'
class T(unittest.TestCase):
 def ev(self):
  p={'buildDefinition':{'buildType':'https://node-operator.example/gitops-chart/v1','resolvedDependencies':[{'uri':'git+https://github.com/s1ns3nz0/node-operator-gitops','digest':{'gitCommit':R}}]},'runDetails':{'builder':{'id':c.BUILDER}}};s={'_type':'https://in-toto.io/Statement/v1','subject':[{'name':'123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-client/node-operator-client','digest':{'sha256':D[7:]}}],'predicateType':'https://slsa.dev/provenance/v1','predicate':p}
  v={c.NAMES[0]:{'schema_version':'v1','oci_digest':D,'chart_archive_digest':A,'chart_version':'0.1.37'},c.NAMES[1]:{'bomFormat':'CycloneDX','metadata':{'component':{'name':'node-operator-client-0.1.37.tgz','version':A},'tools':{'components':[{'name':'syft'}]}}},c.NAMES[2]:{'matches':[],'descriptor':{'name':'grype','version':'1','db':{'status':{'valid':True,'providers':['x']}},'configuration':{'ignore':[],'exclude':[],'only-fixed':False,'only-notfixed':False,'show-suppressed':True}},'source':{'type':'file','target':'node-operator-client-0.1.37.tgz'}},c.NAMES[3]:p,c.NAMES[4]:{'payloadType':'application/vnd.in-toto+json','payload':base64.b64encode(json.dumps(s).encode()).decode(),'signatures':[{'sig':'x'}]}}
  return {k:json.dumps(x).encode() for k,x in v.items()}
 def au(self,e):return {'schema_version':1,'source_revision':R,'publication':{'repository':'s1ns3nz0/node-operator-gitops','workflow':'publish-oci.yml','run_id':'1','artifact_id':'2','artifact_name':'gitops-chart-evidence-x','run_number':'37'},'target':{'image_ref':I,'manifest_digest':D,'chart_archive_digest':A,'chart_version':'0.1.37'},'evidence_sha256':{k:hashlib.sha256(v).hexdigest() for k,v in e.items()},'approvals':{'stage_approved':True,'activation_approved':False}}
 def test_ok_and_reject(self):
  e=self.ev();a=self.au(e);self.assertEqual(c.validate_candidate_authorization(a,e)['target']['chart_version'],'0.1.37')
  x=json.loads(e[c.NAMES[2]]);x['ignoredMatches']=[{'match':{'vulnerability':{'severity':'Unknown'}}}];e[c.NAMES[2]]=json.dumps(x).encode();a=self.au(e)
  with self.assertRaises(c.ClientChartAuthorizationError):c.validate_candidate_authorization(a,e)
  e=self.ev();a=self.au(e);e[c.NAMES[0]]=b'{"x":1,"x":2}';a=self.au(e)
  with self.assertRaises(c.ClientChartAuthorizationError):c.validate_candidate_authorization(a,e)
  for name,change in ((c.NAMES[0],lambda x:x.update(chart_archive_digest=D)),(c.NAMES[2],lambda x:x.update(matches=[{'vulnerability':{'severity':'banana'}}])),(c.NAMES[2],lambda x:x.update(matches=[{'vulnerability':{'severity':'High'}}])),(c.NAMES[3],lambda x:x['buildDefinition'].update(resolvedDependencies=[]))):
   e=self.ev();a=self.au(e); value=json.loads(e[name]);change(value);e[name]=json.dumps(value).encode();a=self.au(e)
   with self.assertRaises(c.ClientChartAuthorizationError):c.validate_candidate_authorization(a,e)
  e=self.ev();a=self.au(e);a['approvals']['stage_approved']=False
  with self.assertRaises(c.ClientChartAuthorizationError):c.validate_candidate_authorization(a,e)
  e=self.ev();a=self.au(e)
  with self.assertRaises(c.ClientChartAuthorizationError):c.validate_candidate_authorization(a,e,'activation')
 def test_release_layout_manifest_and_symlink_rejections(self):
  e=self.ev();a=self.au(e)
  with tempfile.TemporaryDirectory() as temporary:
   b=Path(temporary)/'bundle';(b/'source/release').mkdir(parents=True);(b/c.RECORD_DIR).mkdir(parents=True)
   (b/c.AUTH_PATH).write_text(json.dumps(a)); entries=[]
   for n,raw in e.items():
    p=b/c.RECORD_DIR/n;p.write_bytes(raw);entries.append({'path':f'{c.RECORD_DIR}/{n}','sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw)})
   raw=(b/c.AUTH_PATH).read_bytes();entries.append({'path':c.AUTH_PATH,'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw)})
   (b/'bundle-manifest.json').write_text(json.dumps({'schema_version':'v1','artifact':{},'source_revision':'d'*40,'entries':entries}))
   self.assertEqual(c.validate_release_authorization(b,'d'*40,'stage')['target']['chart_version'],'0.1.37')
   (b/c.RECORD_DIR/'extra.json').write_text('{}')
   with self.assertRaises(c.ClientChartAuthorizationError):c.validate_release_authorization(b,'d'*40,'stage')
   (b/c.RECORD_DIR/'extra.json').unlink();(b/c.RECORD_DIR/c.NAMES[0]).write_text('{}')
   with self.assertRaises(c.ClientChartAuthorizationError):c.validate_release_authorization(b,'d'*40,'stage')
   (b/c.RECORD_DIR/c.NAMES[0]).unlink();(b/c.RECORD_DIR/c.NAMES[0]).symlink_to('missing')
   with self.assertRaises(c.ClientChartAuthorizationError):c.validate_release_authorization(b,'d'*40,'stage')
 def test_parent_symlinks_reject(self):
  import shutil
  for relative in ('source','source/release','rendered','rendered/client-chart-publication-records'):
   with tempfile.TemporaryDirectory() as temporary:
    b=Path(temporary)/'bundle';(b/'source/release').mkdir(parents=True);(b/c.RECORD_DIR).mkdir(parents=True);e=self.ev();a=self.au(e);(b/c.AUTH_PATH).write_text(json.dumps(a));entries=[]
    for n,raw in e.items():
     p=b/c.RECORD_DIR/n;p.write_bytes(raw);entries.append({'path':f'{c.RECORD_DIR}/{n}','sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw)})
    raw=(b/c.AUTH_PATH).read_bytes();entries.append({'path':c.AUTH_PATH,'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw)});(b/'bundle-manifest.json').write_text(json.dumps({'schema_version':'v1','artifact':{},'source_revision':'d'*40,'entries':entries}))
    self.assertEqual(c.validate_release_authorization(b,'d'*40,'stage')['target']['chart_version'],'0.1.37')
    path=b/relative;target=Path(temporary)/'moved';path.rename(target);path.symlink_to(target,target_is_directory=True)
    with self.assertRaises(c.ClientChartAuthorizationError):c.validate_release_authorization(b,'d'*40,'stage')
if __name__=='__main__':unittest.main()

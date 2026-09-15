#!/usr/bin/env python3
# Check objective: Verify Prysm mTLS publication-record retrieval with mocked data.
"""Offline mocked retrieval tests for the Prysm publication record."""
from __future__ import annotations
import hashlib,json,shutil,stat,sys,tempfile,unittest,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts/release'));sys.path.insert(0,str(ROOT/'scripts/ci'))
import prysm_publication_record as rec
import importlib.util
spec=importlib.util.spec_from_file_location('fetch',ROOT/'scripts/ci/fetch-prysm-mtls-publication-record.py'); fetch=importlib.util.module_from_spec(spec);spec.loader.exec_module(fetch)
ORIGINAL=fetch.generic()
C='a'*40;D='sha256:'+'b'*64
class T(unittest.TestCase):
 def setUp(self):
  self.d=Path(tempfile.mkdtemp(dir=ROOT));self.addCleanup(shutil.rmtree,self.d,True);self.source=self.d/'source';shutil.copytree(ROOT/'.ci',self.source/'.ci');self.out=self.d/'out';target={'aws_account_id':'123456789012','aws_region':'ap-northeast-2','deployment_name':'node-operator','repository':'node-operator-baseline-validator-prysm','image_ref':f'123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-prysm@{D}','manifest_digest':D};self.record=rec.create_record(self.source,release_revision=C,build_revision=C,input_sha256=rec.build_input_sha256(self.source),run_id='42',**target);self.raw=json.dumps(self.record).encode();self.auth=self.d/'auth.json';self.auth.write_text(json.dumps({'schema_version':1,'candidate_revision':C,'record_sha256':hashlib.sha256(self.raw).hexdigest(),'publication':{'repository':'s1ns3nz0/node-operator','workflow':'image-publish.yml','run_id':'42','artifact_id':'7'},'target':{'image_ref':target['image_ref'],'manifest_digest':D,'input_sha256':self.record['input_sha256']},'approvals':{'stage_approved':True,'activation_approved':False}}));self.archive=self.d/'a.zip';
  with zipfile.ZipFile(self.archive,'w') as z:
   info=zipfile.ZipInfo('prysm-mtls-publication-record.json');info.create_system=3;info.external_attr=(stat.S_IFREG|0o600)<<16;z.writestr(info,self.raw)
  self.run={'id':42,'repository':{'full_name':'s1ns3nz0/node-operator'},'head_repository':{'full_name':'s1ns3nz0/node-operator'},'head_sha':C,'head_branch':'main','event':'workflow_dispatch','status':'completed','conclusion':'success','path':'.github/workflows/image-publish.yml'};self.artifacts={'artifacts':[{'id':7,'name':f'prysm-mtls-publication-record-{C}','expired':False,'workflow_run':{'id':42,'head_sha':C}}]}
  class G:
   FetchError=ORIGINAL.FetchError
   run_is_trusted=staticmethod(ORIGINAL.run_is_trusted)
   def gh_json(s,*x):return self.run
   def list_artifacts(s,*x):return self.artifacts
   def gh_zip(s,e,d):shutil.copy2(self.archive,d)
   def extract_record(s,a,c,stage):return fetch.generic_real.extract_record(a,c,stage)
   publish=staticmethod(ORIGINAL.publish)
  fetch.generic_real=ORIGINAL;fetch.generic=lambda:G()
 def test_success_and_rejections(self):
  fetch.retrieve(self.auth,self.source,self.out);self.assertEqual([p.name for p in self.out.iterdir()],['prysm-mtls-publication-record.json']);self.assertEqual((self.out/'prysm-mtls-publication-record.json').stat().st_mode&0o777,0o600);self.assertEqual(self.out.stat().st_mode&0o777,0o700)
  for edit in ('hash','artifact','unsafe'):
   self.setUp();a=json.loads(self.auth.read_text())
   if edit=='hash':a['record_sha256']='c'*64;self.auth.write_text(json.dumps(a))
   elif edit=='artifact':a['publication']['artifact_id']='8';self.auth.write_text(json.dumps(a))
   else:
    with zipfile.ZipFile(self.archive,'w') as z:z.writestr('../prysm-mtls-publication-record.json',self.raw)
   with self.assertRaises(fetch.FetchPrysmError):fetch.retrieve(self.auth,self.source,self.out)
   self.assertFalse(self.out.exists())
  self.setUp();self.out.mkdir();(self.out/'sentinel').write_text('keep')
  with self.assertRaises(fetch.FetchPrysmError):fetch.retrieve(self.auth,self.source,self.out)
  self.assertEqual((self.out/'sentinel').read_text(),'keep')
 def test_trusted_run_and_artifact_metadata_reject(self):
  cases=[('head_branch','feature'),('head_sha','d'*40),('conclusion','failure'),('path','other.yml'),('id',43)]
  for key,value in cases:
   self.setUp();self.run[key]=value
   with self.assertRaises(fetch.FetchPrysmError):fetch.retrieve(self.auth,self.source,self.out)
   self.assertFalse(self.out.exists())
 def test_context_duplicate_auth_and_output_ancestry_reject(self):
  for key,value in (('input_sha256','d'*64),('manifest_digest','sha256:'+'d'*64)):
   self.setUp();auth=json.loads(self.auth.read_text());auth['target'][key]=value;self.auth.write_text(json.dumps(auth))
   with self.assertRaises(fetch.FetchPrysmError):fetch.retrieve(self.auth,self.source,self.out)
  self.setUp();self.auth.write_text('{"schema_version":1,"schema_version":1}')
  with self.assertRaises(fetch.FetchPrysmError):fetch.retrieve(self.auth,self.source,self.out)
  self.setUp();real=self.d/'real';real.mkdir();parent=self.d/'link';parent.symlink_to(real,target_is_directory=True)
  with self.assertRaises(fetch.FetchPrysmError):fetch.retrieve(self.auth,self.source,parent/'out')
  for mutate in (lambda a:a.update(expired=True),lambda a:a.update(id=True),lambda a:a.update(workflow_run={'id':True,'head_sha':C}),lambda a:a.update(name='wrong')):
   self.setUp();mutate(self.artifacts['artifacts'][0])
   with self.assertRaises(fetch.FetchPrysmError):fetch.retrieve(self.auth,self.source,self.out)
   self.assertFalse(self.out.exists())
if __name__=='__main__':unittest.main()

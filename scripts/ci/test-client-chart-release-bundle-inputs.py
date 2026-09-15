#!/usr/bin/env python3
# Check objective: Verify authorized client-chart evidence packaging in a disposable Git tree.
"""Exercise authorized client-chart evidence packaging in a disposable Git tree."""
from __future__ import annotations
import importlib.util, hashlib, json, os
from pathlib import Path
import shutil, subprocess, tarfile, tempfile, unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("chart_fixture",ROOT/"scripts/ci/test-fetch-client-chart-publication-records.py")
fixture_module=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(fixture_module)

class T(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.base=Path(self.tmp.name).resolve(); self.repo=self.base/'repo'
  subprocess.run(['git','clone','--quiet','--no-local',str(ROOT),str(self.repo)],check=True)
  subprocess.run(["python3", str(ROOT / "scripts/ci/reset-release-authorization-fixture.py"), str(self.repo)], check=True)
  subprocess.run(['git','-C',str(self.repo),'config','user.email','test@example.invalid'],check=True);subprocess.run(['git','-C',str(self.repo),'config','user.name','test'],check=True)
  for p in ('scripts/ci/build-release-bundle.sh','scripts/ci/test-build-release-bundle.sh','scripts/release/client_chart_release_authorization.py'):
   target=self.repo/p;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/p,target)
  subprocess.run(['git','-C',str(self.repo),'add','scripts'],check=True);subprocess.run(['git','-C',str(self.repo),'commit','--allow-empty','--quiet','-m','chart candidate helper'],check=True)
  self.candidate=self.rev(); self.records=self.base/'records';self.records.mkdir()
  helper=fixture_module.FetchClientChartTests('test_retrieves_exact_authorized_five_file_evidence');helper.setUp()
  try: self.evidence=helper._evidence()
  finally: helper.tearDown()
  for n,b in self.evidence.items():(self.records/n).write_bytes(b)
  digest='sha256:'+'a'*64; archive='sha256:'+'b'*64
  auth={'schema_version':1,'source_revision':fixture_module.SOURCE,'publication':{'repository':'s1ns3nz0/node-operator-gitops','workflow':'publish-oci.yml','run_id':'1','artifact_id':'2','artifact_name':'gitops-chart-evidence-test','run_number':'37'},'target':{'image_ref':f'123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-client/node-operator-client@{digest}','manifest_digest':digest,'chart_archive_digest':archive,'chart_version':'0.1.37'},'evidence_sha256':{n:hashlib.sha256(b).hexdigest() for n,b in self.evidence.items()},'approvals':{'stage_approved':True,'activation_approved':False}}
  p=self.repo/'release/client-chart-publication-authorization.json';p.write_text(json.dumps(auth,sort_keys=True));subprocess.run(['git','-C',str(self.repo),'add',str(p.relative_to(self.repo))],check=True);subprocess.run(['git','-C',str(self.repo),'commit','--quiet','-m','authorize chart'],check=True);self.release=self.rev()
  self.bin=self.base/'bin';self.bin.mkdir();(self.bin/'syft').write_text('#!/bin/sh\no="";n="";v="";while [ "$#" -gt 0 ];do case "$1" in --output)o="${2#cyclonedx-json=}";shift;;--source-name)n=$2;shift;;--source-version)v=$2;shift;;esac;shift;done;printf \'{"bomFormat":"CycloneDX","metadata":{"component":{"name":"%s","version":"%s"},"tools":{"components":[{"name":"syft"}]}},"components":[]}\\n\' "$n" "$v">"$o"\n');(self.bin/'syft').chmod(0o755)
 def tearDown(self):self.tmp.cleanup()
 def rev(self):return subprocess.check_output(['git','-C',str(self.repo),'rev-parse','HEAD'],text=True).strip()
 def invoke(self,out,*args):return subprocess.run([str(self.repo/'scripts/ci/build-release-bundle.sh'),*args,str(out)],cwd=self.repo,env={**os.environ,'PATH':f'{self.bin}:{os.environ["PATH"]}'},text=True,capture_output=True,timeout=90)
 def publication_records(self):
  d=self.base/'publication-records';d.mkdir()
  for component,method,letter in (('vault-bootstrap','input-hash-and-registry-digest','a'),('vault-audit-relay','cosign-and-slsa','b'),('gitops-oci-mirror','input-hash-and-registry-digest','c')):
   digest='sha256:'+letter*64;v={'schema_version':1,'component':component,'kind':'image','release_revision':self.release,'build_revision':self.release,'third_party_source_revision':None,'image_ref':f'ghcr.io/example/{component}@{digest}','manifest_digest':digest,'input_sha256':letter*64,'publication':{'workflow':'image-publish.yml','run_id':'1','invocation':'test'},'verification':{'method':method,'status':'passed'}};(d/f'{component}-publication-record.json').write_text(json.dumps(v))
  return d
 def test_authorized_missing_tamper_extra_symlink_orphan_and_repeat(self):
  first=self.base/'first';r=self.invoke(first,'--client-chart-publication-records',str(self.records));self.assertEqual(r.returncode,0,r.stderr)
  second=self.base/'second';self.assertEqual(self.invoke(second,'--client-chart-publication-records',str(self.records)).returncode,0);self.assertEqual((first/'node-operator-release-bundle.tar').read_bytes(),(second/'node-operator-release-bundle.tar').read_bytes())
  extracted=self.base/'extract';extracted.mkdir()
  with tarfile.open(first/'node-operator-release-bundle.tar') as archive:archive.extractall(extracted,filter='data')
  manifest=json.loads((extracted/'bundle-manifest.json').read_text());entries={item['path']:item['sha256'] for item in manifest['entries']}
  for name,raw in self.evidence.items():
   path=f'rendered/client-chart-publication-records/{name}';self.assertEqual((extracted/path).read_bytes(),raw);self.assertEqual(entries[path],hashlib.sha256(raw).hexdigest())
  for label,action in (('missing',lambda d:(d/'gitops-chart-subject.json').unlink()),('extra',lambda d:(d/'extra.json').write_text('{}')),('tamper',lambda d:(d/'gitops-chart-subject.json').write_bytes(b'{}'))):
   d=self.base/(label+'-records');shutil.copytree(self.records,d);action(d);out=self.base/(label+'-out');self.assertNotEqual(self.invoke(out,'--client-chart-publication-records',str(d)).returncode,0);self.assertFalse(out.exists())
  link=self.base/'linked';shutil.copytree(self.records,link);(link/'gitops-chart-subject.json').unlink();(link/'gitops-chart-subject.json').symlink_to(self.records/'gitops-chart-subject.json');self.assertNotEqual(self.invoke(self.base/'link-out','--client-chart-publication-records',str(link)).returncode,0)
  repro=self.base/'repro'; env={**os.environ,'PATH':f'{self.bin}:{os.environ["PATH"]}'}
  result=subprocess.run([str(self.repo/'scripts/ci/test-build-release-bundle.sh'),'--publication-records-dir',str(self.publication_records()),'--client-chart-publication-records',str(self.records),str(repro)],cwd=self.repo,env=env,text=True,capture_output=True,timeout=180)
  self.assertEqual(result.returncode,0,result.stderr)
  subprocess.run(['git','-C',str(self.repo),'checkout','--quiet',self.candidate],check=True);self.assertNotEqual(self.invoke(self.base/'orphan','--client-chart-publication-records',str(self.records)).returncode,0)
  legacy=self.base/'legacy';self.assertEqual(self.invoke(legacy).returncode,0)
if __name__=='__main__':unittest.main()

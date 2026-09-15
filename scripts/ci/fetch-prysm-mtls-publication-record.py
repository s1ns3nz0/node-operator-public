#!/usr/bin/env python3
"""Read-only retrieval of one authorization-bound Prysm candidate record.

This does not authenticate a release bundle, verify Cosign/ECR, or activate a
validator.  Callers must do those checks before relying on this local result.
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, shutil, stat, sys, tempfile
from pathlib import Path
from typing import Any

ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/"scripts/release"))
from prysm_publication_record import PrysmPublicationRecordError, validate_record
SHA40=__import__('re').compile(r'^[a-f0-9]{40}$'); RUN=__import__('re').compile(r'^[1-9][0-9]*$'); MAX=4*1024*1024
class FetchPrysmError(ValueError): pass
def fail(m:str): raise FetchPrysmError(m)
def generic():
 spec=importlib.util.spec_from_file_location('generic',ROOT/'scripts/ci/fetch-release-publication-records.py'); module=importlib.util.module_from_spec(spec); assert spec and spec.loader; spec.loader.exec_module(module); return module
def read(path:Path)->tuple[Any,bytes]:
 try:
  info=path.lstat()
  if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size>MAX: fail('input is unsafe')
  raw=path.read_bytes()
  def pairs(items):
   result={}
   for key,value in items:
    if key in result: fail('duplicate JSON key')
    result[key]=value
   return result
  return json.loads(raw.decode(),object_pairs_hook=pairs),raw
 except (OSError,UnicodeDecodeError,json.JSONDecodeError) as e: raise FetchPrysmError('input is invalid') from e
def authorization(path:Path)->dict[str,Any]:
 value,_=read(path)
 if not isinstance(value,dict) or set(value)!={'schema_version','candidate_revision','record_sha256','publication','target','approvals'} or type(value['schema_version']) is not int or value['schema_version']!=1 or not isinstance(value['candidate_revision'],str) or not SHA40.fullmatch(value['candidate_revision']) or not isinstance(value['record_sha256'],str) or not __import__('re').fullmatch(r'[a-f0-9]{64}',value['record_sha256']): fail('authorization is invalid')
 p=value['publication']; t=value['target']; a=value['approvals']
 if not isinstance(p,dict) or set(p)!={'repository','workflow','run_id','artifact_id'} or p.get('repository')!='s1ns3nz0/node-operator' or p.get('workflow')!='image-publish.yml' or not isinstance(p.get('run_id'),str) or not RUN.fullmatch(p['run_id']) or not isinstance(p.get('artifact_id'),str) or not RUN.fullmatch(p['artifact_id']) or not isinstance(t,dict) or set(t)!={'image_ref','manifest_digest','input_sha256'} or not isinstance(a,dict) or set(a)!={'stage_approved','activation_approved'} or any(type(x)is not bool for x in a.values()) or a['stage_approved'] is not True: fail('authorization is invalid')
 return value
def retrieve(auth_path:Path,source_root:Path,output:Path)->None:
 auth=authorization(auth_path); c=auth['candidate_revision']; p=auth['publication']; g=generic()
 if not output.is_absolute() or output.exists() or output.is_symlink(): fail('output must be a new absolute directory')
 ancestor=Path(output.anchor)
 for part in output.parts[1:-1]:
  ancestor/=part
  try: info=ancestor.lstat()
  except OSError as e: raise FetchPrysmError('output parent is unavailable') from e
  if ancestor.is_symlink() or not stat.S_ISDIR(info.st_mode): fail('output ancestry is unsafe')
 stage=Path(tempfile.mkdtemp(prefix='.prysm-record-',dir=output.parent)); os.chmod(stage,0o700)
 try:
  try:
   g.run_is_trusted(g.gh_json(f"repos/{p['repository']}/actions/runs/{p['run_id']}",stage),p['repository'],c,p['run_id'])
   listed=g.list_artifacts(p['repository'],p['run_id'],stage).get('artifacts')
  except (g.FetchError, OSError) as e: raise FetchPrysmError('publication run is not trusted') from e
  if not isinstance(listed,list): fail('artifact listing is invalid')
  name=f'prysm-mtls-publication-record-{c}'; found=[x for x in listed if isinstance(x,dict) and x.get('name')==name]
  if len(found)!=1 or type(found[0].get('id')) is not int or found[0].get('id')!=int(p['artifact_id']) or found[0].get('expired') is not False or not isinstance(found[0].get('workflow_run'),dict) or type(found[0]['workflow_run'].get('id')) is not int or found[0]['workflow_run'].get('id')!=int(p['run_id']) or found[0]['workflow_run'].get('head_sha')!=c: fail('artifact is not authorization-bound')
  try:
   archive=stage/'record.zip'; g.gh_zip(f"repos/{p['repository']}/actions/artifacts/{p['artifact_id']}/zip",archive); record_path=g.extract_record(archive,'prysm-mtls',stage); raw=record_path.read_bytes()
  except (g.FetchError, OSError) as e: raise FetchPrysmError('artifact download is unsafe or invalid') from e
  if hashlib.sha256(raw).hexdigest()!=auth['record_sha256']: fail('record hash differs from authorization')
  try: value=validate_record(read(record_path)[0],source_root,expected_release_revision=c)
  except (PrysmPublicationRecordError, FetchPrysmError) as e: raise FetchPrysmError('record is invalid') from e
  if str(value['publication']['run_id'])!=p['run_id'] or {k:value['target'].get(k) for k in ('image_ref','manifest_digest')}|{'input_sha256':value['input_sha256']}!=auth['target']: fail('record context differs from authorization')
  archive.unlink(missing_ok=True)
  try: g.publish(stage,output)
  except (g.FetchError, OSError) as e: raise FetchPrysmError('cannot publish validated record') from e
 finally: shutil.rmtree(stage,ignore_errors=True)
def main()->int:
 q=argparse.ArgumentParser(); q.add_argument('--authorization-path',type=Path,required=True);q.add_argument('--source-root',type=Path,required=True);q.add_argument('--output-dir',type=Path,required=True); a=q.parse_args()
 try: retrieve(a.authorization_path,a.source_root,a.output_dir)
 except FetchPrysmError as e: q.error(str(e))
 return 0
if __name__=='__main__': raise SystemExit(main())

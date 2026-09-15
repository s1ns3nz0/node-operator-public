"""Reader-Pod-only retrieval and matching of a Vault audit archive object."""
from __future__ import annotations
import importlib.util,re,json
from datetime import datetime,timezone
from pathlib import Path
P=Path(__file__).with_name('collect-hoodi-finalized-attestation-evidence.py');s=importlib.util.spec_from_file_location('archive',P);archive=importlib.util.module_from_spec(s);s.loader.exec_module(archive)
M=Path(__file__).with_name('vault_audit_archive_matcher.py');q=importlib.util.spec_from_file_location('matcher',M);matcher=importlib.util.module_from_spec(q);q.loader.exec_module(matcher)
class ReaderError(ValueError):pass
def verify(transport,bucket,prefix,region,account,log_group,marker_hmac,after_ms,expected_kms,start_token=None,prior_matches=None):
 if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{2,62}',bucket) or prefix!='validator/' or not re.fullmatch(r'[a-z]{2}-[a-z0-9-]+-[0-9]+',region):raise ReaderError('invalid archive scope')
 if not isinstance(expected_kms,str) or not re.fullmatch(rf'arn:aws:kms:{re.escape(region)}:{re.escape(account)}:key/[A-Za-z0-9-]+',expected_kms):raise ReaderError('invalid archive KMS key')
 try:
  if start_token is not None and (not isinstance(start_token,str) or not start_token):raise ReaderError('archive cursor is invalid')
  if prior_matches is None: prior_matches=[]
  if not isinstance(prior_matches,list) or any(not isinstance(x,dict) or set(x)!={'key','version_id','event_id','request_id','timestamp_ms'} for x in prior_matches):raise ReaderError('archive cursor is invalid')
  objects,next_token=archive.archive_objects(bucket,prefix,region,start_token=start_token,runner=transport)
  prior_keys=[{'key':x['key']} for x in prior_matches]
  matches=[]; seen=set()
  for item in prior_keys+objects:
   if not isinstance(item,dict) or not isinstance(item.get('key'),str):raise ReaderError('archive listing is malformed')
   try: meta,raw=archive.object_payload(bucket,item['key'],region,runner=transport)
   except Exception as e: raise ReaderError('archive object retrieval failed') from e
   try: proof=matcher.match(raw,marker_hmac,after_ms,account,log_group)
   except matcher.MatchError: continue
   if not isinstance(meta.get('version_id'),str) or not meta['version_id']:raise ReaderError('archive version is unavailable')
   head=json.loads(transport(['s3api','head-object','--bucket',bucket,'--key',meta['key'],'--version-id',meta['version_id'],'--region',region,'--output','json','--no-cli-pager']).decode())
   retain=head.get('ObjectLockRetainUntilDate')
   if not isinstance(retain,str):raise ReaderError('archive object protection is invalid')
   try: future=datetime.fromisoformat(retain.replace('Z','+00:00'))>datetime.now(timezone.utc)
   except ValueError: future=False
   if head.get('ServerSideEncryption')!='aws:kms' or head.get('SSEKMSKeyId')!=expected_kms or head.get('ObjectLockMode')!='COMPLIANCE' or not future:raise ReaderError('archive object protection is invalid')
   identity=(proof['event_id'],proof['request_id'])
   if identity in seen:continue
   seen.add(identity);matches.append({'key':meta['key'],'version_id':meta['version_id'],'event_id':proof['event_id'],'request_id':proof['request_id'],'timestamp_ms':proof['timestamp_ms']})
  if next_token is not None:return {'state':'pending','continuation_token':next_token,'matches':matches}
  if len(matches)!=1:raise ReaderError('archive has no unique matching audit request')
  proof=matches[0];meta={'key':proof['key'],'version_id':proof['version_id']}
 except Exception as e:raise ReaderError('archive correlation is unavailable') from e
 if not isinstance(meta.get('version_id'),str) or not meta['version_id']:raise ReaderError('archive version is unavailable')
 return {'state':'matched','bucket':bucket,'key':meta['key'],'version_id':meta['version_id'],'event_id':proof['event_id'],'request_id':proof['request_id'],'timestamp_ms':proof['timestamp_ms']}

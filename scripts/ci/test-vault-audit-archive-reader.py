#!/usr/bin/env python3
import importlib.util,unittest,json,gzip
from pathlib import Path
P=Path(__file__).resolve().parents[2]/'scripts/release/vault_audit_archive_reader.py';s=importlib.util.spec_from_file_location('r',P);r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
TP=Path(__file__).resolve().parents[2]/'scripts/release/validator_audit_pod_transport.py';ts=importlib.util.spec_from_file_location('t',TP);t=importlib.util.module_from_spec(ts);ts.loader.exec_module(t)
class T(unittest.TestCase):
 K='arn:aws:kms:ap-northeast-2:123456789012:key/a'
 def test_invalid_scope_and_reader_failure_reject(self):
  class X:
   def _exec(self,a):raise RuntimeError()
  with self.assertRaises(r.ReaderError):r.verify(X(),'bad','wrong/','ap-northeast-2','123456789012','/aws/eks/node-op-auth/validator-security','hmac-sha256:'+'a'*64,1,self.K)
  with self.assertRaises(r.ReaderError):r.verify(X(),'node-audit-123','validator/','ap-northeast-2','123456789012','/aws/eks/node-op-auth/validator-security','hmac-sha256:'+'a'*64,1,self.K)
 def test_no_matching_object_rejects(self):
  old=r.archive.archive_objects;r.archive.archive_objects=lambda *a,**k:([],None)
  try:
   with self.assertRaises(r.ReaderError):r.verify(object(),'node-audit-123','validator/','ap-northeast-2','123456789012','/aws/eks/node-op-auth/validator-security','hmac-sha256:'+'a'*64,1,self.K)
  finally:r.archive.archive_objects=old
 def test_unrelated_then_matching_object_and_continuation_pending(self):
  old_list,old_payload,old_match=r.archive.archive_objects,r.archive.object_payload,r.matcher.match
  try:
   r.archive.archive_objects=lambda *a,**k:([{'key':'validator/old'},{'key':'validator/match'}],None)
   r.archive.object_payload=lambda b,k,region,runner:({'key':k,'version_id':'v'},b'')
   r.matcher.match=lambda raw,*a,**k: (_ for _ in ()).throw(ValueError()) if raw==b'' else None
   # Make only the second object match without relying on any external reader.
   r.archive.object_payload=lambda b,k,region,runner:({'key':k,'version_id':'v'},b'match' if k.endswith('match') else b'old')
   r.matcher.match=lambda raw,*a,**k: {'event_id':'e','request_id':'r','timestamp_ms':2} if raw==b'match' else (_ for _ in ()).throw(r.matcher.MatchError())
   calls=[]
   def head(self,a):
    calls.append(a);return json.dumps({'ServerSideEncryption':'aws:kms','SSEKMSKeyId':T.K,'ObjectLockMode':'COMPLIANCE','ObjectLockRetainUntilDate':'2999-01-01T00:00:00Z'}).encode()
   transport=type('X',(),{'__call__':head})()
   self.assertEqual(r.verify(transport,'node-audit-123','validator/','ap-northeast-2','123456789012','/aws/eks/node-op-auth/validator-security','hmac-sha256:'+'a'*64,1,T.K)['state'],'matched');self.assertIn('v',calls[0])
   r.archive.archive_objects=lambda *a,**k:([{'key':'validator/match'}],'next')
   self.assertEqual(r.verify(transport,'node-audit-123','validator/','ap-northeast-2','123456789012','/aws/eks/node-op-auth/validator-security','hmac-sha256:'+'a'*64,1,T.K)['state'],'pending')
  finally:r.archive.archive_objects,r.archive.object_payload,r.matcher.match=old_list,old_payload,old_match
 def test_forged_prior_and_access_denial_reject(self):
  old_list,old_payload=r.archive.archive_objects,r.archive.object_payload
  try:
   r.archive.archive_objects=lambda *a,**k:([],None)
   r.archive.object_payload=lambda *a,**k:(_ for _ in ()).throw(PermissionError())
   transport=type('X',(),{'_exec':lambda self,a:b''})()
   forged=[{'key':'validator/forged','version_id':'v','event_id':'e','request_id':'r','timestamp_ms':2}]
   with self.assertRaises(r.ReaderError):r.verify(transport,'node-audit-123','validator/','ap-northeast-2','123456789012','/aws/eks/node-op-auth/validator-security','hmac-sha256:'+'a'*64,1,T.K,prior_matches=forged)
  finally:r.archive.archive_objects,r.archive.object_payload=old_list,old_payload
 def test_real_pod_transport_delivers_versioned_temp_payload(self):
  payload=gzip.compress(b'{}'); uid='reader-pod-uid'; seen=[]
  def call(command):
   seen.append(command)
   if 'jsonpath={.metadata.uid}' in command:return uid.encode()
   inner=command[command.index('--')+1:]
   if inner[:3]==['aws','s3api','head-object']:return json.dumps({'VersionId':'v1','ETag':'"e"','ContentLength':len(payload)}).encode()
   if inner[:2]==['sh','-c']:return payload
   raise AssertionError(command)
  transport=t.PodAWSTransport('validator-observability','validator-audit-reader-abc',uid,'node-audit-123','validator/','ap-northeast-2',call=call)
  meta,raw=r.archive.object_payload('node-audit-123','validator/item','ap-northeast-2',runner=transport)
  self.assertEqual((meta['version_id'],raw),('v1',b'{}'));self.assertTrue(any('get-object' not in item and 'head-object' in item for item in seen if isinstance(item,list)))
if __name__=='__main__':unittest.main()

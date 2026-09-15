#!/usr/bin/env python3
import gzip, importlib.util, json, unittest
from pathlib import Path
P=Path(__file__).resolve().parents[2]/"scripts/release/vault_audit_archive_matcher.py";s=importlib.util.spec_from_file_location("m",P);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
N="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"; H="hmac-sha256:"+"b"*64; A="123456789012"; G="/aws/eks/node-op-auth/validator-security"
def blob(source="socket",path="sys/audit-hash/validator-socket",h=H,stamp=9):
 relay={"schema_version":1,"audit_source":source,"log":json.dumps({"type":"request","request":{"id":N,"operation":"update","path":path,"data":{"input":h}}})}
 message={"kubernetes":{"namespace_name":"vault","container_name":"vault-validator-audit-relay"},"log":"2026-01-01T00:00:00Z stdout F "+json.dumps(relay)}
 return gzip.compress(gzip.compress(json.dumps({"messageType":"DATA_MESSAGE","owner":A,"logGroup":G,"logEvents":[{"id":"e","timestamp":stamp,"message":json.dumps(message)}]}).encode()))
class T(unittest.TestCase):
 def test_double_gzip_exact_socket_match(self): self.assertEqual(m.match(blob(),H,1,A,G),{"event_id":"e","timestamp_ms":9,"request_id":N})
 def test_rejects_wrong_provenance_path_hmac_or_stale(self):
  for value in (blob(source="file"),blob(path="sys/health"),blob(h="hmac-sha256:"+"c"*64),blob(stamp=0)):
   with self.assertRaises(m.MatchError): m.match(value,H,1,A,G)
 def test_marker_is_cryptographic_and_optional_response_id_is_cross_checked(self):
  self.assertRegex(m.new_marker(),r'^[0-9a-f]{64}$');self.assertNotEqual(m.new_marker(),m.new_marker());self.assertEqual(m.match(blob(),H,1,A,G,N)['request_id'],N)
  with self.assertRaises(m.MatchError):m.match(blob(),H,1,A,G,'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb')
 def test_response_and_malformed_kubernetes_never_match(self):
  raw=blob(); import gzip
  value=json.loads(gzip.decompress(gzip.decompress(raw))); outer=json.loads(value['logEvents'][0]['message']); relay=json.loads(outer['log'].split(' F ',1)[1]); record=json.loads(relay['log']);record['type']='response';relay['log']=json.dumps(record);outer['log']='2026-01-01T00:00:00Z stdout F '+json.dumps(relay);value['logEvents'][0]['message']=json.dumps(outer)
  with self.assertRaises(m.MatchError):m.match(gzip.compress(gzip.compress(json.dumps(value).encode())),H,1,A,G)
if __name__=="__main__": unittest.main()

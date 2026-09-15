#!/usr/bin/env python3
import hashlib, importlib.util, io, json, os, sys, tarfile, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]; PATH=ROOT/'scripts/release/verify-client-chart-deployment-capability.py'
SPEC=importlib.util.spec_from_file_location('capability',PATH); M=importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name]=M; SPEC.loader.exec_module(M)
D='a'*64
VALUES={"deployment":{"profile":"deployment","storageKmsKeyId":"arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"},"dast":{"enabled":False},"clients":{"vaultAgentImage":f"123456789012.dkr.ecr.us-east-1.amazonaws.com/node-operator-example-gitops-vault@sha256:{D}","deployment":{"nethermindImage":f"123456789012.dkr.ecr.us-east-1.amazonaws.com/node-operator-example-gitops-nodes@sha256:{D}","prysmImage":f"123456789012.dkr.ecr.us-east-1.amazonaws.com/node-operator-example-gitops-nodes@sha256:{D}","prysmP2PHostIp":"198.51.100.42"}}}
SCHEMA={"type":"object","properties":{"deployment":{"type":"object","properties":{"profile":{"type":"string"},"storageKmsKeyId":{"type":"string"}}},"dast":{"type":"object","properties":{"enabled":{"type":"boolean"}}},"clients":{"type":"object","properties":{"vaultAgentImage":{"type":"string"},"deployment":{"type":"object","properties":{"nethermindImage":{"type":"string"},"prysmImage":{"type":"string"},"prysmP2PHostIp":{"type":"string"}}}}}}}
def layer(version='0.1.42',schema=SCHEMA,extras=()):
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w:gz') as t:
  entries=list({'node-operator-client/Chart.yaml':f'apiVersion: v2\nname: node-operator-client\nversion: {version}\n'.encode(),'node-operator-client/values.schema.json':json.dumps(schema).encode()}.items())+list(extras)
  for name,data in entries:
   info=tarfile.TarInfo(name)
   if data is None: info.type=tarfile.DIRTYPE;info.size=0;t.addfile(info)
   else: info.size=len(data);t.addfile(info,io.BytesIO(data))
 return out.getvalue()
class R:
 def __init__(self,values):self.values=values
 def __call__(self,cmd,**kwargs):
  if cmd[0]=='helm':
   if 'dast.enabled=true' in cmd:return type('P',(),{'returncode':1,'stdout':''})()
   v=self.values;d=v['clients']['deployment'];agent=v['clients']['vaultAgentImage'];kms=v['deployment']['storageKmsKeyId']
   text=f'''apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata: {{name: nethermind-hoodi-gp3-kms}}
parameters: {{kmsKeyId: "{kms}"}}
---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata: {{name: prysm-hoodi-gp3-kms}}
parameters: {{kmsKeyId: "{kms}"}}
---
apiVersion: apps/v1
kind: StatefulSet
metadata: {{name: nethermind-execution}}
spec:
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-image: "{agent}"
    spec:
      containers:
        - name: nethermind
          image: "{d['nethermindImage']}"
---
apiVersion: apps/v1
kind: StatefulSet
metadata: {{name: prysm-beacon}}
spec:
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-image: "{agent}"
    spec:
      containers:
        - name: beacon-chain
          image: "{d['prysmImage']}"
          args: ["--p2p-host-ip={d['prysmP2PHostIp']}"]
'''
   return type('P',(),{'returncode':0,'stdout':text})()
  v=self.values;d=v['clients']['deployment'];agent=v['clients']['vaultAgentImage'];kms=v['deployment']['storageKmsKeyId']
  def sts(name,container,image,args=[]):return {'kind':'StatefulSet','metadata':{'name':name},'spec':{'template':{'metadata':{'annotations':{'vault.hashicorp.com/agent-image':agent}},'spec':{'containers':[{'name':container,'image':image,'args':args}]}}}}
  items=[{'kind':'StorageClass','metadata':{'name':'nethermind-hoodi-gp3-kms'},'parameters':{'kmsKeyId':kms}},{'kind':'StorageClass','metadata':{'name':'prysm-hoodi-gp3-kms'},'parameters':{'kmsKeyId':kms}},sts('nethermind-execution','nethermind',d['nethermindImage']),sts('prysm-beacon','beacon-chain',d['prysmImage'],args=['--p2p-host-ip='+d['prysmP2PHostIp']])]
  return type('P',(),{'returncode':0,'stdout':json.dumps(items)})()
class T(unittest.TestCase):
 def verify(self,archive,version='0.1.42',runner=None):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'values.json';p.write_text(json.dumps(VALUES));return M.verify_layer_capability(archive,version,p,runner or R(VALUES))
 def test_valid_fixture_proves_schema_and_two_real_render_invocations(self):self.verify(layer())
 def test_old_chart_cannot_pass_new_capability_gate(self):
  old={"type":"object","properties":{"dast":{"type":"object","properties":{"enabled":{"type":"boolean"}}}}}
  with self.assertRaises(M.CapabilityError):self.verify(layer('0.1.41',old),'0.1.41')
 def test_missing_deployment_schema_rejects(self):
  bad=json.loads(json.dumps(SCHEMA));del bad['properties']['clients']['properties']['deployment']['properties']['prysmP2PHostIp']
  with self.assertRaises(M.CapabilityError):self.verify(layer(schema=bad))
 def test_dast_true_must_be_rejected(self):
  class Unsafe(R):
   def __call__(self,cmd,**kwargs):
    if cmd[0]=='helm':return type('P',(),{'returncode':0,'stdout':'ignored'})()
    return super().__call__(cmd,**kwargs)
  with self.assertRaises(M.CapabilityError):self.verify(layer(),runner=Unsafe(VALUES))
 def test_lookup_binds_selected_profile_and_scrubs_ambient_tokens(self):
  archive=layer();layer_digest=hashlib.sha256(archive).hexdigest();manifest=json.dumps({'layers':[{'mediaType':'application/vnd.cncf.helm.chart.content.v1.tar+gzip','digest':'sha256:'+layer_digest}]},separators=(',',':'));digest=hashlib.sha256(manifest.encode()).hexdigest();calls=[]
  def runner(command,**kwargs):
   calls.append((command,kwargs['env']))
   body={'images':[{'imageId':{'imageDigest':'sha256:'+digest},'imageManifest':manifest}]} if len(calls)==1 else {'downloadUrl':'https://example.invalid/layer'}
   return type('P',(),{'returncode':0,'stdout':json.dumps(body)})()
  with patch.dict(os.environ,{'AWS_PROFILE':'ambient','AWS_ACCESS_KEY_ID':'ambient-key','AWS_SECRET_ACCESS_KEY':'ambient-secret','AWS_SESSION_TOKEN':'ambient-token','AWS_WEB_IDENTITY_TOKEN_FILE':'/tmp/ambient-token','AWS_ENDPOINT_URL':'http://ambient.invalid'},clear=False):
   self.assertEqual(M.fetch_authorized_layer(f'123456789012.dkr.ecr.us-east-1.amazonaws.com/node-operator-example-baseline-gitops-client/node-operator-client@sha256:{digest}','selected-profile',runner,lambda *_args,**_kwargs:io.BytesIO(archive)),archive)
  self.assertEqual(len(calls),2)
  for command,environment in calls:
   self.assertEqual(command[:3],['aws','--profile','selected-profile']);self.assertEqual(environment['AWS_PROFILE'],'selected-profile');self.assertEqual(environment['AWS_REGION'],'us-east-1');self.assertNotIn('AWS_ACCESS_KEY_ID',environment);self.assertNotIn('AWS_SECRET_ACCESS_KEY',environment);self.assertNotIn('AWS_SESSION_TOKEN',environment);self.assertNotIn('AWS_WEB_IDENTITY_TOKEN_FILE',environment);self.assertNotIn('AWS_ENDPOINT_URL',environment)
 def test_directory_header_flood_is_bounded_before_member_materialization(self):
  directories=[(f'node-operator-client/empty-{number}/',None) for number in range(M.MAX_MEMBERS+1)]
  with self.assertRaises(M.CapabilityError):M._members(layer(extras=directories),'0.1.42')
 def test_total_decompressed_stream_is_bounded(self):
  extras=[('node-operator-client/a',b'0'*(6*1024)),('node-operator-client/b',b'0'*(6*1024))]
  with patch.object(M,'MAX_UNPACKED',10*1024):
   with self.assertRaises(M.CapabilityError):M._members(layer(extras=extras),'0.1.42')
 def test_malformed_image_id_is_cleanly_rejected(self):
  def runner(_command,**_kwargs):return type('P',(),{'returncode':0,'stdout':json.dumps({'images':[{'imageId':[],'imageManifest':'{}'}]})})()
  with self.assertRaises(M.CapabilityError):M.fetch_authorized_layer(f'123456789012.dkr.ecr.us-east-1.amazonaws.com/node-operator-example-baseline-gitops-client/node-operator-client@sha256:{D}','selected-profile',runner)
if __name__=='__main__':unittest.main()

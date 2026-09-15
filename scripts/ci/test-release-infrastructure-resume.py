#!/usr/bin/env python3
# Check objective: Verify zero-apply infrastructure release resumption with fake CLIs.
"""Offline two-run zero_apply resume proof using fake AWS and Terraform CLIs."""
import hashlib, json, os, pathlib, subprocess, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
ENTRY = ROOT / "scripts/release/node-operator-release.sh"

AWS = r'''#!/usr/bin/env python3
import json, os, sys
a=sys.argv[1:]; run=os.environ['RUN']; out=lambda x: print(json.dumps(x)); bad=run=='bad-owner'
if a[:2]==['sts','get-caller-identity']: out({'Account':'111111111111'})
elif a[:2]==['s3api','list-buckets']: out({'Buckets':([] if run=='one' else [{'Name':'node-operator-tfstate-111111111111-useast1'}])})
elif a[:2]==['s3api','list-objects-v2']: out({'Contents':([] if run=='one' else [{'Key':'node-operator/bootstrap-state/terraform.tfstate'}])})
elif a[:2]==['s3api','get-bucket-tagging']: out({'TagSet':[{'Key':'Project','Value':('foreign' if bad else 'node-operator')},{'Key':'Deployment','Value':'node-operator'},{'Key':'DeploymentRegion','Value':'us-east-1'},{'Key':'ManagedBy','Value':'terraform'},{'Key':'Purpose','Value':'terraform-state-bootstrap'}]})
elif a[:2]==['s3api','get-bucket-encryption']: out({'ServerSideEncryptionConfiguration':{'Rules':[{'ApplyServerSideEncryptionByDefault':{'KMSMasterKeyID':'arn:aws:kms:us-east-1:111111111111:key/abc'}}]}})
elif a[:2]==['dynamodb','describe-table']:
 if run=='one': print('ResourceNotFoundException',file=sys.stderr);sys.exit(255)
 out({'Table':{'TableArn':'arn:aws:dynamodb:us-east-1:111111111111:table/node-operator-terraform-lock'}})
elif a[:2]==['dynamodb','list-tags-of-resource']: out({'Tags':[{'Key':'Project','Value':'node-operator'},{'Key':'Deployment','Value':'node-operator'},{'Key':'DeploymentRegion','Value':'us-east-1'},{'Key':'ManagedBy','Value':'terraform'},{'Key':'Purpose','Value':'terraform-state-bootstrap'}]})
elif a[:2]==['resourcegroupstaggingapi','get-resources']: out({'ResourceTagMappingList':([] if run=='one' else [{'ResourceARN':'arn:aws:kms:us-east-1:111111111111:key/abc'}])})
elif a[:2]==['kms','describe-key']: out({'KeyMetadata':{'KeyId':'abc','Arn':'arn:aws:kms:us-east-1:111111111111:key/abc','KeyState':'Enabled','KeyManager':'CUSTOMER'}})
elif a[:2]==['kms','list-resource-tags']: out({'Tags':[{'TagKey':'Project','TagValue':'node-operator'},{'TagKey':'Deployment','TagValue':'node-operator'},{'TagKey':'DeploymentRegion','TagValue':'us-east-1'},{'TagKey':'ManagedBy','TagValue':'terraform'},{'TagKey':'Purpose','TagValue':'terraform-state-bootstrap'}]})
elif a[:2]==['kms','list-aliases']: out({'Aliases':[{'AliasName':'alias/node-operator-node-operator-bootstrap-state','TargetKeyId':'abc'}]})
elif a[:2]==['configservice','describe-configuration-recorders']: out({'ConfigurationRecorders':[{'name':('foreign-config' if run=='wrong-live-name' else 'node-operator-baseline-config'),'roleARN':('arn:aws:iam::222222222222:role/config' if run=='stale-live' else 'arn:aws:iam::111111111111:role/config')} ]})
elif a[:2]==['configservice','describe-delivery-channels']: out({'DeliveryChannels':([] if os.environ.get('VERIFY_MODE')=='partial' and run != 'untracked-partial' else [{'name':('foreign-channel' if run in ('wrong-live-channel','untracked-partial') else 'node-operator-baseline-config'),'s3BucketName':('foreign-bucket' if run in ('stale-live','wrong-live-channel','untracked-partial') else 'audit-bucket')} ])})
elif a[:2]==['configservice','describe-configuration-recorder-status']: out({'ConfigurationRecordersStatus':[{'name':('foreign-status' if run=='wrong-live-status' else 'node-operator-baseline-config')} ]})
else: out({})
'''
TERRAFORM = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
a=sys.argv[1:]; chdir=''
if a[0].startswith('-chdir='): chdir=a.pop(0).split('=',1)[1]
op=a.pop(0); log=pathlib.Path(os.environ['TF_LOG']); log.write_text(log.read_text()+op+' '+chdir+' '+' '.join(a)+'\n' if log.exists() else op+' '+chdir+' '+' '.join(a)+'\n')
kind='bootstrap' if chdir.endswith('bootstrap-state') or chdir.endswith('/bootstrap') else ('foundation' if chdir.endswith('foundation-network') else 'baseline')
if op=='plan':
 for x in a:
  if x.startswith('-out='): pathlib.Path(x[5:]).touch()
elif op=='show':
 if os.environ.get('VERIFY_RECORDER'):
  resources=[
   {'address':'aws_config_configuration_recorder.baseline[0]','values':{'name':'node-operator-baseline-config','role_arn':'arn:aws:iam::111111111111:role/config'}},
   {'address':'aws_config_delivery_channel.baseline[0]','values':{'name':'node-operator-baseline-config','s3_bucket_name':'audit-bucket'}},
   {'address':'aws_config_configuration_recorder_status.baseline[0]','values':{'name':'node-operator-baseline-config'}},
   {'address':'aws_iam_role.config','values':{'arn':'arn:aws:iam::111111111111:role/config'}},
   {'address':'aws_s3_bucket.audit','values':{'id':'audit-bucket','tags':{'Project':'node-operator','Deployment':'node-operator','DeploymentRegion':'us-east-1','ManagedBy':'terraform'}}},
   {'address':'aws_kms_key.audit','values':{'arn':'arn:aws:kms:us-east-1:111111111111:key/def'}},
  ]
  mode=os.environ.get('VERIFY_MODE','ok')
  if mode=='missing': resources=resources[1:]
  elif mode=='partial': resources=[item for item in resources if item['address'] not in {'aws_config_delivery_channel.baseline[0]','aws_config_configuration_recorder_status.baseline[0]'}]
  elif mode=='channel-name': resources[1]['values']['name']='stale-channel-name'
  elif mode=='foreign': resources[4]['values']['tags']['Deployment']='foreign'
  elif mode=='relationship': resources[1]['values']['s3_bucket_name']='foreign-bucket'
  elif mode=='account': resources[3]['values']['arn']='arn:aws:iam::222222222222:role/config'
  print(json.dumps({'format_version':'1.0','values':{'root_module':{'resources':resources}}}))
 else: print(json.dumps({'format_version':'1.0','values':{'root_module':None},'configuration':{'root_module':{'resources':[{'address':'aws_test.x'}]}},'resource_changes':[{'address':'aws_test.x','change':{'actions':['create']}}]}))
elif op=='output':
 if kind=='bootstrap': print(json.dumps({'bucket':'node-operator-tfstate-111111111111-useast1','region':'us-east-1','dynamodb_table':'node-operator-terraform-lock','kms_key_id':'arn:aws:kms:us-east-1:111111111111:key/abc'}))
 elif kind=='foundation': print(json.dumps({'vpc_id':'vpc-abc','vpc_cidr':'10.0.0.0/16','system_subnet_ids':['subnet-a','subnet-b'],'hoodi_subnet_ids':['subnet-c'],'system_route_table_id':'rtb-a','hoodi_route_table_id':'rtb-b','hoodi_nat_gateway_id':'nat-a','hoodi_nat_public_ip':'198.51.100.42'}))
 else: print(json.dumps({'deployment_account_id':{'value':'111111111111'},'cluster_name':{'value':'node-operator'},'gitops_client_ecr_repository_url':{'value':'111111111111.dkr.ecr.us-east-1.amazonaws.com/x'},'github_gitops_client_ecr_publisher_role_arn':{'value':'arn:aws:iam::111111111111:role/x'}}))
elif op=='apply' and kind=='foundation' and os.environ.get('FAIL_FOUNDATION_ONCE'):
 marker=pathlib.Path(os.environ['TF_FAIL_MARKER'])
 if not marker.exists(): marker.write_text('failed'); sys.exit(7)
sys.exit(0)
'''

class Resume(unittest.TestCase):
 def test_remote_recorder_verifier_rejects_unowned_or_incomplete_state_without_plan_apply(self):
  with tempfile.TemporaryDirectory() as d:
   d=pathlib.Path(d); bind=d/'bin'; bind.mkdir(); (bind/'aws').write_text(AWS); (bind/'terraform').write_text(TERRAFORM); (bind/'aws').chmod(0o755);(bind/'terraform').chmod(0o755)
   bundle=d/'bundle'; bundle.mkdir(); (bundle/'source').symlink_to(ROOT)
   contract=ROOT/'release/hoodi-release-contract.json'; digest=hashlib.sha256(contract.read_bytes()).hexdigest(); (bundle/'bundle-manifest.json').write_text(json.dumps({'entries':[{'path':'source/release/hoodi-release-contract.json','sha256':digest}]}))
   cfg=d/'cfg'; cfg.mkdir()
   for name,data in {'bootstrap-state.tfvars.json':{'aws_account_id':'111111111111','aws_region':'us-east-1','name':'node-operator'},'foundation-network.tfvars.json':{'aws_region':'us-east-1','name':'node-operator'},'baseline.tfvars.json':{'aws_account_id':'111111111111','aws_region':'us-east-1','name':'node-operator','manage_config_recorder':True}}.items(): (cfg/name).write_text(json.dumps(data))
   inputs=cfg/'inputs.json'; inputs.write_text(json.dumps({'schema_version':1,'aws_account_id':'111111111111','aws_region':'us-east-1','bootstrap_config':str(cfg/'bootstrap-state.tfvars.json'),'foundation_config':str(cfg/'foundation-network.tfvars.json'),'baseline_config':str(cfg/'baseline.tfvars.json')}))
   work=d/'work'; work.mkdir(); log=d/'terraform.log'; command=[str(ENTRY),'zero','verify-recorder','--bundle-root',str(bundle),'--inputs',str(inputs),'--work-dir',str(work)]
   env={**os.environ,'PATH':str(bind)+os.pathsep+os.environ['PATH'],'TF_LOG':str(log),'RUN':'two','VERIFY_RECORDER':'1'}
   good=subprocess.run(command,text=True,capture_output=True,env=env)
   self.assertEqual(good.returncode,0,good.stderr); self.assertNotIn('plan ',log.read_text()); self.assertNotIn('apply ',log.read_text())
   self.assertEqual(list(work.glob('.recorder-state-verify.*')), [])
   for mode in ('missing','foreign','relationship','account','channel-name'):
    log.write_text('')
    result=subprocess.run(command,text=True,capture_output=True,env={**env,'VERIFY_MODE':mode})
    self.assertNotEqual(result.returncode,0,mode); self.assertNotIn('plan ',log.read_text()); self.assertNotIn('apply ',log.read_text())
    self.assertEqual(list(work.glob('.recorder-state-verify.*')), [])
   log.write_text('')
   partial=subprocess.run(command,text=True,capture_output=True,env={**env,'VERIFY_MODE':'partial'})
   self.assertEqual(partial.returncode,0,partial.stderr); self.assertNotIn('plan ',log.read_text()); self.assertNotIn('apply ',log.read_text())
   log.write_text('')
   result=subprocess.run(command,text=True,capture_output=True,env={**env,'VERIFY_MODE':'partial','RUN':'untracked-partial'})
   self.assertNotEqual(result.returncode,0,'partial state accepted untracked live channel'); self.assertNotIn('plan ',log.read_text()); self.assertNotIn('apply ',log.read_text())
   for run in ('wrong-live-name','wrong-live-channel','wrong-live-status'):
    log.write_text('')
    result=subprocess.run(command,text=True,capture_output=True,env={**env,'RUN':run})
    self.assertNotEqual(result.returncode,0,run); self.assertNotIn('plan ',log.read_text()); self.assertNotIn('apply ',log.read_text())
   log.write_text('')
   result=subprocess.run(command,text=True,capture_output=True,env={**env,'RUN':'stale-live'})
   self.assertNotEqual(result.returncode,0,'stale remote state accepted foreign live recorder'); self.assertNotIn('plan ',log.read_text()); self.assertNotIn('apply ',log.read_text())
   self.assertEqual(list(work.glob('.recorder-state-verify.*')), [])

 def test_two_runs_reuse_foundation_backend(self):
  with tempfile.TemporaryDirectory() as d:
   d=pathlib.Path(d); bind=d/'bin'; bind.mkdir(); (bind/'aws').write_text(AWS); (bind/'terraform').write_text(TERRAFORM); (bind/'aws').chmod(0o755);(bind/'terraform').chmod(0o755)
   bundle=d/'bundle'; bundle.mkdir(); (bundle/'source').symlink_to(ROOT)
   contract=ROOT/'release/hoodi-release-contract.json'; digest=hashlib.sha256(contract.read_bytes()).hexdigest()
   (bundle/'bundle-manifest.json').write_text(json.dumps({'entries':[{'path':'source/release/hoodi-release-contract.json','sha256':digest}]}))
   cfg=d/'cfg'; cfg.mkdir()
   for name, data in {'bootstrap-state.tfvars.json':{'aws_account_id':'111111111111','aws_region':'us-east-1','name':'node-operator'},'foundation-network.tfvars.json':{'aws_region':'us-east-1','name':'node-operator'},'baseline.tfvars.json':{'aws_account_id':'111111111111','aws_region':'us-east-1','name':'node-operator'}}.items(): (cfg/name).write_text(json.dumps(data))
   inputs=cfg/'inputs.json'; inputs.write_text(json.dumps({'schema_version':1,'aws_account_id':'111111111111','aws_region':'us-east-1','bootstrap_config':str(cfg/'bootstrap-state.tfvars.json'),'foundation_config':str(cfg/'foundation-network.tfvars.json'),'baseline_config':str(cfg/'baseline.tfvars.json')}))
   work=d/'work'; log=d/'terraform.log'; portable_tmp=d/'portable-tmp'; portable_tmp.mkdir()
   self.assertNotIn('mktemp /private/tmp', ENTRY.read_text())
   env={**os.environ,'PATH':str(bind)+os.pathsep+os.environ['PATH'],'TF_LOG':str(log),'TMPDIR':str(portable_tmp)}
   command=[str(ENTRY),'zero','apply','--bundle-root',str(bundle),'--inputs',str(inputs),'--work-dir',str(work)]
   marker=d/'foundation-failed'
   q=subprocess.run(command,text=True,capture_output=True,env={**env,'RUN':'one','FAIL_FOUNDATION_ONCE':'1','TF_FAIL_MARKER':str(marker)})
   self.assertEqual(q.returncode,7,q.stderr); self.assertTrue(marker.exists())
   q=subprocess.run(command,text=True,capture_output=True,env={**env,'RUN':'two','FAIL_FOUNDATION_ONCE':'1','TF_FAIL_MARKER':str(marker)})
   self.assertEqual(q.returncode,0,q.stderr)
   self.assertTrue((work/'foundation.backend.hcl').is_file())
   bundle2=d/'bundle-second-extraction'; bundle2.mkdir(); (bundle2/'source').symlink_to(ROOT); (bundle2/'bundle-manifest.json').write_bytes((bundle/'bundle-manifest.json').read_bytes())
   q=subprocess.run([str(ENTRY),'zero','apply','--bundle-root',str(bundle2),'--inputs',str(inputs),'--work-dir',str(work)],text=True,capture_output=True,env={**env,'RUN':'two'})
   self.assertEqual(q.returncode,0,q.stderr)
   before=log.read_text()
   baseline=cfg/'baseline.tfvars.json'; baseline.write_text(json.dumps({'aws_account_id':'111111111111','aws_region':'us-east-1','name':'different'}))
   q=subprocess.run(command,text=True,capture_output=True,env={**env,'RUN':'two'})
   self.assertNotEqual(q.returncode,0); self.assertEqual(before,log.read_text())
   baseline.write_text(json.dumps({'aws_account_id':'111111111111','aws_region':'us-east-1','name':'node-operator'}))
   manifest=bundle/'bundle-manifest.json'; manifest.write_text('{}')
   q=subprocess.run(command,text=True,capture_output=True,env={**env,'RUN':'two'})
   self.assertNotEqual(q.returncode,0); self.assertEqual(before,log.read_text())
   manifest.write_text(json.dumps({'entries':[{'path':'source/release/hoodi-release-contract.json','sha256':digest}]}))
   sentinel=d/'sentinel'; sentinel.write_text('unchanged'); backend=work/'bootstrap.backend.hcl'; backend.unlink(); backend.symlink_to(sentinel)
   q=subprocess.run(command,text=True,capture_output=True,env={**env,'RUN':'two'})
   self.assertNotEqual(q.returncode,0); self.assertEqual(sentinel.read_text(),'unchanged')
   backend.unlink()
   foundation_input=work/'foundation-network.auto.tfvars.json'; foundation_input.unlink(); foundation_input.symlink_to(sentinel)
   before=log.read_text()
   q=subprocess.run(command,text=True,capture_output=True,env={**env,'RUN':'two'})
   self.assertNotEqual(q.returncode,0); self.assertEqual(sentinel.read_text(),'unchanged')
   foundation_input.unlink()
   unsafe_module_target=work/'foundation-network'/'unsafe.tf'; unsafe_module_target.symlink_to(sentinel)
   q=subprocess.run(command,text=True,capture_output=True,env={**env,'RUN':'two'})
   self.assertNotEqual(q.returncode,0); self.assertEqual(sentinel.read_text(),'unchanged')
   unsafe_module_target.unlink()
   (work/'bootstrap-output.json').write_text('{corrupt')
   q=subprocess.run(command,text=True,capture_output=True,env={**env,'RUN':'two'})
   self.assertEqual(q.returncode,0,q.stderr); self.assertEqual(json.loads((work/'bootstrap-output.json').read_text())['bucket'],'node-operator-tfstate-111111111111-useast1')
   before=log.read_text()
   q=subprocess.run(command,text=True,capture_output=True,env={**env,'RUN':'bad-owner'})
   self.assertNotEqual(q.returncode,0); self.assertEqual(before,log.read_text())
   text=log.read_text()
   self.assertGreaterEqual(text.count('apply '+str(work/'foundation-network')),2)
   self.assertIn('init '+str(work/'foundation-network')+' -input=false -reconfigure',text)

if __name__=='__main__': unittest.main()

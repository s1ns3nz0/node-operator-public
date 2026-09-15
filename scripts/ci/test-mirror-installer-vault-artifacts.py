# Check objective: the shell-facing Vault pre-EKS adapter binds only explicit, validated inputs.
import base64, contextlib, hashlib, importlib.util, io, json, os, subprocess, sys, tempfile, types, unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[2]
RELEASE=ROOT/"scripts/release"
CLI=RELEASE/"mirror-installer-vault-artifacts.py"
sys.path.insert(0,str(RELEASE))
from installer_artifact_prerequisites import projection, _projection_fingerprint
from installer_artifact_mirror import _chart_fixture

mirror_spec=importlib.util.spec_from_file_location("mirror_fixture",Path(__file__).with_name("test-installer-artifact-mirror.py"))
mirror_fixture=importlib.util.module_from_spec(mirror_spec); mirror_spec.loader.exec_module(mirror_fixture)
adapter_spec=importlib.util.spec_from_file_location("vault_adapter",CLI)
adapter=importlib.util.module_from_spec(adapter_spec); adapter_spec.loader.exec_module(adapter)


class VaultMirrorCLI(unittest.TestCase):
 def test_fresh_chart_path_stages_synthetic_exact_oci_bytes_offline(self):
  """Exercise archive+provenance staging without relying on a live chart blob."""
  import installer_artifact_mirror as implementation
  with tempfile.TemporaryDirectory() as raw:
   root=Path(raw); source=root/"source"; release=source/"scripts/release"; release.mkdir(parents=True); synthetic={}
   for chart,provenance in (("vault",False),("cert-manager",True)):
    archive=(chart+"-archive").encode(); config=(chart+"-config").encode(); layers=[{"mediaType":"application/vnd.cncf.helm.chart.content.v1.tar+gzip","digest":"sha256:"+hashlib.sha256(archive).hexdigest(),"size":len(archive)}]
    if provenance:
     proof=b"cert-provenance"; layers.append({"mediaType":"application/vnd.cncf.helm.chart.provenance.v1.prov","digest":"sha256:"+hashlib.sha256(proof).hexdigest(),"size":len(proof)})
    manifest=json.dumps({"schemaVersion":2,"config":{"mediaType":"application/vnd.cncf.helm.config.v1+json","digest":"sha256:"+hashlib.sha256(config).hexdigest(),"size":len(config)},"layers":layers},separators=(",",":")).encode(); fixture=source/".ci/gitops/helm-oci";fixture.mkdir(parents=True,exist_ok=True);(fixture/(chart+".json")).write_text(json.dumps({"schema_version":1,"manifest_base64":base64.b64encode(manifest).decode(),"config_base64":base64.b64encode(config).decode()})); synthetic[chart]=(archive,proof if provenance else None,manifest)
   state=root/"state"; state.mkdir(mode=0o700); work=state/"terraform-work";work.mkdir(); bundle=root/"bundle";(bundle/"rendered").mkdir(parents=True)
   account="123456789012"; region="ap-northeast-2"; revision="c"*40; index=mirror_fixture.strict_index(revision)
   for component,chart in (("vault-chart","vault"),("cert-manager-chart","cert-manager")):
    archive,_,manifest=synthetic[chart];index["components"][component].update(archive_sha256=hashlib.sha256(archive).hexdigest(),expected_oci_manifest_digest="sha256:"+hashlib.sha256(manifest).hexdigest())
   (bundle/"rendered/installer-artifact-index.json").write_text(json.dumps(index)); prefix=f"{account}.dkr.ecr.{region}.amazonaws.com/private/"; (work/"baseline-output.json").write_text(json.dumps({"private_gitops_ecr_repository_urls":{"sensitive":False,"value":{"vault":prefix+"vault","vault_chart":prefix+"vault/vault","cert_manager":prefix+"cert","cert_manager_chart":prefix+"cert/cert-manager"}},"vault_audit_relay_ecr_repository_url":{"sensitive":False,"value":prefix+"relay"}}))
   seen=set(); calls=[]; staged={}
   def run(command,**kwargs):
    calls.append(command); out=""
    if command[:3]==["aws","sts","get-caller-identity"]: out=account
    elif command[:3]==["aws","ecr","get-login-password"]: out="token"
    elif command[:3]==["aws","ecr","describe-images"]:
     repo=command[command.index("--repository-name")+1];tag=command[command.index("--image-ids")+1].split("=",1)[1]; key=repo+"|"+tag
     if key not in seen: return type("R",(),{"stdout":"","stderr":"ImageNotFoundException","returncode":255})()
     chart="vault" if repo.endswith("/vault/vault") else "cert-manager" if repo.endswith("/cert-manager") else None; digest="sha256:"+hashlib.sha256(synthetic[chart][2]).hexdigest() if chart else "sha256:"+"a"*64; out=json.dumps({"imageDetails":[{"registryId":account,"repositoryName":repo,"imageDigest":digest,"imageTags":[tag]}]})
    elif command[:3]==["aws","ecr","batch-get-image"]:
     repo=command[command.index("--repository-name")+1]; tag=command[command.index("--image-ids")+1].split("=",1)[1]; out=json.dumps({"images":[{"imageManifest":staged[repo+"|"+tag].decode()}]})
    elif command[:3]==["aws","ecr","put-image"]:
     repo=command[command.index("--repository-name")+1];tag=command[command.index("--image-tag")+1]; raw_manifest=Path(command[command.index("--image-manifest")+1].removeprefix("file://")).read_bytes(); self.assertIn(raw_manifest,staged.values());seen.add(repo+"|"+tag)
    elif command[:2]==["docker","run"] and any("curl --fail" in str(part) for part in command):
     mount=Path(command[command.index("--volume")+1].split(":",1)[0]); target=Path(command[-3]).name; chart="vault" if target.startswith("vault") else "cert-manager"; (mount/target).write_bytes(synthetic[chart][1] if target.endswith(".prov") else synthetic[chart][0])
    elif command[:2]==["docker","run"] and command[-1].startswith("docker://"):
     destination=command[-1].removeprefix("docker://").split("/",1)[1];seen.add(destination.rsplit(":",1)[0]+"|"+destination.rsplit(":",1)[1])
     if command[-2].startswith("oci:"):
      self.assertIn("--preserve-digests",command)
      mounts=[command[i+1].split(":") for i,value in enumerate(command) if value=="--volume"]; work_mount=Path(next(parts[0] for parts in mounts if parts[1]=="/work")); layout=work_mount/command[-2].split(":",2)[1].removeprefix("/work/"); descriptor=json.loads((layout/"index.json").read_text())["manifests"][0]; raw_manifest=(layout/"blobs/sha256"/descriptor["digest"].removeprefix("sha256:")).read_bytes(); parsed=json.loads(raw_manifest)
      for blob in [parsed["config"],*parsed["layers"]]:
       payload=(layout/"blobs/sha256"/blob["digest"].removeprefix("sha256:")).read_bytes();self.assertEqual(len(payload),blob["size"]);self.assertEqual("sha256:"+hashlib.sha256(payload).hexdigest(),blob["digest"])
      staged[destination.rsplit(":",1)[0]+"|"+destination.rsplit(":",1)[1]]=raw_manifest
    return type("R",(),{"stdout":out,"stderr":"","returncode":0})()
   with patch.object(implementation,"__file__",str(release/"installer_artifact_mirror.py")),patch.object(implementation.subprocess,"run",side_effect=run):
    implementation.mirror(state,bundle,{"aws_account_id":account,"aws_region":region,"deployment_name":"node"},"offline",revision)
   self.assertEqual(len([call for call in calls if call[:3]==["aws","ecr","batch-get-image"]]),2); self.assertEqual(len([call for call in calls if call[:3]==["aws","ecr","put-image"]]),2); self.assertTrue(all("--preserve-digests" in call for call in calls if call[:2]==["docker","run"] and "skopeo" in call))
 def fixture(self, root):
  state=root/"state"; work=state/"terraform-work"; bundle=root/"bundle"; inputs=root/"inputs/zero-resource"; fake=root/"fake-bin"
  work.mkdir(parents=True); (bundle/"rendered").mkdir(parents=True); inputs.mkdir(parents=True); fake.mkdir()
  for directory in (state,work,bundle,inputs): os.chmod(directory,0o700)
  account="123456789012"; region="ap-northeast-2"; name="node-operator"; revision="c"*40
  for filename,value in (("bootstrap-state.tfvars.json",{"aws_account_id":account}),("foundation-network.tfvars.json",{"aws_region":region}),("baseline.tfvars.json",{"name":name})):
   path=inputs/filename; path.write_text(json.dumps(value)); os.chmod(path,0o600)
  manifest=bundle/"bundle-manifest.json"; manifest.write_text("{}"); os.chmod(manifest,0o600)
  fingerprint=_projection_fingerprint(inputs,bundle); checkpoint=work/"zero-inputs.sha256"; checkpoint.write_text(fingerprint); os.chmod(checkpoint,0o600)
  receipt=projection(mirror_fixture._fixture.state_fixture(),account,region,name,fingerprint)
  projected=work/"artifact-prerequisites.json"; projected.write_text(json.dumps(receipt)); os.chmod(projected,0o600)
  authority={}
  for chart in ("vault","cert-manager"):
   fixture=json.loads((ROOT/".ci/gitops/helm-oci"/(chart+".json")).read_text()); raw=base64.b64decode(fixture["manifest_base64"],validate=True); parsed=json.loads(raw); authority[chart]="sha256:"+hashlib.sha256(raw).hexdigest()
   component=chart+"-chart" if chart=="vault" else "cert-manager-chart"; item=mirror_fixture.strict_index(revision)["components"][component]
   item["expected_oci_manifest_digest"]=authority[chart]; item["archive_sha256"]=parsed["layers"][0]["digest"].removeprefix("sha256:")
  value=mirror_fixture.strict_index(revision)
  for component,chart in (("vault-chart","vault"),("cert-manager-chart","cert-manager")):
   value["components"][component]["expected_oci_manifest_digest"]=authority[chart]
   fixture=json.loads((ROOT/".ci/gitops/helm-oci"/(chart+".json")).read_text()); value["components"][component]["archive_sha256"]=json.loads(base64.b64decode(fixture["manifest_base64"],validate=True))["layers"][0]["digest"].removeprefix("sha256:")
  index=bundle/"rendered/installer-artifact-index.json"; index.write_text(json.dumps(value)); os.chmod(index,0o600)
  aws=fake/"aws"; aws.write_text("""#!/usr/bin/env python3
import json, os, sys
a=sys.argv[1:]; account=os.environ['FAKE_ACCOUNT']
if a[:2] == ['sts','get-caller-identity']: print(account)
elif a[:2] == ['ecr','get-login-password']: print('token')
elif a[:2] == ['ecr','describe-images']:
 def value(flag): return a[a.index(flag)+1]
 tag=value('--image-ids').split('imageTag=',1)[1]
 state_file=os.environ['FAKE_ECR_STATE']; state=json.load(open(state_file)) if os.path.exists(state_file) else {}
 key=value('--repository-name')+'|'+tag
 if value('--repository-name').endswith('/vault') or value('--repository-name').endswith('/cert-manager'): state[key]=True
 if not state.get(key):
  state['_pending']=key; json.dump(state,open(state_file,'w')); print('ImageNotFoundException',file=sys.stderr); raise SystemExit(255)
 digest=os.environ['FAKE_DIGEST']
 if value('--repository-name').endswith('/vault') or value('--repository-name').endswith('/cert-manager'): digest=json.loads(os.environ['FAKE_CHART_DIGESTS'])['vault' if value('--repository-name').endswith('/vault') else 'cert-manager']
 print(json.dumps({'imageDetails':[{'registryId':value('--registry-id'),'repositoryName':value('--repository-name'),'imageDigest':digest,'imageTags':[tag]}]}))
else: raise SystemExit(64)
"""); os.chmod(aws,0o700)
  docker=fake/"docker"; docker.write_text("""#!/usr/bin/env python3
import json, os, sys
a=sys.argv[1:]
with open(os.environ['FAKE_LOG'],'a') as out: out.write(' '.join(a)+'\\n')
if a[:2] == ['run','--rm']:
 state_file=os.environ['FAKE_ECR_STATE']; state=json.load(open(state_file)) if os.path.exists(state_file) else {}
 state['_runs']=state.get('_runs',0)+1
 if str(state['_runs']) == os.environ.get('FAKE_FAIL_COPY_AT',''):
  json.dump(state,open(state_file,'w')); raise SystemExit(23)
 pending=state.pop('_pending',None)
 if pending: state[pending]=True
 json.dump(state,open(state_file,'w'))
"""); os.chmod(docker,0o700)
  env={**os.environ,"PATH":str(fake)+os.pathsep+os.environ["PATH"],"FAKE_ACCOUNT":account,"FAKE_LOG":str(root/"docker.log"),"FAKE_ECR_STATE":str(root/"ecr.json"),"FAKE_DIGEST":"sha256:"+"a"*64,"FAKE_CHART_DIGESTS":json.dumps(authority)}
  args=["--bundle-root",str(bundle),"--state-dir",str(state),"--work-dir",str(work),"--inputs-dir",str(inputs),"--account",account,"--region",region,"--deployment-name",name,"--profile","offline","--release-sha",revision]
  return state,bundle,env,args
 def test_real_chart_fixtures_bind_exact_manifests_configs_and_layers(self):
  expected={"vault":"85cfa6b40396a198a104fbf06c7cccaf75428db7201394f9061c272441bcd0e4","cert-manager":"62c4745561eccfd723678c6547500750ebef5a880d81ff670d33124ab335f877"}
  for name,digest in expected.items():
   with self.subTest(name=name):
    wrapper=json.loads((ROOT/".ci/gitops/helm-oci"/(name+".json")).read_text()); raw=base64.b64decode(wrapper["manifest_base64"],validate=True); value=json.loads(raw); item={"expected_oci_manifest_digest":"sha256:"+digest,"archive_sha256":value["layers"][0]["digest"].removeprefix("sha256:")}
    manifest,config,layers=_chart_fixture(name+"-chart" if name=="vault" else "cert-manager-chart",item)
    self.assertEqual(hashlib.sha256(manifest).hexdigest(),digest); self.assertEqual(hashlib.sha256(config).hexdigest(),value["config"]["digest"].removeprefix("sha256:")); self.assertEqual(len(layers),1 if name=="vault" else 2)
    self.assertEqual([layer["mediaType"] for layer in layers],["application/vnd.cncf.helm.chart.content.v1.tar+gzip"]+( ["application/vnd.cncf.helm.chart.provenance.v1.prov"] if name=="cert-manager" else []))
 def command(self, action, args, env):
  return subprocess.run([sys.executable,str(CLI),action,*args],text=True,capture_output=True,env=env,check=False)
 def test_mirror_and_verify_use_actual_projection_with_fake_external_commands(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp).resolve(); state,_,env,args=self.fixture(root)
   mirrored=self.command("mirror",args,env); self.assertEqual(mirrored.returncode,0,mirrored.stderr); self.assertIn("Vault subset",mirrored.stdout)
   self.assertTrue((state/"vault-artifact-manifest.json").is_file()); self.assertTrue((state/"vault-artifact-mirror-receipt.json").is_file()); self.assertTrue((state/"vault-pre-eks-artifact-mirror-binding.json").is_file())
   verified=self.command("verify",args,env); self.assertEqual(verified.returncode,0,verified.stderr); self.assertIn("Vault subset",verified.stdout)
   # Components sharing a repository/tag/digest need no duplicate copy.
   self.assertGreaterEqual((root/"docker.log").read_text().count("run --rm"),4)
 def test_wrong_identity_stops_before_docker_and_relative_path_stops_before_aws(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp).resolve(); _,bundle,env,args=self.fixture(root); env["FAKE_ACCOUNT"]="210987654321"
   failed=self.command("mirror",args,env); self.assertEqual(failed.returncode,2); self.assertIn("operation failed",failed.stderr); self.assertFalse((root/"docker.log").exists())
   relative=list(args); relative[relative.index("--bundle-root")+1]=str(bundle.relative_to(root))
   failed=self.command("mirror",relative,{**env,"FAKE_ACCOUNT":"123456789012"}); self.assertEqual(failed.returncode,2); self.assertIn("operation failed",failed.stderr); self.assertFalse((root/"docker.log").exists())
 def test_vault_resume_recovers_partial_copy_with_persistent_tag_only_ecr_state(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp).resolve(); state,_,env,args=self.fixture(root)
   failed=self.command("mirror",args,{**env,"FAKE_FAIL_COPY_AT":"2"})
   self.assertEqual(failed.returncode,2); marker=state/"vault-pre-eks-artifact-mirror-uncertain.json"; self.assertTrue(marker.exists())
   first=(root/"docker.log").read_text(); resumed=self.command("resume",args,env)
   self.assertEqual(resumed.returncode,0,resumed.stderr); self.assertIn("Vault subset",resumed.stdout)
   self.assertTrue((state/"vault-artifact-mirror-receipt.json").exists()); self.assertFalse(marker.exists())
   self.assertGreater((root/"docker.log").read_text().count("run --rm"),first.count("run --rm"))
 def test_non_vault_scope_dispatches_to_fake_full_helper_with_explicit_resume_only(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp).resolve(); state,bundle,_,args=self.fixture(root); work=state/"terraform-work"; inputs=root/"inputs/zero-resource"
   mirrored=Mock(); verified=Mock()
   fake=types.SimpleNamespace(mirror=mirrored,verify=verified)
   with patch.dict(sys.modules,{"installer_full_artifact_mirror":fake}),contextlib.redirect_stdout(io.StringIO()) as output:
    self.assertEqual(adapter.main(["mirror","--scope","non-vault",*args]),0)
    self.assertEqual(adapter.main(["resume","--scope","non-vault",*args]),0)
    self.assertEqual(adapter.main(["verify","--scope","non-vault",*args]),0)
   self.assertIn("Non-Vault subset",output.getvalue())
   self.assertEqual(mirrored.call_count,2)
   self.assertEqual(mirrored.call_args_list[0].args,(state,bundle,{"aws_account_id":"123456789012","aws_region":"ap-northeast-2","deployment_name":"node-operator"},"offline","c"*40))
   self.assertEqual(mirrored.call_args_list[0].kwargs,{"work_dir":work,"inputs_dir":inputs,"resume":False})
   self.assertEqual(mirrored.call_args_list[1].kwargs,{"work_dir":work,"inputs_dir":inputs,"resume":True})
   self.assertEqual(verified.call_args.args,(state,bundle,{"aws_account_id":"123456789012","aws_region":"ap-northeast-2","deployment_name":"node-operator"},"offline","c"*40))
   self.assertEqual(verified.call_args.kwargs,{"work_dir":work,"inputs_dir":inputs})
 def test_vault_scope_forwards_resume_only_when_requested(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp).resolve(); state,bundle,_,args=self.fixture(root); work=state/"terraform-work"; inputs=root/"inputs/zero-resource"; mirrored=Mock()
   with patch.object(adapter,"mirror",mirrored),contextlib.redirect_stdout(io.StringIO()) as output:
    self.assertEqual(adapter.main(["mirror",*args]),0)
    self.assertEqual(adapter.main(["resume",*args]),0)
   self.assertIn("Vault subset",output.getvalue()); self.assertEqual(mirrored.call_count,2)
   self.assertEqual(mirrored.call_args_list[0].args,(state,bundle,{"aws_account_id":"123456789012","aws_region":"ap-northeast-2","deployment_name":"node-operator"},"offline","c"*40))
   self.assertEqual(mirrored.call_args_list[0].kwargs,{"prerequisites_path":work/"artifact-prerequisites.json","inputs_dir":inputs,"work_dir":work})
   self.assertEqual(mirrored.call_args_list[1].kwargs,{"prerequisites_path":work/"artifact-prerequisites.json","inputs_dir":inputs,"work_dir":work,"resume":True})
 def test_invalid_scope_rejects_before_external_calls(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp).resolve(); _,_,env,args=self.fixture(root)
   invalid=self.command("mirror",["--scope","invalid",*args],env)
   self.assertEqual(invalid.returncode,2); self.assertIn("invalid choice",invalid.stderr); self.assertFalse((root/"docker.log").exists())


if __name__ == "__main__": unittest.main()

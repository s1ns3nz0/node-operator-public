# Check objective: Reject unsafe installer artifact mirror inputs before any registry copy.
import base64, hashlib, importlib.util, json, os, tempfile, unittest
from pathlib import Path
import sys
from unittest.mock import patch
from contextlib import nullcontext
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"release"))
import installer_artifact_mirror as mirror_module
from installer_artifact_mirror import MirrorError, _describe_digest, mirror, verify_pre_eks_vault_mirror, NAMES, AWS_TIMEOUT, DOCKER_TIMEOUT
from installer_artifact_prerequisites import projection, _projection_fingerprint
from installer_vault_platform import artifacts as platform_artifacts

_fixture_spec=importlib.util.spec_from_file_location("artifact_prerequisite_fixture", Path(__file__).with_name("test-installer-artifact-prerequisites.py"))
_fixture=importlib.util.module_from_spec(_fixture_spec); _fixture_spec.loader.exec_module(_fixture)

def strict_index(revision):
 digest="sha256:"+"a"*64
 first={"kind":"image","build_revision":"b"*40,"third_party_source_revision":None,"image_ref":"ghcr.io/s1ns3nz0/node-operator/vault-bootstrap@"+digest,"manifest_digest":digest,"input_sha256":"c"*64,"publication":{"workflow":"image.yml","run_id":"1","invocation":"main"},"verification":{"method":"input-hash-and-registry-digest","status":"passed"}}
 image={"kind":"image","image_ref":"docker.io/example/image@"+digest,"manifest_digest":digest,"destination":"ignored","tag":"1.2.3"}
 chart={"kind":"helm-chart","approved_url":"https://example.invalid/chart.tgz","archive_sha256":"d"*64,"expected_oci_manifest_digest":digest,"version":"1.2.3","destination":"ignored","tag":"1.2.3"}
 components={name:dict(first if name in {"vault-bootstrap","vault-audit-relay","gitops-oci-mirror"} else chart if name in {"vault-chart","cert-manager-chart"} else image) for name in NAMES}
 components["vault-audit-relay"]["verification"]={"method":"cosign-and-slsa","status":"passed"}; components["gitops-oci-mirror"]["image_ref"]="ghcr.io/s1ns3nz0/node-operator/gitops-oci-mirror@"+digest
 return {"schema_version":1,"release_revision":revision,"components":components}

def described(args,digest):
 tag=args[args.index("--image-ids")+1].split("imageTag=",1)[1].split(",",1)[0]
 return json.dumps({"imageDetails":[{"registryId":args[args.index("--registry-id")+1],"repositoryName":args[args.index("--repository-name")+1],"imageDigest":digest,"imageTags":[tag]}]})
CHARTS={}
def chart_fixture(bundle, name, version):
 archive=("chart-"+name).encode(); config=("config-"+name).encode()
 config_digest=hashlib.sha256(config).hexdigest(); archive_digest=hashlib.sha256(archive).hexdigest()
 manifest=json.dumps({"schemaVersion":2,"config":{"mediaType":"application/vnd.cncf.helm.config.v1+json","digest":"sha256:"+config_digest,"size":len(config)},"layers":[{"mediaType":"application/vnd.cncf.helm.chart.content.v1.tar+gzip","digest":"sha256:"+archive_digest,"size":len(archive)}]},separators=(",",":")).encode()
 path=bundle/"source/.ci/gitops/helm-oci";path.mkdir(parents=True,exist_ok=True);(path/(name+".json")).write_text(json.dumps({"schema_version":1,"manifest_base64":base64.b64encode(manifest).decode(),"config_base64":base64.b64encode(config).decode()}))
 digest="sha256:"+hashlib.sha256(manifest).hexdigest(); CHARTS[digest]=(manifest,config,[{"mediaType":"application/vnd.cncf.helm.chart.content.v1.tar+gzip","digest":"sha256:"+archive_digest,"size":len(archive)}]); return archive, digest, archive_digest

def mock_chart_fixture(name, item):
 value=CHARTS.get(item.get("expected_oci_manifest_digest"))
 if value is None:
  raw=json.dumps({"schemaVersion":2,"config":{},"layers":[]},separators=(",",":")).encode(); value=(raw,b"",[]); CHARTS[item.get("expected_oci_manifest_digest")]=value
 return value

def mock_chart_layout(work, name, manifest, config, layers, archives):
 path=work/"oci"/name/"blobs/sha256";path.mkdir(parents=True,exist_ok=True);(path/hashlib.sha256(manifest).hexdigest()).write_bytes(manifest)
 return path.parents[2],"mirror-"+hashlib.sha256(manifest).hexdigest()
class Mirror(unittest.TestCase):
 def test_environment_cannot_redirect_aws_evidence(self):
  overrides={"AWS_ENDPOINT_URL":"http://invalid", "AWS_ENDPOINT_URL_STS":"http://invalid", "AWS_ENDPOINT_URL_ECR":"http://invalid", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS":"false", "AWS_DEFAULT_REGION":"us-east-1", "AWS_DEFAULT_PROFILE":"other", "GITHUB_TOKEN":"unchanged-fixture"}
  with patch.dict(os.environ,overrides):
   value=mirror_module._mirror_env("selected","ap-northeast-2")
   self.assertFalse(any(key.startswith("AWS_ENDPOINT_URL") for key in value))
   self.assertEqual(value["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"],"true")
   self.assertEqual(value["AWS_DEFAULT_REGION"],"ap-northeast-2")
   self.assertEqual(value["AWS_DEFAULT_PROFILE"],"selected")
   self.assertEqual(value["GITHUB_TOKEN"],"unchanged-fixture")
   self.assertEqual(os.environ["AWS_ENDPOINT_URL"],"http://invalid")
 def test_release_payload_copies_images_and_charts_without_vendor_download(self):
  with tempfile.TemporaryDirectory() as temporary:
   state,bundle,digest=self.fixture(Path(temporary)); layouts=state/"verified-oci"; layouts.mkdir()
   calls=[]
   class Result:
    def __init__(self,stdout=""): self.stdout=stdout
   def run(command,**kwargs):
    calls.append(command)
    if command[:3]==["aws","sts","get-caller-identity"]: return Result("123456789012")
    if command[:3]==["aws","ecr","get-login-password"]: return Result("fixture")
    return Result()
   with patch("installer_oci_binding.payload_context",return_value=nullcontext(layouts)), patch.object(mirror_module.subprocess,"run",side_effect=run), patch.object(mirror_module,"_describe_digest",side_effect=lambda a,r,repo,tag,expected,*args,**kwargs: expected):
    mirror(state,bundle,{"aws_account_id":"123456789012","aws_region":"ap-northeast-1","deployment_name":"fixture"},"test","c"*40,payload_dir=state,authenticated_bundle_manifest_sha256="a"*64)
   copies=[command for command in calls if command[:2]==["docker","run"]]
   self.assertEqual(len(copies),10)
   self.assertTrue(all(any(value.startswith("oci:/payload/") for value in command) for command in copies))
   self.assertTrue(all("--preserve-digests" in command for command in copies))
   self.assertFalse(any("curl" in value for command in calls for value in command))
   self.assertFalse(any(command[:3]==["aws","ecr","put-image"] for command in calls))
 def setUp(self):
  self.chart_patcher=patch.object(mirror_module,"_chart_fixture",side_effect=mock_chart_fixture);self.layout_patcher=patch.object(mirror_module,"_chart_layout",side_effect=mock_chart_layout);self.chart_patcher.start();self.layout_patcher.start()
  self.stage_patcher=patch.object(mirror_module,"_staged_chart_manifest");self.stage_patcher.start()
 def tearDown(self): self.chart_patcher.stop();self.layout_patcher.stop();self.stage_patcher.stop()
 def fixture(self, root):
  bundle=root/"bundle"; (bundle/"rendered").mkdir(parents=True)
  digest="sha256:"+"a"*64; image=lambda n:{"image_ref":f"ghcr.io/s1ns3nz0/node-operator/{n}@{digest}","manifest_digest":digest}
  components={n:image(n) for n in NAMES if n not in {"vault-chart","cert-manager-chart"}}
  for n in ("vault-chart","cert-manager-chart"):
   archive,manifest_digest,archive_digest=chart_fixture(bundle,n,"1.2.3"); components[n]={"approved_url":"https://vendor.invalid/"+n+".tgz","archive_sha256":archive_digest,"expected_oci_manifest_digest":manifest_digest,"tag":"v1","version":"1.2.3"}
  (bundle/"rendered/installer-artifact-index.json").write_text(json.dumps({"schema_version":1,"release_revision":"c"*40,"components":components}))
  state=root/"state"; state.mkdir(mode=0o700); (state/"terraform-work").mkdir()
  repos={k:"123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/private/"+v for k,v in {"vault":"vault","vault_chart":"vault/vault","cert_manager":"cert","cert_manager_chart":"cert/cert-manager"}.items()}
  out={"private_gitops_ecr_repository_urls":{"sensitive":False,"value":repos},"vault_audit_relay_ecr_repository_url":{"sensitive":False,"value":"123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/private/relay"}}
  (state/"terraform-work/baseline-output.json").write_text(json.dumps(out)); return state,bundle,digest
 def test_missing_or_wrong_index_never_starts_copy(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t); state=root/"state"; state.mkdir(mode=0o700); (state/"terraform-work").mkdir()
   with self.assertRaises(MirrorError): mirror(state, root, {"aws_account_id":"123456789012","aws_region":"ap-northeast-1"}, "test", "a"*40)
 def test_uncertain_marker_blocks_retry(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t); state=root/"state"; state.mkdir(mode=0o700); (state/"vault-artifact-mirror-uncertain.json").write_text("{}")
   with self.assertRaises(MirrorError): mirror(state, root, {"aws_account_id":"123456789012","aws_region":"ap-northeast-1"}, "test", "a"*40)
 def test_full_payload_flow_and_partial_failure_retains_marker(self):
  for partial in (False,True):
   with self.subTest(partial=partial), tempfile.TemporaryDirectory() as t:
    state,bundle,digest=self.fixture(Path(t))
    calls=[]
    auth_snapshots=[]
    class R:
     def __init__(self,s=""): self.stdout=s
    def run(args,**kwargs):
     calls.append((args,kwargs))
     if args[:2]==["docker","run"] and any(item.endswith(":/auth:ro") for item in args):
      volume=args[args.index("--volume")+1]; auth_path=Path(volume.split(":",1)[0])/"config.json"
      auth_snapshots.append((json.loads(auth_path.read_text()), auth_path.stat().st_mode & 0o777, auth_path.parent.stat().st_mode & 0o777, auth_path.parent))
     if args[:2]==["docker","run"] and any("curl --fail" in str(value) for value in args):
      work=Path(args[args.index("--volume")+1].split(":",1)[0]); filename=Path(args[-3]).name; (work/filename).write_bytes(("chart-"+filename.removesuffix(".tgz")).encode())
     if args[:3]==["aws","sts","get-caller-identity"]: return R("123456789012\n")
     if args[:3]==["aws","ecr","get-login-password"]: return R("token")
     if args[:3]==["aws","ecr","batch-get-image"]:
      stage=args[args.index("--image-ids")+1].split("=",1)[1]; raw=next(raw for raw,_,_ in CHARTS.values() if stage.endswith(hashlib.sha256(raw).hexdigest())); return R(json.dumps({"images":[{"imageManifest":raw.decode()}]}))
     if args[:3]==["aws","ecr","describe-images"]:
      expected="sha256:"+"b"*64 if partial and len([x for x,_ in calls if x[:3]==["aws","ecr","describe-images"]])==1 else digest
      if args[args.index("--image-ids")+1]=="imageTag=v1":
       component="vault-chart" if args[args.index("--repository-name")+1].endswith("/vault") else "cert-manager-chart"; expected=json.loads((bundle/"rendered/installer-artifact-index.json").read_text())["components"][component]["expected_oci_manifest_digest"]
      return R(described(args,expected))
     return R()
    discovery={"aws_account_id":"123456789012","aws_region":"ap-northeast-1","deployment_name":"node"}
    with patch("installer_artifact_mirror.subprocess.run",side_effect=run):
     if partial:
      with self.assertRaises(MirrorError): mirror(state,bundle,discovery,"profile","c"*40)
      self.assertTrue((state/"vault-artifact-mirror-uncertain.json").exists()); self.assertFalse((state/"vault-artifact-manifest.json").exists())
      with self.assertRaises(MirrorError): mirror(state,bundle,discovery,"profile","c"*40)
     else:
      output=mirror(state,bundle,discovery,"profile","c"*40); self.assertTrue(output.exists()); self.assertTrue((state/"vault-artifact-mirror-receipt.json").exists())
      manifest=json.loads(output.read_text()); self.assertEqual(set(manifest),{"schema_version","aws_account_id","aws_region","deployment_name","images","chart"}); self.assertEqual(set(manifest["images"]),{"bootstrap","server","agent","injector","audit_relay"}); self.assertEqual(manifest["images"]["server"],manifest["images"]["agent"])
      copies=[x for x,_ in calls if x[:3]==["docker","run","--rm"]]; self.assertEqual(len(copies),12)
      charts=[x for x in copies if "skopeo" in x]; self.assertEqual(len(charts),2)
      images=[x for x in copies if "--entrypoint" not in x]; self.assertEqual(len(images),8)
      self.assertTrue(all(any(part.startswith("docker://123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/private/") for part in call) for call in images))
      self.assertTrue(all("--preserve-digests" in call and "REGISTRY_AUTH_FILE=/auth/config.json" in call for call in charts))
      self.assertTrue(auth_snapshots)
      self.assertTrue(all(snapshot[0] == {"auths":{"123456789012.dkr.ecr.ap-northeast-1.amazonaws.com":{"auth":"QVdTOnRva2Vu"}}} and snapshot[1:3] == (0o600,0o700) for snapshot in auth_snapshots))
      self.assertTrue(all(not snapshot[3].exists() for snapshot in auth_snapshots))
      describe_calls=[x for x,_ in calls if x[:3]==["aws","ecr","describe-images"]]; self.assertEqual(len(describe_calls),10)
      self.assertIn("private/vault/vault", describe_calls[8])
      self.assertIn("private/cert/cert-manager", describe_calls[9])
 def test_preflight_failure_has_no_marker_or_copy(self):
  with tempfile.TemporaryDirectory() as t:
   state,bundle,_=self.fixture(Path(t)); calls=[]
   def run(args,**kwargs):
    calls.append(args)
    if args[:2]==["docker","pull"]: raise __import__("subprocess").CalledProcessError(1,args)
    return type("R",(),{"stdout":"123456789012\n"})()
   with patch("installer_artifact_mirror.subprocess.run",side_effect=run), self.assertRaises(MirrorError):
    mirror(state,bundle,{"aws_account_id":"123456789012","aws_region":"ap-northeast-1","deployment_name":"node"},"profile","c"*40)
   self.assertFalse((state/"vault-artifact-mirror-uncertain.json").exists())
   self.assertFalse(any(call[:3]==["docker","run","--rm"] for call in calls))
 def test_cert_manager_v_prefix_reaches_mocked_external_boundary_and_invalid_versions_stop_before_it(self):
  with tempfile.TemporaryDirectory() as t:
   state,bundle,_=self.fixture(Path(t)); index_path=bundle/"rendered/installer-artifact-index.json"; index=json.loads(index_path.read_text())
   chart=index["components"]["cert-manager-chart"]; chart.update(version="v1.21.1",tag="v1.21.1",approved_url="https://charts.jetstack.io/charts/cert-manager-v1.21.1.tgz")
   index_path.write_text(json.dumps(index)); calls=[]
   def run(args,**kwargs):
    calls.append(args); raise RuntimeError("mocked external boundary")
   with patch("installer_artifact_mirror.subprocess.run",side_effect=run), self.assertRaisesRegex(RuntimeError,"mocked external boundary"):
    mirror(state,bundle,{"aws_account_id":"123456789012","aws_region":"ap-northeast-1","deployment_name":"node"},"profile","c"*40)
   self.assertEqual(calls[0][:3],["aws","sts","get-caller-identity"])
  for version in ("vv1.21.1","1.21","v1.21.1/other","latest","v1.21.1\n"):
   with self.subTest(version=version), tempfile.TemporaryDirectory() as t:
    state,bundle,_=self.fixture(Path(t)); index_path=bundle/"rendered/installer-artifact-index.json"; index=json.loads(index_path.read_text()); index["components"]["cert-manager-chart"]["version"]=version; index_path.write_text(json.dumps(index)); calls=[]
    with patch("installer_artifact_mirror.subprocess.run",side_effect=lambda args,**kwargs: calls.append(args)), self.assertRaises(MirrorError):
     mirror(state,bundle,{"aws_account_id":"123456789012","aws_region":"ap-northeast-1","deployment_name":"node"},"profile","c"*40)
    self.assertEqual(calls,[])
 def test_pre_eks_cert_manager_v_prefix_passes_shared_and_local_validation_before_aws(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t); state=root/"state"; work=state/"terraform-work"; bundle=root/"bundle"; work.mkdir(parents=True); (bundle/"rendered").mkdir(parents=True); os.chmod(state,0o700); os.chmod(work,0o700)
   index=strict_index("c"*40); index["components"]["cert-manager-chart"].update(version="v1.21.1",tag="v1.21.1",approved_url="https://charts.jetstack.io/charts/cert-manager-v1.21.1.tgz"); (bundle/"rendered/installer-artifact-index.json").write_text(json.dumps(index)); projection_path=work/"artifact-prerequisites.json"; projection_path.write_text("{}")
   account="123456789012"; region="ap-northeast-1"; prefix="node-baseline-"; names=[prefix+"gitops-vault",prefix+"gitops-vault/vault",prefix+"gitops-cert-manager",prefix+"gitops-cert-manager/cert-manager",prefix+"vault-audit-relay"]
   loaded={"aws_account_id":account,"aws_region":region,"deployment_name":"node","input_fingerprint":"f"*64,"repositories":{name:{"url":f"{account}.dkr.ecr.{region}.amazonaws.com/{name}"} for name in names}}; calls=[]
   def run(args,**kwargs):
    calls.append(args); raise RuntimeError("mocked external boundary")
   with patch("installer_artifact_prerequisites.load_projection",return_value=loaded),patch("installer_artifact_mirror.subprocess.run",side_effect=run),self.assertRaisesRegex(RuntimeError,"mocked external boundary"):
    mirror(state,bundle,{"aws_account_id":account,"aws_region":region,"deployment_name":"node"},"profile","c"*40,prerequisites_path=projection_path,work_dir=work)
   self.assertEqual(calls[0][:3],["aws","sts","get-caller-identity"])
 def test_structured_ecr_identity_rejects_wrong_registry_or_repository(self):
  account="123456789012"; region="ap-northeast-1"; repository="private/vault"; digest="sha256:"+"a"*64
  for field, wrong in (("registryId","210987654321"),("repositoryName","private/foreign")):
   with self.subTest(field=field):
    row={"registryId":account,"repositoryName":repository,"imageDigest":digest}; row[field]=wrong
    with patch("installer_artifact_mirror.subprocess.run",return_value=type("R",(),{"stdout":json.dumps({"imageDetails":[row]})})()):
     with self.assertRaises(MirrorError): _describe_digest(account,region,repository,"v1",digest,{})
 def test_ecr_readback_requires_tag_on_the_approved_digest(self):
  account="123456789012"; region="ap-northeast-1"; repository="private/vault/vault"; digest="sha256:"+"a"*64
  for tags in (None, [], "v1", ["other"], ["v1", None], ["v1", "v1"], ["v1", "other"]):
   with self.subTest(tags=tags):
    row={"registryId":account,"repositoryName":repository,"imageDigest":digest,"imageTags":tags}
    with patch("installer_artifact_mirror.subprocess.run",return_value=type("R",(),{"stdout":json.dumps({"imageDetails":[row]})})()):
     if tags == ["v1", "other"]:
      self.assertEqual(_describe_digest(account,region,repository,"v1",digest,{}),digest)
     else:
      with self.assertRaises(MirrorError): _describe_digest(account,region,repository,"v1",digest,{})
  for response in ({"imageDetails":[]},{"imageDetails":[{"registryId":account,"repositoryName":repository,"imageDigest":digest}]*2},{"bad":True}):
   with self.subTest(response=response):
    with patch("installer_artifact_mirror.subprocess.run",return_value=type("R",(),{"stdout":json.dumps(response)})()):
     with self.assertRaises(MirrorError): _describe_digest(account,region,repository,"v1",digest,{})
 def test_pre_eks_projection_mirror_needs_no_baseline_and_freshly_rechecks(self):
  with tempfile.TemporaryDirectory() as t:
   state,bundle,digest=self.fixture(Path(t)); (state/"terraform-work/baseline-output.json").unlink(); projection=state/"terraform-work/artifact-prerequisites.json"; projection.write_text("{}")
   prefix="node-baseline-"; account="123456789012"; region="ap-northeast-1"
   names=[prefix+"gitops-vault",prefix+"gitops-vault/vault",prefix+"gitops-cert-manager",prefix+"gitops-cert-manager/cert-manager",prefix+"vault-audit-relay"]
   loaded={"aws_account_id":account,"aws_region":region,"deployment_name":"node","input_fingerprint":"f"*64,"repositories":{n:{"url":f"{account}.dkr.ecr.{region}.amazonaws.com/{n}"} for n in names}}
   calls=[]
   def run(args,**kwargs):
    calls.append(args)
    if args[:3]==["aws","sts","get-caller-identity"]: return type("R",(),{"stdout":account+"\n"})()
    if args[:3]==["aws","ecr","get-login-password"]: return type("R",(),{"stdout":"token"})()
    if args[:3]==["aws","ecr","describe-images"]:
     actual=digest
     if args[args.index("--image-ids")+1]=="imageTag=v1": actual=json.loads((bundle/"rendered/installer-artifact-index.json").read_text())["components"]["vault-chart" if args[args.index("--repository-name")+1].endswith("/vault") else "cert-manager-chart"]["expected_oci_manifest_digest"]
     return type("R",(),{"stdout":described(args,actual)})()
    return type("R",(),{"stdout":""})()
   with patch("installer_artifact_prerequisites.load_projection",return_value=loaded), patch("installer_artifact_mirror._strict_pre_eks_index"), patch("installer_artifact_mirror.subprocess.run",side_effect=run):
    output=mirror(state,bundle,{"aws_account_id":account,"aws_region":region,"deployment_name":"node"},"profile","c"*40,prerequisites_path=projection,work_dir=state/"terraform-work")
    self.assertEqual(output,state/"vault-artifact-manifest.json"); self.assertTrue((state/"vault-artifact-mirror-receipt.json").exists())
    binding=json.loads((state/"vault-pre-eks-artifact-mirror-binding.json").read_text()); self.assertEqual(binding["input_fingerprint"],"f"*64); self.assertIn("projection_sha256",binding)
    self.assertEqual(len([c for c in calls if c[:3]==["aws","ecr","describe-images"]]),10)
   def mismatch(args,**kwargs):
    if args[:3]==["aws","sts","get-caller-identity"]: return type("R",(),{"stdout":account+"\n"})()
    if args[:3]==["aws","ecr","describe-images"]: return type("R",(),{"stdout":described(args,"sha256:"+"b"*64)})()
    return type("R",(),{"stdout":""})()
   with patch("installer_artifact_prerequisites.load_projection",return_value=loaded), patch("installer_artifact_mirror._strict_pre_eks_index"), patch("installer_artifact_mirror.subprocess.run",side_effect=mismatch), self.assertRaises(MirrorError):
    verify_pre_eks_vault_mirror(state,bundle,{"aws_account_id":account,"aws_region":region,"deployment_name":"node"},"profile","c"*40,work_dir=state/"terraform-work")
   changed=dict(loaded); changed["input_fingerprint"]="e"*64
   with patch("installer_artifact_prerequisites.load_projection",return_value=changed), patch("installer_artifact_mirror._strict_pre_eks_index"), self.assertRaises(MirrorError):
    verify_pre_eks_vault_mirror(state,bundle,{"aws_account_id":account,"aws_region":region,"deployment_name":"node"},"profile","c"*40,work_dir=state/"terraform-work")
 def test_pre_eks_partial_publication_resume_and_tampered_residue_fail_before_calls(self):
  with tempfile.TemporaryDirectory() as t:
   state,bundle,digest=self.fixture(Path(t)); work=state/"terraform-work"; projection_path=work/"artifact-prerequisites.json"; projection_path.write_text("{}")
   account="123456789012"; region="ap-northeast-1"; discovery={"aws_account_id":account,"aws_region":region,"deployment_name":"node"}; prefix="node-baseline-"; names=[prefix+"gitops-vault",prefix+"gitops-vault/vault",prefix+"gitops-cert-manager",prefix+"gitops-cert-manager/cert-manager",prefix+"vault-audit-relay"]
   loaded={"aws_account_id":account,"aws_region":region,"deployment_name":"node","input_fingerprint":"f"*64,"repositories":{n:{"url":f"{account}.dkr.ecr.{region}.amazonaws.com/{n}"} for n in names}}
   calls=[]
   def run(args,**kwargs):
    calls.append((args,kwargs))
    if args[:3]==["aws","sts","get-caller-identity"]: return type("R",(),{"stdout":account+"\n","returncode":0})()
    if args[:3]==["aws","ecr","get-login-password"]: return type("R",(),{"stdout":"token","returncode":0})()
    if args[:3]==["aws","ecr","describe-images"]:
     actual=digest
     if args[args.index("--image-ids")+1]=="imageTag=v1": actual=json.loads((bundle/"rendered/installer-artifact-index.json").read_text())["components"]["vault-chart" if args[args.index("--repository-name")+1].endswith("/vault") else "cert-manager-chart"]["expected_oci_manifest_digest"]
     return type("R",(),{"stdout":described(args,actual),"returncode":0})()
    return type("R",(),{"stdout":"","returncode":0})()
   import installer_artifact_mirror as mod
   original=mod._write; writes=[0]
   def crash(path,value):
    writes[0]+=1
    if path.name=="vault-artifact-mirror-receipt.json": raise MirrorError("fixture crash")
    return original(path,value)
   with patch("installer_artifact_prerequisites.load_projection",return_value=loaded),patch("installer_artifact_mirror._strict_pre_eks_index"),patch("installer_artifact_mirror.subprocess.run",side_effect=run),patch("installer_artifact_mirror._write",side_effect=crash):
    with self.assertRaises(MirrorError): mirror(state,bundle,discovery,"profile","c"*40,prerequisites_path=projection_path,work_dir=work)
   manifest=state/"vault-artifact-manifest.json"; marker=state/"vault-pre-eks-artifact-mirror-uncertain.json"; saved=manifest.read_bytes(); self.assertTrue(marker.exists())
   calls.clear()
   with patch("installer_artifact_prerequisites.load_projection",return_value=loaded),patch("installer_artifact_mirror._strict_pre_eks_index"),patch("installer_artifact_mirror.subprocess.run",side_effect=run):
    mirror(state,bundle,discovery,"profile","c"*40,prerequisites_path=projection_path,work_dir=work,resume=True)
   self.assertEqual(manifest.read_bytes(),saved); self.assertFalse(marker.exists()); self.assertFalse(any(c[:2]==["docker","run"] for c,_ in calls))
   for command,kwargs in calls:
    expected=DOCKER_TIMEOUT if command[:2] in (["docker","pull"],["docker","run"]) else AWS_TIMEOUT
    self.assertEqual(kwargs.get("timeout"),expected)
   calls.clear()
   with patch("installer_artifact_prerequisites.load_projection",return_value=loaded),patch("installer_artifact_mirror._strict_pre_eks_index"),patch("installer_artifact_mirror.subprocess.run",side_effect=run):
    mirror(state,bundle,discovery,"profile","c"*40,prerequisites_path=projection_path,work_dir=work,resume=True)
   self.assertFalse(any(c[0]=="docker" or c[:3]==["aws","ecr","get-login-password"] for c,_ in calls)); self.assertFalse((state/".vault-pre-eks-artifact-mirror.lock").exists())
   manifest.write_text("{}"); calls.clear()
   with patch("installer_artifact_prerequisites.load_projection",return_value=loaded),patch("installer_artifact_mirror._strict_pre_eks_index"),patch("installer_artifact_mirror.subprocess.run",side_effect=run),self.assertRaises(MirrorError): mirror(state,bundle,discovery,"profile","c"*40,prerequisites_path=projection_path,work_dir=work,resume=True)
   self.assertEqual(calls,[])
 def test_pre_eks_wrong_existing_tag_digest_rejects_before_docker_copy(self):
  with tempfile.TemporaryDirectory() as t:
   state,bundle,_=self.fixture(Path(t)); work=state/"terraform-work"; projection_path=work/"artifact-prerequisites.json"; projection_path.write_text("{}")
   account="123456789012"; region="ap-northeast-1"; discovery={"aws_account_id":account,"aws_region":region,"deployment_name":"node"}; prefix="node-baseline-"; names=[prefix+"gitops-vault",prefix+"gitops-vault/vault",prefix+"gitops-cert-manager",prefix+"gitops-cert-manager/cert-manager",prefix+"vault-audit-relay"]
   loaded={"aws_account_id":account,"aws_region":region,"deployment_name":"node","input_fingerprint":"f"*64,"repositories":{n:{"url":f"{account}.dkr.ecr.{region}.amazonaws.com/{n}"} for n in names}}; calls=[]
   def run(args,**kwargs):
    calls.append(args)
    if args[:3]==["aws","sts","get-caller-identity"]: return type("R",(),{"stdout":account,"returncode":0})()
    if args[:3]==["aws","ecr","get-login-password"]: return type("R",(),{"stdout":"token\n","returncode":0})()
    if args[:3]==["aws","ecr","describe-images"]: return type("R",(),{"stdout":described(args,"sha256:"+"b"*64),"returncode":0})()
    return type("R",(),{"stdout":"","returncode":0})()
   with patch("installer_artifact_prerequisites.load_projection",return_value=loaded),patch("installer_artifact_mirror._strict_pre_eks_index"),patch("installer_artifact_mirror.subprocess.run",side_effect=run),self.assertRaises(MirrorError):
    mirror(state,bundle,discovery,"profile","c"*40,prerequisites_path=projection_path,work_dir=work)
   self.assertTrue((state/"vault-pre-eks-artifact-mirror-uncertain.json").exists()); self.assertFalse(any(c[:2]==["docker","run"] for c in calls))
   index=json.loads((bundle/"rendered/installer-artifact-index.json").read_text()); index["components"]["vault-server"]["manifest_digest"]=""; (bundle/"rendered/installer-artifact-index.json").write_text(json.dumps(index))
   with patch("installer_artifact_prerequisites.load_projection",return_value=loaded), patch("installer_artifact_mirror._strict_pre_eks_index"), self.assertRaises(MirrorError):
    verify_pre_eks_vault_mirror(state,bundle,{"aws_account_id":account,"aws_region":region,"deployment_name":"node"},"profile","c"*40,work_dir=state/"terraform-work")
 def test_pre_eks_real_projection_and_strict_index_without_baseline(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t).resolve(); state=root/"deployment-work"; work=state/"terraform-work"; bundle=root/"bundle"; inputs=root/"inputs/zero-resource"; work.mkdir(parents=True); bundle.mkdir(); (bundle/"rendered").mkdir(); inputs.mkdir(parents=True); os.chmod(state,0o700); os.chmod(work,0o700); os.chmod(bundle,0o700); os.chmod(inputs,0o700)
   account="123456789012"; region="ap-northeast-2"; name="node-operator"; discovery={"aws_account_id":account,"aws_region":region,"deployment_name":name}
   for filename, value in (("bootstrap-state.tfvars.json",{"aws_account_id":account}), ("foundation-network.tfvars.json",{"aws_region":region}), ("baseline.tfvars.json",{"name":name})):
    path=inputs/filename; path.write_text(json.dumps(value)); os.chmod(path,0o600)
   manifest=bundle/"bundle-manifest.json"; manifest.write_text("{}"); os.chmod(manifest,0o600)
   fingerprint=_projection_fingerprint(inputs,bundle); checkpoint=work/"zero-inputs.sha256"; checkpoint.write_text(fingerprint); os.chmod(checkpoint,0o600)
   receipt=projection(_fixture.state_fixture(),account,region,name,fingerprint); path=work/"artifact-prerequisites.json"; path.write_text(json.dumps(receipt)); os.chmod(path,0o600)
   index=strict_index("c"*40); index_path=bundle/"rendered/installer-artifact-index.json"; index_path.write_text(json.dumps(index)); os.chmod(index_path,0o600)
   calls=[]
   def run(args,**kwargs):
    calls.append(args)
    if args[:3]==["aws","sts","get-caller-identity"]: return type("R",(),{"stdout":account+"\n"})()
    if args[:3]==["aws","ecr","get-login-password"]: return type("R",(),{"stdout":"token"})()
    if args[:3]==["aws","ecr","describe-images"]: return type("R",(),{"stdout":described(args,"sha256:"+"a"*64)})()
    return type("R",(),{"stdout":""})()
   with patch("installer_artifact_mirror.subprocess.run",side_effect=run):
    mirror(state,bundle,discovery,"profile","c"*40,prerequisites_path=path,inputs_dir=inputs,work_dir=work)
    self.assertFalse((work/"baseline-output.json").exists()); self.assertEqual(len([x for x in calls if x[:3]==["aws","ecr","describe-images"]]),10)
    verify_pre_eks_vault_mirror(state,bundle,discovery,"profile","c"*40,inputs_dir=inputs,work_dir=work)
   prefix=f"{account}.dkr.ecr.{region}.amazonaws.com/"; refreshed={"private_gitops_ecr_repository_urls":{"sensitive":False,"value":{"vault":prefix+name+"-baseline-gitops-vault","vault_chart":prefix+name+"-baseline-gitops-vault/vault","cert_manager":prefix+name+"-baseline-gitops-cert-manager","cert_manager_chart":prefix+name+"-baseline-gitops-cert-manager/cert-manager"}},"vault_audit_relay_ecr_repository_url":{"sensitive":False,"value":prefix+name+"-baseline-vault-audit-relay"}}
   self.assertEqual(platform_artifacts(bundle/"rendered/installer-artifact-index.json",state/"vault-artifact-mirror-receipt.json",refreshed,discovery)[0],prefix+name+"-baseline-gitops-vault@sha256:"+"a"*64)
   receipt_path=state/"vault-artifact-mirror-receipt.json"; receipt_raw=receipt_path.read_text(); receipt=json.loads(receipt_raw); receipt["status"]="tampered"; receipt_path.write_text(json.dumps(receipt)); os.chmod(receipt_path,0o600)
   with self.assertRaises(MirrorError): verify_pre_eks_vault_mirror(state,bundle,discovery,"profile","c"*40,inputs_dir=inputs,work_dir=work)
   receipt_path.write_text(receipt_raw); os.chmod(receipt_path,0o600)
   sidecar=state/"vault-pre-eks-artifact-mirror-binding.json"; side=json.loads(sidecar.read_text()); side["input_fingerprint"]="0"*64; sidecar.write_text(json.dumps(side)); os.chmod(sidecar,0o600)
   with self.assertRaises(MirrorError): verify_pre_eks_vault_mirror(state,bundle,discovery,"profile","c"*40,inputs_dir=inputs,work_dir=work)
   (inputs/"baseline.tfvars.json").write_text('{"changed":true}')
   os.chmod(inputs/"baseline.tfvars.json",0o600)
   with self.assertRaises(MirrorError): verify_pre_eks_vault_mirror(state,bundle,discovery,"profile","c"*40,inputs_dir=inputs,work_dir=work)
if __name__=="__main__": unittest.main()

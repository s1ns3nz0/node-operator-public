#!/usr/bin/env python3
# Check objective: Validate signer identity probe publishing with fake CLI tools.
"""Offline fake-CLI contract for the signer identity probe publisher."""
import os, pathlib, shutil, subprocess, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]

class Publisher(unittest.TestCase):
 def setUp(self):
  self.tmp=pathlib.Path(tempfile.mkdtemp()); self.fixture=self.tmp/"source"; self.bin=self.tmp/"bin"; self.bin.mkdir()
  files=("go.mod", ".ci/validator-signer-identity-probe/Dockerfile", ".ci/validator-signer-identity-probe/Dockerfile.dockerignore", "cmd/validator-signer-identity-probe/main.go", "cmd/validator-signer-identity-probe/main_test.go", "scripts/release/publish-signer-identity-probe.sh", "scripts/release/signer_probe_build_inputs.py", "scripts/release/signer_probe_publication_record.py", "scripts/release/fence_build_inputs.py", "scripts/ci/install-validator-signing-fence-release-tools.sh", "scripts/ci/scan-release-sbom.sh", "scripts/ci/verify-release-scan-attestation.sh", "scripts/ci/lib/common.sh", ".github/workflows/image-publish.yml")
  for item in files:
   out=self.fixture/item; out.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(ROOT/item,out)
  self.sha="a"*40; self.digest="sha256:"+"b"*64
  self.fake("git", "#!/bin/sh\n[ \"$1\" = rev-parse ] && { echo \"$GITHUB_SHA\"; exit 0; }; [ \"$1\" = diff ] && [ \"$FAKE_MODE\" = dirty ] && exit 1; exit 0\n")
  self.fake("curl", "#!/bin/sh\nprintf curl >> \"$AUDIT\"; while [ \"$#\" -gt 0 ]; do [ \"$1\" = --output ] && { shift; echo '{\"value\":\"token\"}' > \"$1\"; exit; }; shift; done\n")
  self.fake("aws", "#!/usr/bin/env bash\ncase \"$1:$2\" in sts:assume-role-with-web-identity) echo '{\"Credentials\":{\"AccessKeyId\":\"key\",\"SecretAccessKey\":\"secret\",\"SessionToken\":\"session\"}}' ;; sts:get-caller-identity) echo '{\"Account\":\"123456789012\",\"Arn\":\"arn:aws:sts::123456789012:assumed-role/test-role/x\"}' ;; ecr:get-login-password) [ \"$FAKE_MODE\" = large-login ] && { head -c 131072 /dev/zero | tr '\\0' p; exit; }; echo password ;; *) d=sha256:$(printf 'b%.0s' {1..64}); [ \"$FAKE_MODE\" = bad-digest ] && d=sha256:$(printf 'c%.0s' {1..64}); for x; do case \"$x\" in imageTag=*) t=${x#imageTag=}; t=${t%%,*};; esac; done; printf '{\"imageDetails\":[{\"registryId\":\"123456789012\",\"repositoryName\":\"node-operator-baseline-validator-signer-identity-probe\",\"imageDigest\":\"%s\",\"imageTags\":[\"%s\"],\"imageManifestMediaType\":\"application/vnd.oci.image.manifest.v1+json\"}]}\\n' \"$d\" \"$t\";; esac\n")
  self.fake("docker", "#!/usr/bin/env bash\n[ \"$1\" = build ] && [ \"$FAKE_MODE\" = signal ] && kill -INT \"$PPID\"\ncase \"$1:$2\" in image:inspect) case \"$4\" in *Os*Architecture*) echo linux/amd64;; *Labels*) [ \"$4\" = '{{ index .Config.Labels \"io.node-operator.signer-probe-input-sha\" }}' ] || exit 93; python3 -c 'from pathlib import Path; import sys; sys.path.insert(0,str(Path.cwd()/\"scripts/release\")); from signer_probe_build_inputs import signer_probe_input_sha256; print(signer_probe_input_sha256(Path.cwd()))';; *RepoDigests*) [ \"$FAKE_MODE\" = bad-pushed ] && echo '[]' || echo '[\"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-signer-identity-probe@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"]';; esac;; login:*) cat >/dev/null;; *) exit 0;; esac\n")
  self.fake("syft", "#!/bin/sh\nfor x; do case \"$x\" in cyclonedx-json=*) o=${x#*=};; sha256:*) d=${x##*@};; esac; done; printf '{\"metadata\":{\"component\":{\"version\":\"%s\"}}}\\n' \"$d\" > \"$o\"\n")
  self.fake("grype", "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do [ \"$1\" = --file ] && { shift; m=''; [ \"$FAKE_MODE\" = scan-fail ] && m='{\"vulnerability\":{\"severity\":\"High\"}}'; printf '{\"matches\":[%s],\"descriptor\":{\"name\":\"grype\",\"version\":\"1\",\"db\":{\"status\":{\"built\":\"2026\",\"valid\":true,\"schemaVersion\":\"1\"}}}}\\n' \"$m\" > \"$1\"; exit; }; shift; done\n")
  cosign="""#!/usr/bin/env python3
import base64,json,os,pathlib,sys
cmd=sys.argv[1]; args=sys.argv[2:]; mode=os.environ['FAKE_MODE']; subject=args[-1]; digest=subject.rsplit('@sha256:',1)[1]
if cmd in ('sign','attest','version'): raise SystemExit(0)
for flag, value in (('--certificate-identity','https://github.com/s1ns3nz0/node-operator/.github/workflows/image-publish.yml@refs/heads/main'),('--certificate-oidc-issuer','https://token.actions.githubusercontent.com'),('--certificate-github-workflow-sha',os.environ['GITHUB_SHA'])):
 if flag not in args or args[args.index(flag)+1] != value: raise SystemExit(92)
if cmd=='verify':
 reference = subject
 signature_digest = digest
 if mode == 'bad-signature-reference': reference = 'other.example/not-the-subject@sha256:' + digest
 if mode == 'bad-signature-digest': signature_digest = 'c' * 64
 print(json.dumps([{'critical':{'image':{'docker-manifest-digest':'sha256:'+signature_digest},'identity':{'docker-reference':reference}}}])); raise SystemExit(0)
typ=args[args.index('--type')+1]; evidence=next(pathlib.Path(os.environ['RUNNER_TEMP']).glob('.signer-probe-release.*/evidence'))
path={'slsaprovenance1':'provenance.json','cyclonedx':'sbom.json'}.get(typ,'scan.json'); predicate=json.loads((evidence/path).read_text()); ptype={'slsaprovenance1':'https://slsa.dev/provenance/v1','cyclonedx':'https://cyclonedx.org/bom'}.get(typ,'https://github.com/s1ns3nz0/node-operator/attestations/scan-summary/v1')
if mode=='bad-provenance' and typ=='slsaprovenance1': predicate={}
name='other.example/not-the-subject' if mode=='bad-subject' else subject.rsplit('@',1)[0]
print(json.dumps({'payload':base64.b64encode(json.dumps({'_type':'https://in-toto.io/Statement/v1','subject':[{'name':name,'digest':{'sha256':digest}}],'predicateType':ptype,'predicate':predicate}).encode()).decode()}))
"""
  self.fake("cosign",cosign); installer=self.fixture/"scripts/ci/install-validator-signing-fence-release-tools.sh"; installer.write_text("#!/usr/bin/env bash\nmkdir -p \"$1\"; cp \"$FAKE_BIN\"/{cosign,syft,grype} \"$1\"/\n"); installer.chmod(0o700)
 def tearDown(self): shutil.rmtree(self.tmp)
 def fake(self,name,text):
  p=self.bin/name; p.write_text(text); p.chmod(0o700)
 def invoke(self,mode,**overrides):
  run=self.tmp/mode; run.mkdir(exist_ok=True); audit=run/"audit"
  if mode=="collision": (run/"signer-probe-publication-records").mkdir()
  env=os.environ|{"PATH":f"{self.bin}:{os.environ['PATH']}","FAKE_BIN":str(self.bin),"FAKE_MODE":mode,"RUNNER_TEMP":str(run),"GITHUB_REF":"refs/heads/main","GITHUB_REPOSITORY":"s1ns3nz0/node-operator","GITHUB_SHA":self.sha,"GITHUB_RUN_ID":"42","GITHUB_RUN_ATTEMPT":"1","ACCOUNT_ID":"123456789012","AWS_REGION":"ap-northeast-2","AWS_ROLE_ARN":"arn:aws:iam::123456789012:role/test-role","DEPLOYMENT_NAME":"node-operator","ACTIONS_ID_TOKEN_REQUEST_URL":"https://oidc.example","ACTIONS_ID_TOKEN_REQUEST_TOKEN":"token","AUDIT":str(audit),"GITHUB_STEP_SUMMARY":"/dev/null"}
  return subprocess.run(["bash",str(self.fixture/"scripts/release/publish-signer-identity-probe.sh")],cwd=self.fixture,env=env|overrides,text=True,capture_output=True,timeout=30),run
 def test_publisher_and_fail_closed_paths(self):
  result,run=self.invoke("ok"); self.assertEqual(result.returncode,0,result.stderr); self.assertTrue((run/"signer-probe-publication-records/signer-identity-probe-publication-record.json").is_file()); self.assertFalse(list(run.glob(".signer-probe-release.*")))
  for mode in ("dirty","bad-digest","bad-pushed","scan-fail","bad-provenance","bad-subject","bad-signature-reference","bad-signature-digest","signal","collision"):
   result,run=self.invoke(mode); self.assertNotEqual(result.returncode,0,(mode,result.stderr)); self.assertFalse((run/"signer-probe-publication-records/signer-identity-probe-publication-record.json").exists()); self.assertFalse(list(run.glob(".signer-probe-release.*")))
   if mode in ("dirty", "collision"): self.assertFalse((run/"audit").exists())
   if mode=="signal": self.assertEqual(result.returncode, 130, result.stderr)
  result,run=self.invoke("wrong-repository",GITHUB_REPOSITORY="other/repository"); self.assertNotEqual(result.returncode,0); self.assertFalse((run/"audit").exists())
 def test_docker_login_consumes_large_password_pipe(self):
  result,run=self.invoke("large-login"); self.assertEqual(result.returncode,0,result.stderr); self.assertTrue((run/"signer-probe-publication-records/signer-identity-probe-publication-record.json").is_file())
if __name__=='__main__': unittest.main(verbosity=2)

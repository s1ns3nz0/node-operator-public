#!/usr/bin/env python3
# Check objective: Validate the artifact-first infrastructure path at its shell boundary.
"""Shell-boundary checks for the central artifact-first infrastructure path."""
import errno, json, os, pty, select, signal, subprocess, tempfile, time, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
CLI=ROOT/"scripts/release/hoodi-validator-release.sh"

class ArtifactFirst(unittest.TestCase):
 def test_payload_release_requires_authenticated_handoff_before_aws(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp); env,args,log=self.fixture(root)
   (root/"bundle/rendered").mkdir(); (root/"bundle/rendered/installer-oci-payload-manifest.json").write_text("{}")
   env.pop("NODE_OPERATOR_OCI_PAYLOAD_DIR",None); env.pop("NODE_OPERATOR_AUTHENTICATED_BUNDLE_MANIFEST_SHA256",None)
   result=subprocess.run([str(CLI),*args],text=True,capture_output=True,env=env)
   self.assertNotEqual(result.returncode,0)
   self.assertIn("authenticated release launcher",result.stderr)
   self.assertFalse(any(row.startswith("aws:") or "node:zero:" in row for row in log.read_text().splitlines()))
 def test_payload_arguments_reach_both_copiers_not_readonly_verify(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp); env,args,log=self.fixture(root)
   payload=root/"payload"; payload.mkdir()
   env.update(NODE_OPERATOR_OCI_PAYLOAD_DIR=str(payload),NODE_OPERATOR_AUTHENTICATED_BUNDLE_MANIFEST_SHA256="b"*64)
   helper=root/"bundle/source/scripts/release/mirror-installer-vault-artifacts.py"
   helper.write_text('import os,sys\na=sys.argv\nif a[1]=="verify":\n assert "--oci-payload-dir" not in a\nelse:\n assert a[a.index("--oci-payload-dir")+1]==os.environ["NODE_OPERATOR_OCI_PAYLOAD_DIR"]\n assert a[a.index("--verified-bundle-manifest-sha256")+1]=="b"*64\nopen(os.environ["LOG"],"a").write("payload-args:"+a[1]+"\\n")\n')
   result=subprocess.run([str(CLI),*args],text=True,capture_output=True,env=env)
   self.assertEqual(result.returncode,0,result.stderr)
   self.assertEqual(log.read_text().count("payload-args:mirror"),2)
   self.assertEqual(log.read_text().count("payload-args:verify"),2)
 def fixture(self, root, fail=""):
  bundle=root/"bundle"; release=bundle/"source/scripts/release"; release.mkdir(parents=True)
  work=root/"work"; inputs=root/"inputs"; zero=inputs/"zero-resource"; zero.mkdir(parents=True)
  account="123456789012"; region="ap-northeast-2"; name="node-operator"; sha="a"*40
  (bundle/"bundle-manifest.json").write_text(json.dumps({"source_revision":sha}))
  baseline=zero/"baseline.tfvars.json"; baseline.write_text(json.dumps({"name":name}))
  (zero/"zero-resource-inputs.json").write_text(json.dumps({"schema_version":1,"aws_account_id":account,"aws_region":region,"baseline_config":str(baseline)}))
  (inputs/"validator-deployment").mkdir(); (inputs/"validator-deployment/validator-deployment-handoff.json").write_text(json.dumps({"schema_version":1,"network":"hoodi","aws_account_id":account,"aws_region":region,"staged_client_replicas":0,"staged_fence_replicas":0}))
  (inputs/"hoodi-zero-release-inputs.json").write_text(json.dumps({"schema_version":1,"network":"hoodi","aws_account_id":account,"aws_region":region,"validator_set":"hoodi-1","zero_resource_inputs":str(zero/"zero-resource-inputs.json"),"validator_deployment_handoff":str(inputs/"validator-deployment/validator-deployment-handoff.json"),"required_checkpoints":[1,2,3,4,5,6]}))
  log=root/"log"
  def fake(name, body):
   p=release/name; p.write_text("#!/bin/sh\n"+body); p.chmod(0o755)
  fake("node-operator-release.sh",'echo "node:$1:$2:$*:$AWS_PROFILE:${AWS_ACCESS_KEY_ID-unset}:$GITHUB_TOKEN" >> "$LOG"; if [ "$1:$2" = "zero:prepare-artifacts" ]; then mkdir -p "$8"; fi; [ "${FAIL_NODE_PHASE:-}" = "$1:$2" ] && exit 7; exit 0')
  fake("bootstrap-local-installer-artifacts.sh", 'echo "bootstrap:$AWS_PROFILE" >> "$LOG"; : > "$4/local-artifact-authority.json"; if [ "${BOOTSTRAP_FAIL:-}" = 1 ]; then exit 8; fi')
  inventory=release/"installer_artifact_inventory.py"; inventory.write_text('#!/usr/bin/env python3\nimport os,sys\nopen(os.environ["LOG"],"a").write("inventory:%s:%s:%s\\n"%(os.environ["AWS_PROFILE"],os.environ.get("AWS_ACCESS_KEY_ID","unset"),os.environ["GITHUB_TOKEN"]))\nsys.exit(int(os.environ.get("INV_FAIL","0")))\n'); inventory.chmod(0o755)
  fake("prepare-hoodi-zero-release-inputs.sh",'[ -z "${AWS_ACCESS_KEY_ID+x}${AWS_SECRET_ACCESS_KEY+x}${AWS_SESSION_TOKEN+x}${AWS_SECURITY_TOKEN+x}" ] || exit 91; for arg in "$@"; do [ -n "$arg" ] || exit 92; done; echo "prepare:$AWS_PROFILE:$GITHUB_TOKEN" >> "$LOG"; exit 23')
  mirror=release/"mirror-installer-vault-artifacts.py"; mirror.write_text('#!/usr/bin/env python3\nimport os,sys\nscope="non-vault" if "--scope" in sys.argv else "vault"\nstep=scope+":"+sys.argv[1]\nopen(os.environ["LOG"],"a").write("mirror:%s:%s\\n"%(step,os.environ["AWS_PROFILE"]))\nsys.exit(8 if os.environ.get("FAIL_MIRROR_COMMAND")==step else 0)\n'); mirror.chmod(0o755)
  bin=root/"bin"; bin.mkdir(); aws=bin/"aws"; aws.write_text('#!/bin/sh\n[ -z "${AWS_ACCESS_KEY_ID+x}${AWS_SECRET_ACCESS_KEY+x}${AWS_SESSION_TOKEN+x}${AWS_SECURITY_TOKEN+x}" ] || exit 91\necho "aws:$1:$2:$AWS_PROFILE:$GITHUB_TOKEN" >> "$LOG"\n[ "${STS_FAIL:-}" = 1 ] && exit 9\n[ "$1:$2" = "sts:get-caller-identity" ] && { case " $* " in *" --output text "*) echo 123456789012 ;; *) echo "{\\"Account\\":\\"123456789012\\",\\"Arn\\":\\"arn:aws:iam::123456789012:role/test\\"}" ;; esac; exit 0; }\n[ "$1:$2" = "ec2:describe-availability-zones" ] && { printf "ap-northeast-2a\\nap-northeast-2b\\n"; exit 0; }; exit 64\n'); aws.chmod(0o755)
  env={**os.environ,"PATH":str(bin)+os.pathsep+os.environ["PATH"],"LOG":str(log),"AWS_ACCESS_KEY_ID":"bad","AWS_SECRET_ACCESS_KEY":"bad","AWS_SESSION_TOKEN":"bad","AWS_SECURITY_TOKEN":"bad","GITHUB_TOKEN":"kept"}
  args=["infrastructure","apply","--bundle-root",str(bundle),"--inputs",str(inputs/"hoodi-zero-release-inputs.json"),"--work-dir",str(work),"--profile","chosen"]
  return env,args,log
 def test_order_profile_and_fail_closed_boundaries(self):
  for failure, needle in (("",None),("INV_FAIL","inventory"),("FAIL_MIRROR_COMMAND","vault:mirror")):
   with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temp:
    env,args,log=self.fixture(Path(temp)); env[failure]="vault:mirror" if failure else ""
    result=subprocess.run([str(CLI),*args],text=True,capture_output=True,env=env)
    rows=log.read_text().splitlines() if log.exists() else []
    if failure:
     self.assertNotEqual(result.returncode,0); self.assertFalse(any("node:zero:apply" in x for x in rows))
    else:
     self.assertEqual(result.returncode,0,result.stderr); self.assertLess(rows.index(next(x for x in rows if "node:zero:prepare-artifacts" in x)), rows.index(next(x for x in rows if x.startswith("inventory:")))); self.assertTrue(rows[-1].startswith("node:zero:apply")); self.assertTrue(all(":chosen:unset:kept" in x for x in rows if x.startswith("inventory:") or x.startswith("node:zero:")))
 def test_vault_partial_state_resumes_without_forcing_non_vault_resume(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp); env,args,log=self.fixture(root); work=Path(args[args.index("--work-dir")+1]); work.mkdir(); (work/"vault-artifact-mirror-receipt.json").write_text("partial")
   result=subprocess.run([str(CLI),*args],text=True,capture_output=True,env=env); self.assertEqual(result.returncode,0,result.stderr)
   rows=log.read_text().splitlines(); self.assertIn("mirror:vault:resume:chosen",rows); self.assertIn("mirror:non-vault:mirror:chosen",rows)
 def test_invalid_baseline_path_stops_before_sts(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp); env,args,log=self.fixture(root); zero=root/"inputs/zero-resource/zero-resource-inputs.json"; value=json.loads(zero.read_text()); value["baseline_config"]="/foreign"; zero.write_text(json.dumps(value))
   result=subprocess.run([str(CLI),*args],text=True,capture_output=True,env=env); self.assertNotEqual(result.returncode,0); self.assertEqual(len(log.read_text().splitlines()),1); self.assertTrue(log.read_text().startswith("node:verify:"))
 def test_each_artifact_first_stage_failure_blocks_zero_apply(self):
  for key,value in (("STS_FAIL","1"),("FAIL_NODE_PHASE","zero:prepare-artifacts"),("BOOTSTRAP_FAIL","1"),("FAIL_MIRROR_COMMAND","vault:mirror"),("FAIL_MIRROR_COMMAND","vault:verify"),("FAIL_MIRROR_COMMAND","non-vault:mirror"),("FAIL_MIRROR_COMMAND","non-vault:verify")):
   with self.subTest(key=key,value=value),tempfile.TemporaryDirectory() as temp:
    env,args,log=self.fixture(Path(temp)); env[key]=value
    result=subprocess.run([str(CLI),*args],text=True,capture_output=True,env=env); self.assertNotEqual(result.returncode,0)
    rows=log.read_text().splitlines() if log.exists() else []; self.assertFalse(any("node:zero:apply" in row for row in rows))
 def test_interactive_prepare_uses_selected_profile_for_initial_aws_calls(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp); env,_,log=self.fixture(root); bundle=root/"bundle"; output=root/"prepared"
   supplied="hoodi-1\n0x"+"1"*96+"\n0x"+"2"*40+"\nweb@sha256:"+"a"*64+"\npost@sha256:"+"a"*64+"\nprysm@sha256:"+"a"*64+"\nfence@sha256:"+"a"*64+"\n1.2.3.4/32\n"
   master,slave=pty.openpty()
   output_bytes=b""
   try:
    process=subprocess.Popen([str(CLI),"interactive","prepare","--bundle-root",str(bundle),"--output-dir",str(output),"--profile","chosen"],stdin=slave,stdout=slave,stderr=slave,env=env,close_fds=True,start_new_session=True)
    os.close(slave); slave=-1; sent=False; deadline=time.monotonic()+10
    while time.monotonic()<deadline and process.poll() is None:
     ready,_,_=select.select([master],[],[],.1)
     if ready:
      try: chunk=os.read(master,4096)
      except OSError as error:
       if error.errno!=errno.EIO: raise
       chunk=b""
      output_bytes+=chunk
      if not sent and b"Validator set" in output_bytes:
       os.write(master,supplied.encode()); sent=True
    if process.poll() is None:
     os.killpg(process.pid,signal.SIGKILL); process.wait(); self.fail("interactive PTY timeout: "+output_bytes.decode(errors="replace"))
   finally:
    if 'process' in locals() and process.poll() is None:
     process.terminate()
     try: process.wait(timeout=2)
     except subprocess.TimeoutExpired:
      process.kill(); process.wait(timeout=2)
    if slave!=-1: os.close(slave)
    os.close(master)
   self.assertEqual(process.returncode,23,output_bytes.decode(errors="replace")); rows=log.read_text().splitlines(); aws_rows=[row for row in rows if row.startswith("aws:")]
   self.assertGreaterEqual(len(aws_rows),2); self.assertTrue(all(":chosen:kept" in row for row in aws_rows)); self.assertEqual(rows[-1],"prepare:chosen:kept")

if __name__=="__main__": unittest.main()

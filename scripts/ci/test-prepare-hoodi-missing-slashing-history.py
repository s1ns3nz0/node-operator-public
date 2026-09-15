#!/usr/bin/env python3
"""Mocked fail-closed execution test for the Hoodi maintenance command."""
import os, shutil, subprocess, tempfile, textwrap, time, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMAND = ROOT / "scripts/ops/prepare-hoodi-missing-slashing-history.sh"
KEY = "0x" + "a" * 96

FAKE_KUBECTL = r'''#!/usr/bin/python3
import json, os, re, sys
args=sys.argv[1:]; log=os.environ["MOCK_LOG"]; mode=os.environ.get("MOCK_MODE","")
def obj(kind, name):
  meta={"uid":name+"-uid","resourceVersion":"1","generation":1,"name":name,"namespace":"validator-operations","labels":{"node-operator.io/validator-set":"hoodi-example","app.kubernetes.io/component":"validator-slashing-db"}}
  signer_image="123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-op-test-validator-runtime-web3signer@sha256:9a20e02a5821ad72fd318fa2a3ec0158a9a5acd9db80aa9214e9cc991ad4dbc3"
  db_image="123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-op-test-validator-runtime-postgres@sha256:bb3e1a57e5407e0a5280b4211980a5e537f4abd234a87014ac979849a78dd825"
  claim="data-validator-hoodi-example-slashing-db-0"
  if mode=="tamperedimage": signer_image=signer_image.replace("9a20","dead")
  if kind=="deployment": meta["labels"]={}; replicas=1 if mode=="active" and name.endswith("remote-signer") else 0; return {"metadata":meta,"spec":{"replicas":replicas,"template":{"spec":{"containers":[{"name":"web3signer","image":signer_image}]}}},"status":{"replicas":replicas,"readyReplicas":replicas,"observedGeneration":1}}
  if kind=="statefulset": return {"metadata":meta,"spec":{"replicas":0 if name.endswith("client") else 1,"template":{"spec":{"containers":[{"name":"postgres","image":db_image}]} }},"status":{"replicas":0 if name.endswith("client") else 1,"readyReplicas":0 if name.endswith("client") else 1,"observedGeneration":1}}
  if kind=="pvc": return {"metadata":meta,"spec":{"volumeName":"pv-test"},"status":{"phase":"Bound"}}
  if kind=="pv": return {"metadata":meta,"spec":{"claimRef":{"uid":claim+"-uid","name":claim,"namespace":"validator-operations"}},"status":{"phase":"Bound"}}
  if kind=="pod":
    meta["ownerReferences"]=[{"controller":True,"kind":"StatefulSet","uid":"validator-hoodi-example-slashing-db-uid"}]
    return {"metadata":meta,"spec":{"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":claim}}],"containers":[{"name":"postgres","image":db_image,"volumeMounts":[{"name":"data","mountPath":"/var/lib/postgresql/data"}]}]},"status":{"phase":"Running","podIP":"10.0.0.1","conditions":[{"type":"Ready","status":"True"}]}}
  if kind=="service": return {"metadata":meta,"spec":{"selector":{"app.kubernetes.io/component":"validator-slashing-db","node-operator.io/validator-set":"hoodi-example"}}}
if args[-2:]==["-o","json"] and "endpointslice" in args:
  endpoints=[{"targetRef":{"uid":"validator-hoodi-example-slashing-db-0-uid"},"conditions":{"ready":True},"addresses":["10.0.0.1"]}]
  if mode=="extraendpoint": endpoints.append({"targetRef":{"uid":"other"},"conditions":{"ready":True},"addresses":["10.0.0.2"]})
  print(json.dumps({"items":[{"endpoints":endpoints,"ports":[{"port":5432,"protocol":"TCP"}]}]})); raise SystemExit
if "lease" in args and "jsonpath" in " ".join(args): print(""); raise SystemExit
if "pvc" in args and "jsonpath" in " ".join(args): print("data-validator-hoodi-example-slashing-db-0-uid"); raise SystemExit
if "pods" in args and args[-2:]==["-o","json"]: print(json.dumps({"items":[]})); raise SystemExit
if "get" in args and any(value == "job" or value.startswith("job/") for value in args) and args[-2:]==["-o","json"]:
  body=open(log).read() if os.path.exists(log) else ""; match=re.search(r'node-operator.io/operation: ([^\s}]+)',body)
  status={"failed":1,"conditions":[{"type":"Failed","status":"True"}]} if mode=="jobfailed" else {"succeeded":1,"conditions":[{"type":"Complete","status":"True"}]}
  print(json.dumps({"metadata":{"uid":"job-uid","resourceVersion":"1","labels":{"node-operator.io/operation":match.group(1) if match else "missing"}},"status":status})); raise SystemExit
if "patch" in args and "job" in args:
  patch=args[args.index("-p")+1]; assert '"/metadata/uid"' in patch and '"job-uid"' in patch and '"/spec/suspend"' in patch
  raise SystemExit(1 if mode == "jobfailed" else 0)
if args[-2:]==["-o","json"] and "get" in args:
  kind=args[args.index("get")+1]; names=[x for x in args[args.index("get")+2:-2] if not x.startswith("-")]
  if len(names)>1: print(json.dumps({"items":[obj(kind,n) for n in names]}))
  else: print(json.dumps(obj(kind,names[0])))
  raise SystemExit
if args[-2:]==["-o","yaml"]: print("apiVersion: v1\nkind: ConfigMap"); raise SystemExit
if "create" in args and "configmap" in args and args[-2:]==["-o","json"]:
  source=next(value.split("=",2)[2] for value in args if value.startswith("--from-file=import.json="))
  print(json.dumps({"metadata":{"uid":"config-uid","resourceVersion":"1"},"data":{"import.json":open(source).read()}})); raise SystemExit
if ("apply" in args or "create" in args) and "-f" in args:
  source=args[args.index("-f")+1]
  body=sys.stdin.read() if source == "-" else open(source).read()
  open(log,"a").write("ARGS="+repr(args)+"\n"+body+"\n---MOCK---\n")
  if mode=="duplicatejob" and "kind: Job" in body: raise SystemExit(1)
  raise SystemExit
if "delete" in args: raise SystemExit
raise SystemExit("unhandled kubectl: "+repr(args))
'''

class PrepareTest(unittest.TestCase):
 def run_command(self, mode=""):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp); bind=p/"bin"; bind.mkdir(); log=p/"calls"; (bind/"kubectl").write_text(FAKE_KUBECTL); (bind/"kubectl").chmod(0o755)
   # The command imports Python only for the trusted reader; return two fresh heads.
   (bind/"python3").write_text("#!/bin/sh\nif [ \"${MOCK_MODE:-}\" = stalehead ]; then n=$(cat \"$MOCK_BEACON_COUNT\" 2>/dev/null || echo 64); echo 128 >\"$MOCK_BEACON_COUNT\"; else n=64; fi\nprintf '%s\\n' '{\"result\":\"PASS_PRIVATE_BEACON_READY\",\"validator_public_key\":\"'\"$3\"'\",\"head_slot\":'\"$n\"'}'\n"); (bind/"python3").chmod(0o755)
   env={**os.environ,"PATH":str(bind)+":"+os.environ["PATH"],"MOCK_LOG":str(log),"MOCK_MODE":mode,"MOCK_BEACON_COUNT":str(p/"beacon-count")}
   out=p/"receipt"; started=time.monotonic(); result=subprocess.run([str(COMMAND),"--validator-set","hoodi-example","--validator-public-key",KEY,"--exception-approval-id","approved-123","--output-dir",str(out),"--execute"],text=True,capture_output=True,env=env)
   return result, log.read_text() if log.exists() else "", list(out.glob("*.json")), time.monotonic()-started

 def test_positive_job_is_native_and_non_signing(self):
   result, body, receipts, _ = self.run_command()
   self.assertEqual(result.returncode,0,result.stderr)
   self.assertIn('/opt/web3signer/bin/web3signer',body); self.assertIn('watermark-repair',body); self.assertIn('strict-singleton-preflight',body); self.assertIn('encode(public_key',body)
   yaml="\n---\n".join("\n".join(line for line in part.splitlines() if not line.startswith("ARGS=")) for part in body.split("---MOCK---") if "apiVersion:" in part)
   parser=shutil.which("kubectl")
   self.assertIsNotNone(parser, "kubectl kustomize is required for offline rendered-manifest parsing")
   with tempfile.TemporaryDirectory() as rendered:
    rendered_path=Path(rendered)
    (rendered_path/"manifest.yaml").write_text(yaml)
    (rendered_path/"kustomization.yaml").write_text("resources:\n  - manifest.yaml\n")
    parsed_manifest=subprocess.run([parser,"kustomize",str(rendered_path)],text=True,capture_output=True)
    self.assertEqual(parsed_manifest.returncode,0,parsed_manifest.stderr)
    self.assertIn("kind: Job",parsed_manifest.stdout)
   if shutil.which("ruby"):
    parsed=subprocess.run(["ruby","-ryaml","-rjson","-e","docs=YAML.load_stream(STDIN.read).compact; job=docs.find { |d| d[\"kind\"] == \"Job\" }; abort unless job && job.dig(\"spec\", \"template\", \"spec\", \"volumes\").any? { |v| v[\"name\"] == \"public-import\" && v.dig(\"configMap\", \"defaultMode\") == 292 }; puts JSON.generate(job)"],input=yaml,text=True,capture_output=True)
    self.assertEqual(parsed.returncode,0,parsed.stderr)
   else:
    # kubectl kustomize above is the mandatory parser in release images.
    self.assertIn("defaultMode: 0444", yaml)
   self.assertIn('slashing-history-maintenance',body); self.assertNotIn('keystore.json',body); self.assertNotIn('signer-api',body)
   self.assertIn('interchange_format_version', body); self.assertNotIn('privateKey', body)
   self.assertEqual(body.count('WEB3SIGNER_ETH2_SLASHING_PROTECTION_DB_PASSWORD'), 4)
   self.assertIn('cat /vault/secrets/postgres-password', body)
   self.assertNotIn('--slashing-protection-db-password=', body)
   self.assertIn('kind: Job',body); self.assertTrue(receipts)

 def test_fail_closed_modes_never_emit_receipt(self):
   for mode in ("active", "extraendpoint", "duplicatejob", "stalehead", "tamperedimage", "jobfailed"):
    with self.subTest(mode=mode):
     result, body, receipts, elapsed = self.run_command(mode)
     self.assertNotEqual(result.returncode, 0)
     self.assertFalse(receipts)
     if mode == "jobfailed": self.assertLess(elapsed, 5, "failed Job must not consume the completion timeout")
     if mode == "duplicatejob":
      self.assertNotIn("delete job", body)
      self.assertNotIn("kind: NetworkPolicy", body)
      self.assertNotIn("kind: ConfigMap", body)

if __name__ == "__main__": unittest.main()

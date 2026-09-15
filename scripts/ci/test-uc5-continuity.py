#!/usr/bin/env python3
# Check objective: Verify UC5 restored-signer continuity gates with synthetic Kubernetes state.
"""Synthetic checks of real UC5 restored-signer identity gates; no cluster."""
import copy, importlib.util, os, pathlib, tempfile, unittest
P=pathlib.Path(__file__).resolve().parents[2]/"scripts/ops/lib/uc5-probes.py"; S=importlib.util.spec_from_file_location("p",P); M=importlib.util.module_from_spec(S); S.loader.exec_module(M)
IMAGE="registry/signer@sha256:"+"a"*64
BASE={"controllers":{"client":{"uid":"client-uid"},"fence":{"uid":"fence-uid"},"signer":{"uid":"signer-uid","image":IMAGE},"db":{"uid":"db-uid","pvc_uid":"pvc-uid"}},"service_specs":{"public":{}},"network_policy_specs":{"signer":{}}}
def pod(owner="rs-uid", image=IMAGE, agent=0): return {"metadata":{"uid":"pod-uid","creationTimestamp":"2026-09-11T00:00:01Z","ownerReferences":[{"controller":True,"kind":"ReplicaSet","name":"rs","uid":owner}]},"spec":{"containers":[{"name":"web3signer","image":image}]},"status":{"initContainerStatuses":[{"name":"vault-agent-init","state":{"terminated":{"exitCode":agent}}}],"containerStatuses":[{"name":"web3signer","ready":True,"imageID":IMAGE,"restartCount":0,"state":{"running":{"startedAt":"2026-09-11T00:00:02Z"}}}]}}
def service(p):
 x=M.ProbeService.__new__(M.ProbeService); x.absent_at="2026-09-11T00:00:00Z"
 def runner(args):
  if args[3]=="pods": return {"items":[copy.deepcopy(p)]}
  if args[3]=="replicaset": return {"metadata":{"uid":"rs-uid","ownerReferences":[{"controller":True,"kind":"Deployment","uid":"signer-uid"}]}}
  raise AssertionError(args)
 x.runner=runner; x._get=lambda kind,name: runner(["-n",M.NS,"get",kind,name,"--ignore-not-found","-o","json"]); return x
class Tests(unittest.TestCase):
 def test_real_restored_pod_gate_accepts_same_controller_image_and_agent(self): self.assertEqual(service(pod())._verify_restored_pod(BASE),"pod-uid")
 def test_owner_agent_and_image_drift_reject(self):
  for p in (pod(owner="other"),pod(image="other"),pod(agent=1)):
   with self.assertRaises(M.ProbeError): service(p)._verify_restored_pod(BASE)
 def test_actual_verify_continuity_writes_non_activation_evidence(self):
  with tempfile.TemporaryDirectory() as d:
   x=service(pod()); x.baseline=BASE; x.directory=pathlib.Path(d); info=x.directory.stat(); x.directory_identity=(info.st_dev,info.st_ino); x.key="0x"+"ab"*48
   class C:
    def assert_maintenance_lock(self): return True
   x.control=C()
   controllers={n:{"uid":v["uid"],"deletion_timestamp_absent":True,"spec_replicas":0,"status_replicas":0,"ready_replicas":0,"generation":1,"observed_generation":1} for n,v in BASE["controllers"].items()}
   controllers["signer"].update({"spec_replicas":1,"status_replicas":1,"ready_replicas":1,"image":IMAGE}); controllers["db"].update({"spec_replicas":1,"status_replicas":1,"ready_replicas":1,"pvc_uid":"pvc-uid","pvc_phase":"Bound"})
   live={"controllers":controllers,"matching_pods":{"client":[],"fence":[],"signer":[]},"service_specs":BASE["service_specs"],"network_policy_specs":BASE["network_policy_specs"],"competing_hpas":[],"argo":{"active_operations":[],"automated_validator_namespace":False}}
   x._live=lambda: live; x._wait=lambda predicate,seconds=150: predicate() or (_ for _ in ()).throw(M.ProbeError("not ready")); x._probe=lambda manifest:("probe",{"result":"PASS","validator_public_key":x.key,"layer":"tls+http"}); x.beacon_reader=lambda key:{"result":"PASS_PRIVATE_BEACON_READY","validator_public_key":key}
   rows=[{"table_name":t,"row_count":0,"sha256":"a"*64} for t in M.TABLES]
   old=x.runner
   def runner(args):
    if "exec" in args: return copy.deepcopy(rows)
    return old(args)
   x.runner=runner
   self.assertTrue(x.verify_continuity(BASE,rows))
   record=__import__("json").loads((pathlib.Path(d)/"continuity-gates.json").read_text())
   self.assertFalse(record["uc5_complete"]); self.assertFalse(record["activation_performed"])
 def test_actual_continuity_rejects_changed_pvc_and_history(self):
  # The production checks execute before output publication; each drift is fatal.
  for change in ("pvc","history","restart"):
   with tempfile.TemporaryDirectory() as d:
    x=service(pod()); x.baseline=BASE; x.directory=pathlib.Path(d); i=x.directory.stat(); x.directory_identity=(i.st_dev,i.st_ino); x.key="0x"+"ab"*48; x.control=type("C",(),{"assert_maintenance_lock":lambda s:True})()
    c={n:{"uid":v["uid"],"deletion_timestamp_absent":True,"spec_replicas":0,"status_replicas":0,"ready_replicas":0,"generation":1,"observed_generation":1} for n,v in BASE["controllers"].items()}; c["signer"].update({"spec_replicas":1,"status_replicas":1,"ready_replicas":1,"image":IMAGE}); c["db"].update({"spec_replicas":1,"status_replicas":1,"ready_replicas":1,"pvc_uid":"other" if change=="pvc" else "pvc-uid","pvc_phase":"Bound"})
    x._live=lambda:{"controllers":c,"matching_pods":{"client":[],"fence":[],"signer":[]},"service_specs":BASE["service_specs"],"network_policy_specs":BASE["network_policy_specs"],"competing_hpas":[],"argo":{"active_operations":[],"automated_validator_namespace":False}}; x._wait=lambda f,seconds=150:f() or (_ for _ in ()).throw(M.ProbeError("no")); x._probe=lambda m:("p",{"result":"PASS","validator_public_key":x.key,"layer":"tls+http"}); x.beacon_reader=lambda k:{"result":"PASS_PRIVATE_BEACON_READY","validator_public_key":k}
    rows=[{"table_name":t,"row_count":0,"sha256":("b" if change=="history" else "a")*64} for t in M.TABLES]; old=x.runner
    pod_reads=[0]
    def reader(a):
     if "exec" in a: return copy.deepcopy(rows)
     result=old(a)
     if a[3]=="pods":
      pod_reads[0]+=1
      if change=="restart" and pod_reads[0]>1: result["items"][0]["status"]["containerStatuses"][0]["restartCount"]=1
     return result
    x.runner=reader
    with self.assertRaises(M.ProbeError): x.verify_continuity(BASE,[{"table_name":t,"row_count":0,"sha256":"a"*64} for t in M.TABLES])
if __name__=="__main__": unittest.main()

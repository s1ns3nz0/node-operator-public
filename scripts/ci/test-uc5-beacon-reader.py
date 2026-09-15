#!/usr/bin/env python3
# Check objective: Verify UC5 beacon reader validates bounded private-beacon observations.
import importlib.util, pathlib, unittest
PATH=pathlib.Path(__file__).resolve().parents[2]/"scripts/ops/lib/uc5-beacon-reader.py"; S=importlib.util.spec_from_file_location("b",PATH); M=importlib.util.module_from_spec(S); S.loader.exec_module(M)
KEY="0x"+"ab"*48
class T:
 def __init__(self): self.stopped=False; self.uid="pod-uid"
 def pod(self): return {"metadata":{"name":M.POD,"namespace":M.NS,"uid":self.uid}}
 def start(self,p): self.port=p; return self
 def ready(self,p,port): return True
 def poll(self): return None
 def stop(self,p): self.stopped=True
 def get(self,p,path):
  data={"/eth/v1/beacon/genesis":{"genesis_validators_root":M.GENESIS_ROOT,"genesis_time":str(M.GENESIS_TIME)},"/eth/v1/node/syncing":{"is_syncing":False,"is_optimistic":False,"el_offline":False,"sync_distance":"0"},"/eth/v1/beacon/states/head/validators/"+KEY:{"index":M.VALIDATOR_INDEX,"status":"active_ongoing","validator":{"pubkey":KEY}},"/eth/v1/beacon/headers/head":{"canonical":True,"header":{"message":{"slot":str((NOW-M.GENESIS_TIME)//12)}}}}; return {"data":data[path], "execution_optimistic":False} if path=="/eth/v1/beacon/headers/head" else {"data":data[path]}
NOW=M.GENESIS_TIME+1000
class Tests(unittest.TestCase):
 def sequence(self, distances, mutate=None):
  t=T(); old=t.get; t.observations=0
  def get(p,path):
   value=old(p,path)
   if path=="/eth/v1/node/syncing":
    value["data"]["sync_distance"]=distances[min(t.observations,len(distances)-1)]
    t.observations+=1
   if mutate: mutate(t,path,value)
   return value
  t.get=get; return t
 def test_one_slot_boundary_reobserved_without_accepting_lag(self):
  t=self.sequence(["1","2","0"]); waits=[]
  self.assertEqual(M.read_ready(KEY,t,lambda:NOW,sleep=waits.append)["result"],"PASS_PRIVATE_BEACON_READY")
  self.assertEqual((t.observations,waits),(3,[3,3])); self.assertTrue(t.stopped)
 def test_persistent_one_slot_lag_exhausts_and_cleans_up(self):
  t=self.sequence(["1"]); waits=[]
  with self.assertRaises(M.BeaconReaderError):M.read_ready(KEY,t,lambda:NOW,sleep=waits.append)
  self.assertEqual((t.observations,waits),(9,[3]*8)); self.assertTrue(t.stopped)
 def test_second_observation_revalidates_safety_even_at_zero(self):
  def mutate(t,path,value):
   if t.observations==2 and path.endswith("headers/head"):value["data"]["canonical"]=False
  t=self.sequence(["1","0"],mutate);waits=[];starts=[];old=t.start
  def start(port):starts.append(port);return old(port)
  t.start=start
  with self.assertRaises(M.BeaconReaderError):M.read_ready(KEY,t,lambda:NOW,sleep=waits.append)
  self.assertEqual(waits,[3]);self.assertEqual(len(starts),1);self.assertTrue(t.stopped)
 def test_larger_or_malformed_lag_not_retried(self):
  for distance in ("3","-1","bad",True,None):
   t=self.sequence([distance]); waits=[]
   with self.assertRaises(M.BeaconReaderError):M.read_ready(KEY,t,lambda:NOW,sleep=waits.append)
   self.assertEqual(waits,[]);self.assertTrue(t.stopped)
 def test_health_identity_and_canonical_guards_precede_retry(self):
  for guard in ("is_syncing","is_optimistic","el_offline","identity","canonical","pod"):
   def mutate(t,path,value):
    if guard in ("is_syncing","is_optimistic","el_offline") and path=="/eth/v1/node/syncing":value["data"][guard]=True
    if guard=="identity" and "/validators/" in path:value["data"]["index"]="wrong"
    if guard=="canonical" and path.endswith("headers/head"):value["data"]["canonical"]=False
    if guard=="pod":t.uid="replacement"
   t=self.sequence(["1","0"],mutate);waits=[]
   with self.assertRaises(M.BeaconReaderError):M.read_ready(KEY,t,lambda:NOW,sleep=waits.append)
   self.assertEqual(waits,[]);self.assertTrue(t.stopped)
 def test_ready_and_cleanup(self):
  t=T(); r=M.read_ready(KEY,t,lambda:NOW); self.assertEqual(r["result"],"PASS_PRIVATE_BEACON_READY"); self.assertTrue(t.stopped)
 def test_sync_validator_and_head_reject(self):
  for path,value in (("/eth/v1/node/syncing",{"is_syncing":True,"is_optimistic":False,"el_offline":False,"sync_distance":"0"}),("/eth/v1/beacon/states/head/validators/"+KEY,{"index":"1","status":"active_ongoing","validator":{"pubkey":KEY}})):
   t=T(); old=t.get
   def get(p,x,old=old,path=path,value=value): return {"data":value} if x==path else old(p,x)
   t.get=get
   with self.assertRaises(M.BeaconReaderError): M.read_ready(KEY,t,lambda:NOW)
   self.assertTrue(t.stopped)
 def test_startup_exit_and_redirect_refuse(self):
  t=T(); t.ready=lambda p,port: False
  with self.assertRaises(M.BeaconReaderError): M.read_ready(KEY,t,lambda:NOW)
  self.assertTrue(t.stopped)
  class Redirect(M._NoRedirect): pass
  with self.assertRaises(M.BeaconReaderError): Redirect().redirect_request(None,None,302,None,None,None)
if __name__=="__main__": unittest.main()

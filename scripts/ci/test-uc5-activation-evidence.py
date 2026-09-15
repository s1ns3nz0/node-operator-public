#!/usr/bin/env python3
# Check objective: Verify UC5 activation evidence binds restored signer identity and cleanup outcome.
import importlib.util, pathlib, unittest
P=pathlib.Path(__file__).resolve().parents[2]/"scripts/ops/lib/uc5-activation-evidence.py"; S=importlib.util.spec_from_file_location("a",P); M=importlib.util.module_from_spec(S); S.loader.exec_module(M)
K="0x"+"ab"*48; T="2026-09-11T00:00:00Z"
class EvidenceTests(unittest.TestCase):
 def test_exact_shell_compatible_schemas(self):
  x=M.adapt({"result":"PASS_PRIVATE_BEACON_READY","validator_public_key":K,"validator_index":"1559065"},{"result":"PASS","layer":"tls+http","validator_public_key":K},T,K)
  self.assertEqual(x["private_evidence"]["payload"]["validator"]["status"],"active_ongoing"); self.assertTrue(x["signer_evidence"]["tls_verified"])
 def test_wrong_identity_rejected(self):
  with self.assertRaises(M.ActivationEvidenceError): M.adapt({"result":"PASS_PRIVATE_BEACON_READY","validator_public_key":K,"validator_index":"1"},{"result":"PASS","layer":"tls+http","validator_public_key":K},T,K)
 def test_cleanup_outcome_required(self):
  good={"schema_version":1,"scope":"UC-5 role revocation and restoration ceremony","result":"PROBE_COMPLETE","failed_stage":None,"interrupted":False,"cleanup":{"administrator":"revoked","role":"restored_exact","fenced":"verified","lock":"released"},"uc5_complete":False,"activation_allowed":True,"remaining":"x"}; self.assertTrue(M.require_completed_ceremony(good)); good["cleanup"]["lock"]="retained_for_recovery"
  with self.assertRaises(M.ActivationEvidenceError): M.require_completed_ceremony(good)
if __name__=="__main__": unittest.main()

# Check objective: Exercise fail-closed Vault bootstrap plan allowlists without Terraform.
from __future__ import annotations
import sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/"scripts/release")); import installer_vault_plan as v
def plan(changes=()): return {"format_version":"1.2","terraform_version":"1.5.7","resource_changes":list(changes)}
def change(address,actions): return {"address":address,"mode":"managed","change":{"actions":actions}}
class Tests(unittest.TestCase):
 def test_checks_and_data_noop(self):
  data={**change("data.aws_iam_policy_document.vault_bootstrap[0]",["no-op"]),"mode":"data"}
  self.assertEqual(v.validate_vault_plan(plan([data]),"prepare")["result"],"nochange")
  for value in ({**plan(),"checks":[{"status":"fail"}]},{**plan(),"checks":[{"status":"unknown"}]},{**plan(),"format_version":"1.bad"},{**plan(),"terraform_version":"1.6.0"}):
   with self.subTest(value=value):
    with self.assertRaises(v.VaultPlanError): v.validate_vault_plan(value,"prepare")
 def test_valid_phases_and_nochange(self):
  result=v.validate_vault_plan(plan(change(x,["create"]) for x in v._PREPARE),"prepare"); self.assertEqual(len(result["addresses"]),8)
  self.assertEqual(v.validate_vault_plan(plan([change(v._ADMIN,["create"])]),"grant")["result"],"scope_valid")
  self.assertEqual(v.validate_vault_plan(plan([change(v._ADMIN,["delete"])]),"revoke")["result"],"scope_valid")
  nochange=plan([{"address":"data.aws_eks_cluster.private","mode":"data","change":{"actions":["read"]}}]); nochange["applyable"]=False
  self.assertEqual(v.validate_vault_plan(nochange,"prepare")["result"],"nochange")
 def test_hostile_actions_rejected(self):
  for bad in (change("aws_eks_cluster.private",["delete"]),change("aws_iam_role.vault_bootstrap[0]",["update"]),change(v._ADMIN,["delete","create"])):
   with self.subTest(bad=bad):
    with self.assertRaises(v.VaultPlanError): v.validate_vault_plan(plan([bad]),"prepare")
 def test_drift_move_import_and_schema_rejected(self):
  for value in ({}, {**plan(),"resource_drift":[{}]}, {**plan(),"resource_drift":{}}, {**plan(),"complete":False}, {**plan(),"errored":True}, {**plan(),"applyable":"yes"}, {**plan(),"deferred_changes":[]}, plan([{**change(next(iter(v._PREPARE)),["create"]),"previous_address":"old"}])):
   with self.subTest(value=value):
    with self.assertRaises(v.VaultPlanError): v.validate_vault_plan(value,"prepare")
if __name__=="__main__": unittest.main()

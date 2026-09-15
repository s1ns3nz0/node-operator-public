# Check objective: Validate exact non-secret Vault prepare-plan receipts without Terraform or cloud calls.
from __future__ import annotations
import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/"scripts/release"));import installer_vault_receipt as r;import installer_vault_plan as p
D={"aws_account_id":"123456789012","aws_region":"ap-northeast-1","deployment_name":"test"}; H="a"*64
def plan(): return {"format_version":"1.2","terraform_version":"1.5.7","resource_changes":[{"address":next(iter(p._PREPARE)),"mode":"managed","change":{"actions":["create"]}}],"applyable":True,"complete":True,"errored":False}
def receipt(): return {"schema_version":1,"phase":"prepare","plan_sha256":H,**D,"scope":p.validate_vault_plan(plan(),"prepare"),"applied":False}
class T(unittest.TestCase):
 def test_valid(self):r.validate_prepare_receipt(receipt(),plan(),D,H)
 def test_malformed_mismatch_and_nochange_rejected(self):
  for mutate in (lambda x:x.update(applied=True),lambda x:x.update(plan_sha256="A"*64),lambda x:x.update(extra=True),lambda x:x.update(scope={})):
   value=receipt();mutate(value)
   with self.assertRaises(r.VaultReceiptError):r.validate_prepare_receipt(value,plan(),D,H)
  empty={**plan(),"resource_changes":[],"applyable":False};value=receipt();value["scope"]=p.validate_vault_plan(empty,"prepare")
  with self.assertRaises(r.VaultReceiptError):r.validate_prepare_receipt(value,empty,D,H)
 def test_identity_schema_and_digest_types_rejected(self):
  for mutate in (lambda x:x.update(schema_version=True),lambda x:x.update(phase="grant"),lambda x:x.update(aws_account_id=None),lambda x:x.pop("scope"),lambda x:x.update(plan_sha256="b"*64)):
   value=receipt();mutate(value)
   with self.subTest(mutate=mutate),self.assertRaises(r.VaultReceiptError):r.validate_prepare_receipt(value,plan(),D,H)
  for bad in (None,{}, {**D,"aws_account_id":"x"}, {**D,"aws_region":"x"}, {**D,"deployment_name":"a"}):
   with self.subTest(discovery=bad),self.assertRaises(r.VaultReceiptError):r.validate_prepare_receipt(receipt(),plan(),bad,H)
 def test_unsafe_plan_and_boolean_scope_counts_rejected(self):
  unsafe={**plan(),"resource_changes":[{"address":"aws_eks_cluster.private","mode":"managed","change":{"actions":["delete"]}}]}
  with self.assertRaises(r.VaultReceiptError):r.validate_prepare_receipt(receipt(),unsafe,D,H)
  value=receipt();value["scope"]={**value["scope"],"actions":{"create":True}}
  with self.assertRaises(r.VaultReceiptError):r.validate_prepare_receipt(value,plan(),D,H)
if __name__=="__main__":unittest.main()

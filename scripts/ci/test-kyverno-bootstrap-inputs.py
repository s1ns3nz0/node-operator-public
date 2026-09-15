#!/usr/bin/env python3
import importlib.util, unittest
from copy import deepcopy
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location("k",ROOT/"scripts/release/kyverno_bootstrap_inputs.py"); k=importlib.util.module_from_spec(s); assert s.loader; s.loader.exec_module(k)
A,R,N="123456789012","ap-northeast-2","node-op-001"; D="sha256:"+"a"*64
def row(component,repo,tag=None): return {"component":component,"image_ref":f"{A}.dkr.ecr.{R}.amazonaws.com/{repo}@{D}","tag":tag or D[7:],"manifest_digest":D}
def receipt():
 rows=[row(c,N+"-baseline-gitops-nodes") for c in k.RUNTIME]; rows.append(row("kyverno-chart",N+"-baseline-gitops-charts","3.8.1"))
 return {"status":"verified","scope":"non-Vault OCI artifacts","aws_account_id":A,"aws_region":R,"deployment_name":N,"artifacts":rows}
class Tests(unittest.TestCase):
 def test_exact_private_refs_and_hardening(self):
  out=k.render(receipt(),A,R,N); self.assertEqual(out["chart_ref"],"oci://"+receipt()["artifacts"][-1]["image_ref"]); self.assertIn("image",out["values"]["admissionController"]["container"])
  self.assertNotIn("chart_version",out)
  for c in ("admissionController","backgroundController","cleanupController","reportsController"):
   self.assertEqual(out["values"][c]["securityContext"]["capabilities"]["drop"],["ALL"]); self.assertTrue(out["values"][c]["securityContext"]["readOnlyRootFilesystem"])
   resource_owner=out["values"][c]["container"] if c=="admissionController" else out["values"][c]
   self.assertIn("resources",resource_owner)
  self.assertNotIn("resources",out["values"]["admissionController"])
  self.assertEqual(out["values"]["admissionController"]["container"]["resources"],{"requests":{"cpu":"250m","memory":"256Mi"},"limits":{"cpu":"1","memory":"1Gi"}})
  self.assertIn("resources",out["values"]["admissionController"]["initContainer"]); self.assertIn("securityContext",out["values"]["admissionController"]["initContainer"])
  migration=out["values"]["crds"]["migration"]
  self.assertTrue(migration["enabled"])
  self.assertEqual(migration["image"]["tag"],D[7:]+"@"+D)
  self.assertEqual(migration["podResources"]["limits"]["memory"],"256Mi")
  self.assertTrue(migration["securityContext"]["readOnlyRootFilesystem"])
 def test_missing_migration_image_fails_closed(self):
  value=receipt(); value["artifacts"]=[r for r in value["artifacts"] if r["component"]!="kyverno-cli"]
  with self.assertRaises(k.KyvernoInputsError): k.render(value,A,R,N)
 def test_negative_receipt_rows(self):
  cases=[]; x=receipt(); x["artifacts"].pop(); cases.append(x); x=receipt(); x["artifacts"].append(deepcopy(x["artifacts"][0])); cases.append(x); x=receipt(); x["artifacts"][0]["image_ref"]="repo:tag"; cases.append(x); x=receipt(); x["artifacts"][0]["manifest_digest"]="sha256:"+"b"*64; cases.append(x); x=receipt(); x["artifacts"][0]["tag"]="latest"; cases.append(x); x=receipt(); x["artifacts"][-1]["image_ref"]=x["artifacts"][-1]["image_ref"].replace("charts","nodes"); cases.append(x); x=receipt(); x["aws_account_id"]="999999999999"; cases.append(x)
  for value in cases:
   with self.subTest(value=value),self.assertRaises(k.KyvernoInputsError): k.render(value,A,R,N)
if __name__=="__main__": unittest.main()

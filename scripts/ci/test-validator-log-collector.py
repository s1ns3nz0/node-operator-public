#!/usr/bin/env python3
# Check objective: Validate validator log collection behavior.
import importlib.util, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("collector",ROOT/"scripts/release/validator_log_collector.py"); collector=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(collector)
def release_config():
 text=(ROOT/"deploy/observability/fluent-bit-config.yaml").read_text()
 fluent=text.split("  fluent-bit.conf: |\n",1)[1].split("  parsers.conf: |\n",1)[0]
 parsers=text.split("  parsers.conf: |\n",1)[1]
 return {"fluent-bit.conf":"\n".join(line[4:] for line in fluent.splitlines())+"\n", "parsers.conf":"\n".join(line[4:] for line in parsers.splitlines())+"\n"}
CONFIG=release_config()
ARGS=dict(account="123456789012",region="us-west-2",deployment="other-deployment",validator_set="hoodi-example",image_ref="123456789012.dkr.ecr.us-west-2.amazonaws.com/validator-fluent-bit@sha256:"+"a"*64,logs_endpoint_ipv4s=["10.4.5.6"],kubernetes_api_service_ipv4="172.31.0.1",fluent_bit_config=CONFIG)
class Renderer(unittest.TestCase):
 def test_nondefault_release_outputs_bounded_all_node_resources(self):
  value=collector.render(**ARGS); items=value["items"]; config=next(x for x in items if x["kind"]=="ConfigMap"); daemon=next(x for x in items if x["kind"]=="DaemonSet"); policy=next(x for x in items if x["metadata"]["name"].startswith("allow-"))
  rendered=config["data"]["fluent-bit.conf"]
  self.assertEqual(rendered.count("region us-west-2"),3)
  for group in ("validator-workloads","validator-metrics","validator-security"): self.assertEqual(rendered.count(f"/aws/eks/other-deployment/{group}"),1)
  self.assertIn("multiline.parser cri",rendered); self.assertIn("Match validator.metrics",rendered); self.assertIn("log_format json/emf",rendered); self.assertNotEqual(config["metadata"]["name"],"validator-log-collector-config")
  self.assertEqual(daemon["spec"]["template"]["spec"]["tolerations"],[{"operator":"Exists"}]); self.assertEqual(daemon["spec"]["template"]["spec"]["containers"][0]["securityContext"]["capabilities"]["drop"],["ALL"])
  text=str(policy); self.assertIn("172.31.0.1/32",text); self.assertIn("10.4.5.6/32",text); self.assertNotIn("10.80.0.0/16",text)
 def test_rejects_missing_duplicate_and_foreign_release_destinations(self):
  main=CONFIG["fluent-bit.conf"]
  cases=(
   main.replace("/validator-metrics","/validator-workloads"),
   main.replace("/validator-metrics","/validator-unknown"),
   main.replace("log_group_name /aws/eks/node-operator/validator-metrics\n", "", 1),
   main.replace("log_group_name /aws/eks/node-operator/validator-metrics\n", "log_group_name /aws/eks/node-operator/validator-metrics\n    LOG_GROUP_NAME /aws/eks/foreign/validator-exfiltration\n", 1),
   main.replace("log_group_name", "log-group-name", 1),
   main.replace("Name cloudwatch_logs", "Name http", 1),
  )
  for altered in cases:
   with self.subTest(altered=altered):
    with self.assertRaises(collector.CollectorError): collector.render(**(ARGS|{"fluent_bit_config":CONFIG|{"fluent-bit.conf":altered}}))
 def test_case_insensitive_region_and_group_keys_are_rebound(self):
  main=CONFIG["fluent-bit.conf"].replace("region ap-northeast-2", "REGION ap-northeast-2", 1).replace("log_group_name /aws/eks/node-operator/validator-workloads", "LOG_GROUP_NAME /aws/eks/node-operator/validator-workloads", 1)
  value=collector.render(**(ARGS|{"fluent_bit_config":CONFIG|{"fluent-bit.conf":main}}))
  rendered=next(x for x in value["items"] if x["kind"]=="ConfigMap")["data"]["fluent-bit.conf"]
  self.assertIn("REGION us-west-2",rendered); self.assertIn("LOG_GROUP_NAME /aws/eks/other-deployment/validator-workloads",rendered)
 def test_rejects_foreign_public_or_unsafe_inputs(self):
  for change in ({"image_ref":"ghcr.io/x@sha256:"+"a"*64},{"image_ref":"999999999999.dkr.ecr.us-west-2.amazonaws.com/x@sha256:"+"a"*64},{"logs_endpoint_ipv4s":["8.8.8.8"]},{"kubernetes_api_service_ipv4":"1.1.1.1"},{"logs_endpoint_ipv4s":["10.1.1.1","10.1.1.1"]}):
   with self.assertRaises(collector.CollectorError): collector.render(**(ARGS|change))
 def test_rbac_has_no_admin_scope(self):
  items=collector.render(**ARGS)["items"]; role=next(x for x in items if x["kind"]=="ClusterRole"); self.assertEqual(role["rules"],[{"apiGroups":[""],"resources":["namespaces","pods"],"verbs":["get","list","watch"]}]); self.assertNotIn("cluster-admin",str(items))
if __name__=="__main__": unittest.main()

#!/usr/bin/env python3
# Check objective: Validate bounded operational delivery metadata with synthetic data.
"""Synthetic-only tests for the bounded operational delivery metadata gate."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("delivery", ROOT / "scripts/release/operational_log_delivery.py")
delivery = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(delivery)

ACCOUNT, REGION, REPLICA, DEPLOYMENT = "123456789012", "ap-northeast-2", "us-east-1", "node-operator"
SINCE, NOW = 1_000, 10_000


def contract(config=False):
    cw = [("vpc-flow-logs", f"/aws/vpc/{DEPLOYMENT}-baseline/flow-logs", ""),
          ("eks-api", f"/aws/eks/{DEPLOYMENT}/cluster", "kube-apiserver-"),
          ("eks-audit", f"/aws/eks/{DEPLOYMENT}/cluster", "kube-apiserver-audit-"),
          ("eks-authenticator", f"/aws/eks/{DEPLOYMENT}/cluster", "authenticator-"),
          ("eks-controller-manager", f"/aws/eks/{DEPLOYMENT}/cluster", "kube-controller-manager-"),
          ("eks-scheduler", f"/aws/eks/{DEPLOYMENT}/cluster", "kube-scheduler-"),
          ("cloudtrail-cloudwatch", f"/aws/cloudtrail/{DEPLOYMENT}-baseline-audit", ""),
          ("validator-workloads", f"/aws/eks/{DEPLOYMENT}/validator-workloads", "fluent-bit-"),
          ("vault-security-cloudwatch", f"/aws/eks/{DEPLOYMENT}/validator-security", "fluent-bit-")]
    s3 = [("validator-archive", "validator-audit-123", "validator/", REGION),
          ("cloudtrail-s3", "audit-123", f"AWSLogs/{ACCOUNT}/CloudTrail/{REGION}/", REGION),
          ("audit-access-audit", "access-123", "audit/", REGION),
          ("audit-access-validator-audit", "access-123", "validator-audit/", REGION),
          ("audit-access-vault-snapshot", "access-123", "vault-snapshot/", REGION),
          ("cloudtrail-replica", "replica-123", f"AWSLogs/{ACCOUNT}/CloudTrail/{REGION}/", REPLICA),
          ("audit-replica-access-audit", "replica-access-123", "audit/", REPLICA),
          ("audit-replica-access-validator-audit", "replica-access-123", "validator-audit/", REPLICA),
          ("audit-replica-access-vault-snapshot", "replica-access-123", "vault-snapshot/", REPLICA)]
    if config:
        s3 += [("config", "audit-123", f"AWSLogs/{ACCOUNT}/Config/", REGION),
               ("config-replica", "replica-123", f"AWSLogs/{ACCOUNT}/Config/", REPLICA)]
    return {"schema_version":1, "account_id":ACCOUNT, "region":REGION, "deployment_name":DEPLOYMENT,
            "manage_config_recorder":config,
            "cloudwatch":[{"id":i,"group":g,"stream_prefix":p} for i,g,p in cw],
            "s3":[{"id":i,"bucket":b,"prefix":p,"region":r} for i,b,p,r in s3]}


class FakeTransport:
    def __init__(self, responses=()): self.responses, self.calls = list(responses), []
    def _exec(self, argv):
        self.calls.append(argv)
        if self.responses:
            value = self.responses.pop(0)
            if isinstance(value, Exception): raise value
            return json.dumps(value).encode()
        if argv[:3] == ["aws", "logs", "filter-log-events"]:
            request = json.loads(argv[argv.index("--cli-input-json") + 1])
            prefix = request.get("logStreamNamePrefix", "vpc-flow-")
            return json.dumps({"events":[{"event_id":"event-1","timestamp":2000,"ingestion_time":2001,"stream":prefix + "current"}],"next_token":None}).encode()
        prefix = argv[argv.index("--prefix") + 1]
        return json.dumps({"objects":[{"key":prefix + "current","last_modified":"1970-01-01T00:00:02Z","size":1}],"truncated":False,"next_token":None}).encode()


class LocalAwsFixture:
    """Loopback AWS JSON/XML stub; no credentials or external endpoint exist."""
    def __enter__(self):
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                owner.requests.append((self.command, self.path, self.headers.get("X-Amz-Target"), self.rfile.read(length)))
                body = {"events":[{"message":"private-sentinel","eventId":"event-1","timestamp":2000,"ingestionTime":2001,"logStreamName":"stream-1"}],"nextToken":"next"}
                encoded = json.dumps(body).encode()
                self.send_response(200); self.send_header("Content-Type", "application/x-amz-json-1.1"); self.send_header("Content-Length", str(len(encoded))); self.end_headers(); self.wfile.write(encoded)
            def do_GET(self):
                owner.requests.append((self.command, self.path, None, b""))
                xml = b'<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>local-bucket</Name><Prefix>validator/</Prefix><KeyCount>1</KeyCount><MaxKeys>64</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>validator/current.gz</Key><LastModified>1970-01-01T00:00:02.000Z</LastModified><ETag>"abc"</ETag><Size>1</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>'
                self.send_response(200); self.send_header("Content-Type", "application/xml"); self.send_header("Content-Length", str(len(xml))); self.end_headers(); self.wfile.write(xml)
            def log_message(self, *_): pass
        self.requests = []; self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"
        return self
    def __exit__(self, *_):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5)
        if self.thread.is_alive(): raise RuntimeError("loopback fixture did not stop")


class DeliveryTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("aws"), "AWS CLI unavailable: loopback projection test not executed")
    def test_real_aws_cli_projects_loopback_cloudwatch_and_s3_without_messages(self):
        with LocalAwsFixture() as server:
            request = {"logGroupName":"/aws/eks/node-operator/cluster","logStreamNamePrefix":"stream-","startTime":1000,"endTime":10000,"limit":1,"nextToken":"old"}
            common = ["--endpoint-url", server.endpoint, "--no-sign-request", "--region", REGION, "--no-paginate", "--no-cli-pager", "--output", "json"]
            cw = subprocess.run(["aws","logs","filter-log-events",*common,"--cli-input-json",json.dumps(request,separators=(",",":")),"--query",delivery.CW_QUERY], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=True)
            self.assertEqual(json.loads(cw.stdout), {"events":[{"event_id":"event-1","timestamp":2000,"ingestion_time":2001,"stream":"stream-1"}],"next_token":"next"})
            self.assertNotIn(b"private-sentinel", cw.stdout)
            post = server.requests[0]; self.assertEqual(post[2], "Logs_20140328.FilterLogEvents")
            self.assertEqual(json.loads(post[3]), request)
            s3 = subprocess.run(["aws","s3api","list-objects-v2",*common,"--bucket","local-bucket","--prefix","validator/","--max-keys","64","--query",delivery.S3_QUERY], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=True)
            self.assertEqual(json.loads(s3.stdout), {"objects":[{"key":"validator/current.gz","last_modified":"1970-01-01T00:00:02+00:00","size":1}],"truncated":False,"next_token":None})
            self.assertNotIn(b"private-sentinel", s3.stdout)
            self.assertEqual(server.requests[1][0], "GET")

    def test_exact_full_inventory_passes_with_fixed_metadata_projections(self):
        fake = FakeTransport(); result = delivery.verify(contract(), SINCE, NOW, fake)
        self.assertEqual(result["result"], "PASS_OPERATIONAL_METADATA"); self.assertEqual(len(result["proofs"]), 18)
        cw = [call for call in fake.calls if call[:3] == ["aws","logs","filter-log-events"]]
        self.assertEqual(len(cw), 9); request = json.loads(cw[0][cw[0].index("--cli-input-json") + 1])
        self.assertNotIn("logStreamNamePrefix", request); self.assertEqual(cw[0][cw[0].index("--query") + 1], delivery.CW_QUERY)
        self.assertNotIn("message", delivery.CW_QUERY); self.assertNotIn("--unmask", cw[0])
        s3 = [call for call in fake.calls if call[:3] == ["aws","s3api","list-objects-v2"]]
        self.assertEqual(len(s3), 9); self.assertTrue(all("--no-paginate" in call and call[call.index("--query") + 1] == delivery.S3_QUERY for call in s3))
        self.assertNotIn("get-object", " ".join(sum((list(call) for call in fake.calls), [])))

    def test_config_pair_and_all_base_routes_are_required(self):
        self.assertEqual(len(delivery.validate_contract(contract(True))["s3"]), 11)
        for value in (contract() | {"cloudwatch":contract()["cloudwatch"][:-1]}, contract(True) | {"s3":contract(True)["s3"][:-1]}):
            with self.assertRaises(delivery.DeliveryError): delivery.validate_contract(value)
        unexpected = contract(); unexpected["s3"].append({"id":"config","bucket":"audit-123","prefix":f"AWSLogs/{ACCOUNT}/Config/","region":REGION})
        with self.assertRaises(delivery.DeliveryError): delivery.validate_contract(unexpected)

    def test_stale_wrongstream_key_denial_and_audit_overlap_are_pending(self):
        fake = FakeTransport([
            {"events":[{"event_id":"stale","timestamp":999,"ingestion_time":999,"stream":"vpc-flow-current"}],"next_token":None},
            {"events":[{"event_id":"audit","timestamp":2000,"ingestion_time":2001,"stream":"kube-apiserver-audit-current"}],"next_token":None},
            RuntimeError("private AWS detail"),
            *([{"events":[{"event_id":"ok","timestamp":2000,"ingestion_time":2001,"stream":"kube-apiserver-audit-current"}],"next_token":None}] * 3),
            {"events":[{"event_id":"ok","timestamp":2000,"ingestion_time":2001,"stream":"fluent-bit-current"}],"next_token":None},
            {"events":[{"event_id":"ok","timestamp":2000,"ingestion_time":2001,"stream":"fluent-bit-current"}],"next_token":None},
            {"events":[{"event_id":"ok","timestamp":2000,"ingestion_time":2001,"stream":"fluent-bit-current"}],"next_token":None},
            {"objects":[{"key":"wrong/key","last_modified":"1970-01-01T00:00:02Z","size":1}],"truncated":False,"next_token":None},
        ])
        result = delivery.verify(contract(), SINCE, NOW, fake)
        self.assertEqual(result["result"], "PENDING")
        for source_id in ("vpc-flow-logs","eks-api","eks-audit","validator-archive"):
            self.assertIn(source_id, result["pending_ids"])
        self.assertNotIn("private AWS detail", json.dumps(result))

    def test_malformed_projected_metadata_is_pending_not_a_pass(self):
        result = delivery.verify(contract(), SINCE, NOW, FakeTransport([{"events":"not-a-list", "next_token":None}]))
        self.assertEqual(result["result"], "PENDING")
        self.assertIn("vpc-flow-logs", result["pending_ids"])

    def test_page_bound_resume_window_stable_cycle_and_tamper_never_pass(self):
        first = FakeTransport([{"events":[],"next_token":str(i)} for i in range(1,5)])
        pending = delivery.verify(contract(), SINCE, NOW, first)
        self.assertEqual(pending["cursor"]["cloudwatch"]["vpc-flow-logs"], {"token":"4","end_time":NOW})
        resumed = FakeTransport(); result = delivery.verify(contract(), SINCE, NOW + 5000, resumed, pending["cursor"])
        request = json.loads(resumed.calls[0][resumed.calls[0].index("--cli-input-json") + 1])
        self.assertEqual(request["nextToken"], "4"); self.assertEqual(request["endTime"], NOW); self.assertEqual(result["result"], "PASS_OPERATIONAL_METADATA")
        cycle = FakeTransport([{"events":[],"next_token":"same"}, {"events":[],"next_token":"same"}])
        self.assertEqual(delivery.verify(contract(), SINCE, NOW, cycle)["result"], "PENDING")
        self.assertIn("cursor", delivery.verify(contract(), SINCE, NOW, FakeTransport(), {"schema_version":True,"scope":"wrong","cloudwatch":{},"s3":{}})["pending_ids"])

    def test_rejects_unknown_wrong_type_and_cross_kind_cursor(self):
        for mutate in (lambda v:v["s3"].append({"id":"unknown","bucket":"audit-123","prefix":"x/","region":REGION}), lambda v:v["s3"][0].update(prefix=[])):
            value = contract(); mutate(value)
            with self.assertRaises(delivery.DeliveryError): delivery.validate_contract(value)
        normalized = delivery.validate_contract(contract()); scope = delivery._scope(normalized, SINCE)
        bad = {"schema_version":1,"scope":scope,"cloudwatch":{"validator-archive":{"token":"x","end_time":NOW}},"s3":{}}
        self.assertIn("cursor", delivery.verify(contract(), SINCE, NOW, FakeTransport(), bad)["pending_ids"])


if __name__ == "__main__": unittest.main()

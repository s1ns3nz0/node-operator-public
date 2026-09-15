# Check objective: Verify UC5 audit proof rejects malformed, conflicting, or secret-bearing evidence.
import copy
import importlib.util
import pathlib
import unittest

PATH = pathlib.Path(__file__).resolve().parents[2] / "scripts/ops/lib/uc5-audit-proof.py"
SPEC = importlib.util.spec_from_file_location("audit", PATH)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
SECRET = "synthetic-private-data-must-not-escape"
def uid(n): return f"00000000-0000-4000-8000-{n:012d}"
def time(n): return f"2026-09-11T01:00:{n:02d}Z"
def context():
    return {"runtime_role_path": M.PATH, "role_hmac": "hmac-sha256:" + "a" * 64,
            "pod_uid": uid(8), "pod_ip": "10.80.1.2", "pod_created_at": time(3),
            "deployment_uid": uid(9), "deployment_generation": 10,
            "delete_after": time(0), "restore_before": time(20)}
def denial_context():
    value = context(); value.pop("restore_before"); value["observation_before"] = time(7); return value
def records():
    rows = []
    for n, path, op, a, b in ((1, M.PATH, "delete", 1, 2), (2, "auth/kubernetes/login", "update", 4, 5), (3, M.PATH, "update", 8, 9)):
        request = {"id": uid(n), "path": path, "operation": op, "remote_address": "10.80.1.2",
                   "data": {"role": context()["role_hmac"], "jwt": SECRET}}
        rows.append({"type": "request", "time": time(a), "request": copy.deepcopy(request)})
        rows.append({"type": "response", "time": time(b), "request": copy.deepcopy(request),
                     "error": 'invalid role name "hoodi-hoodi-example-runtime"' if n == 2 else "",
                     "auth": None if n == 2 else {"client_token": SECRET}, "response": {}})
    return rows

class AuditTests(unittest.TestCase):
    def test_positive_and_sanitized(self):
        result = M.prove(records(), context())
        self.assertEqual(result["result"], "PASS_AUDIT_BINDING")
        self.assertNotIn(SECRET, str(result))
        self.assertNotIn(context()["role_hmac"], str(result))
        self.assertEqual(len(result["events"]), 3)

    def test_wrong_role_ip_token_or_time_rejected(self):
        cases = []
        x = records(); x[2]["request"]["data"]["role"] = "hmac-sha256:" + "b" * 64; cases.append(x)
        x = records(); x[2]["request"]["remote_address"] = "10.80.2.3"; cases.append(x)
        x = records(); x[3]["response"] = {"auth": {"client_token": SECRET}}; cases.append(x)
        x = records(); x[1]["time"] = time(6); cases.append(x)
        x = records(); x[4]["time"] = time(4); cases.append(x)
        x = records(); x[3]["error"] = "permission denied"; cases.append(x)
        for case in cases:
            with self.assertRaises(M.AuditProofError): M.prove(case, context())

    def test_retry_and_identical_duplicate_are_tolerated(self):
        x = records(); retry = copy.deepcopy(x[2:4])
        for row in retry: row["request"]["id"] = uid(4)
        retry[0]["time"], retry[1]["time"] = time(6), time(7)
        self.assertEqual(M.prove(x + retry + [copy.deepcopy(x[0])], context())["result"], "PASS_AUDIT_BINDING")

    def test_malformed_context_and_conflicting_duplicates_rejected(self):
        for key, value in (("runtime_role_path", "other"), ("deployment_generation", True),
                           ("role_hmac", "a" * 64), ("pod_created_at", time(1))):
            c = context(); c[key] = value
            with self.assertRaises(M.AuditProofError): M.prove(records(), c)
        x = records(); duplicate = copy.deepcopy(x[0]); duplicate["time"] = time(2)
        with self.assertRaises(M.AuditProofError): M.prove(x + [duplicate], context())

    def test_pre_restore_denial_binding_is_paired_and_metadata_only(self):
        result = M.prove_denial(records()[:4], denial_context())
        self.assertEqual(result["result"], "PASS_DENIAL_BINDING")
        self.assertEqual([event["kind"] for event in result["events"]], ["role_deleted", "fresh_pod_denied"])
        self.assertNotIn(SECRET, str(result))
        self.assertNotIn(denial_context()["role_hmac"], str(result))

    def test_pre_restore_denial_rejects_role_ip_order_and_malformed_pairs(self):
        cases = []
        x = records()[:4]; x[2]["request"]["data"]["role"] = "hmac-sha256:" + "b" * 64; cases.append(x)
        x = records()[:4]; x[2]["request"]["remote_address"] = "10.80.9.9"; cases.append(x)
        x = records()[:4]; x[2]["time"] = time(2); cases.append(x)
        x = records()[:4]; x.append(copy.deepcopy(x[0])); x[-1]["time"] = time(6); cases.append(x)
        for case in cases:
            with self.assertRaises(M.AuditProofError): M.prove_denial(case, denial_context())
        restored = denial_context(); restored["observation_before"] = time(20)
        with self.assertRaises(M.AuditProofError): M.prove_denial(records(), restored)

if __name__ == "__main__": unittest.main()

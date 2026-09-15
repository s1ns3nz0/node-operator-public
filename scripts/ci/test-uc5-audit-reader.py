#!/usr/bin/env python3
# Check objective: Verify UC5 audit reader accepts only bounded, provenance-labeled synthetic audit records.
"""Synthetic-only tests for fixed UC5 CloudWatch audit reader."""
import copy, importlib.util, json, pathlib, unittest

PATH = pathlib.Path(__file__).resolve().parents[2] / "scripts/ops/lib/uc5-audit-reader.py"
SPEC = importlib.util.spec_from_file_location("reader", PATH)
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)
PROOF_PATH = PATH.with_name("uc5-audit-proof.py")
PROOF_SPEC = importlib.util.spec_from_file_location("proof", PROOF_PATH)
PROOF = importlib.util.module_from_spec(PROOF_SPEC); PROOF_SPEC.loader.exec_module(PROOF)
FIXTURE_PATH = pathlib.Path(__file__).with_name("test-uc5-audit-proof.py")
FIXTURE_SPEC = importlib.util.spec_from_file_location("proof_fixture", FIXTURE_PATH)
FIXTURE = importlib.util.module_from_spec(FIXTURE_SPEC); FIXTURE_SPEC.loader.exec_module(FIXTURE)
START, END = "2026-09-11T00:00:00Z", "2026-09-11T00:01:00Z"

def row(kind="request"):
    return {"type": kind, "time": START, "request": {"id": "00000000-0000-4000-8000-000000000001"}}

def relay(record=None, source="socket"):
    return {"schema_version": 1, "audit_source": source, "log": json.dumps(record or row(), separators=(",", ":"))}

class ReaderTests(unittest.TestCase):
    def test_fixed_cli_scope_nested_cri_dedup_and_memory_only(self):
        calls = []
        first = json.dumps({"log": "2026-09-11T00:00:01Z stdout F " + json.dumps(relay())})
        pages = [json.dumps({"events": [{"message": first}], "nextToken": "next"}), json.dumps({"events": [{"message": json.dumps(relay())}]})]
        def runner(args): calls.append(args); return pages.pop(0)
        records = M.read_records(START, END, runner)
        self.assertEqual(records, [row()])
        self.assertEqual(calls[0][:8], ("aws", "logs", "filter-log-events", "--region", M.REGION, "--log-group-name", M.GROUP, "--start-time"))
        self.assertIn("--next-token", calls[1])
        self.assertIn("--no-paginate", calls[0])
        self.assertIn("--filter-pattern", calls[0])

    def test_nested_cri_without_plain_duplicate_is_not_discarded(self):
        wrapped = json.dumps({"log": "2026-09-11T00:00:01Z stdout F " + json.dumps(relay())})
        self.assertEqual(M.read_records(START, END, lambda _: json.dumps({"events": [{"message": wrapped}]})), [row()])

    def test_compact_fluent_bit_envelope_is_parsed_before_its_inner_cri_log(self):
        # This is the observed envelope shape: compact JSON, Kubernetes source
        # metadata, and a CRI-prefixed JSON audit record in ``log``.  Applying a
        # permissive CRI regex to the outer string corrupts it before json.loads.
        outer = json.dumps({"kubernetes": {"namespace_name": "vault", "container_name": "vault-validator-audit-relay"},
                            "log": "2026-09-11T00:00:01Z stdout F " + json.dumps(relay(), separators=(",", ":"))},
                           separators=(",", ":"))
        self.assertEqual(M.read_records(START, END, lambda _: json.dumps({"events": [{"message": outer}]})), [row()])

    def test_only_socket_relay_records_are_returned_and_legacy_records_are_ignored(self):
        socket = row(); socket["request"]["device_hmac"] = "socket"
        file = row(); file["request"]["device_hmac"] = "file"
        messages = [json.dumps(relay(file, "file")), json.dumps(relay(socket)), json.dumps(row())]
        response = json.dumps({"events": [{"message": value} for value in messages]})
        self.assertEqual(M.read_records(START, END, lambda _: response), [socket])

    def test_malformed_or_unknown_relay_provenance_is_rejected(self):
        for envelope in ({"schema_version": 2, "audit_source": "socket", "log": json.dumps(row())},
                         {"schema_version": True, "audit_source": "socket", "log": json.dumps(row())},
                         {"schema_version": 1, "audit_source": "unknown", "log": json.dumps(row())},
                         {"schema_version": 1, "audit_source": "socket"}):
            with self.assertRaises(M.AuditReaderError):
                M.read_records(START, END, lambda _, envelope=envelope: json.dumps({"events": [{"message": json.dumps(envelope)}]}))

    def test_conflicting_socket_duplicates_reach_and_are_rejected_by_audit_proof(self):
        records = FIXTURE.records()
        conflicting = copy.deepcopy(records[0]); conflicting["time"] = FIXTURE.time(2)
        messages = [json.dumps(relay(record)) for record in records + [conflicting]]
        decoded = M.read_records(START, END, lambda _: json.dumps({"events": [{"message": value} for value in messages]}))
        self.assertEqual(len(decoded), len(messages))
        with self.assertRaises(PROOF.AuditProofError):
            PROOF.prove(decoded, FIXTURE.context())

    def test_windows_and_pagination_budgets_fail_closed(self):
        with self.assertRaises(M.AuditReaderError): M.read_records(END, START, lambda _: "{}")
        with self.assertRaises(M.AuditReaderError): M.read_records(START, "2026-09-11T00:16:00Z", lambda _: "{}")
        with self.assertRaises(M.AuditReaderError): M.read_records(START, END, lambda _: json.dumps({"events": [], "nextToken": "same"}))
        def looping(_): return json.dumps({"events": [], "nextToken": "different"})
        with self.assertRaises(M.AuditReaderError): M.read_records(START, END, looping)

    def test_malformed_or_oversized_events_are_refused_without_log_output(self):
        with self.assertRaises(M.AuditReaderError): M.read_records(START, END, lambda _: json.dumps({"events": [{"message": "x" * (M.MAX_EVENT_BYTES + 1)}]}))
        with self.assertRaises(M.AuditReaderError): M.read_records(START, END, lambda _: json.dumps({"events": [{}]}))

if __name__ == "__main__": unittest.main()

#!/usr/bin/env python3
# Check objective: Validate synthetic Hoodi finalized-attestation archive collection.
"""Synthetic archive contract; it does not access AWS."""
import contextlib, gzip, importlib.util, io, json, subprocess, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("collector", ROOT / "scripts/release/collect-hoodi-finalized-attestation-evidence.py")
collector = importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(collector)
transport_spec = importlib.util.spec_from_file_location("pod_transport", ROOT / "scripts/release/validator_audit_pod_transport.py")
transport = importlib.util.module_from_spec(transport_spec); transport_spec.loader.exec_module(transport)
KEY = "0x" + "a" * 96
IDENTITY = {"validator_set":"hoodi-example", "validator_public_key":KEY, "validator_index":"123", "deployment_name":"node-operator", "release_revision":"b" * 40}


class ArchiveCollection(unittest.TestCase):
    def setUp(self): self.temp = tempfile.TemporaryDirectory(); self.base = Path(self.temp.name); self.assignment = self.base / "duties.json"
    def tearDown(self): self.temp.cleanup()
    def duty(self, rows=((10, 320, "0"),)):
        groups = {}
        for epoch, slot, committee in rows:
            groups[f"epoch-{epoch}"] = {"epoch":epoch,"attester":[{"pubkey":KEY,"validator_index":"123","committee_index":committee,"committee_length":"1","committees_at_slot":"1","validator_committee_index":"0","slot":str(slot)}]}
        epochs=[epoch for epoch, _, _ in rows]
        if len(epochs) == 1:
            next_epoch = epochs[0] + 1; groups[f"epoch-{next_epoch}"] = {"epoch":next_epoch,"attester":[]}; epochs.append(next_epoch)
        self.assignment.write_text(json.dumps({"schema_version":1,"event_type":"uc-4","collected_at_utc":"2026-09-13T00:00:00Z","correlation_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","network":"hoodi","validator_set":IDENTITY["validator_set"],"validator_public_key":KEY,"source":"private-beacon","payload":{"observation_status":"assignments-observed","signed_outcomes_observed":False,"signed_outcomes_note":"not observed by assignment queries; correlate separately with validator and signer audit evidence","validator_index":"123","queried_epochs":epochs,"assignments":groups}}))
    def runner(self, events):
        wrapped = {"messageType":"DATA_MESSAGE","logEvents":events}; archive = gzip.compress(json.dumps(wrapped).encode())
        def call(args):
            if args[:2] == ["s3api", "list-objects-v2"]: return b'{"Contents":[{"Key":"validator/year=2026/a.gz"}]}'
            if args[:2] == ["s3api", "head-object"]: return json.dumps({"VersionId":"version-1","ETag":"\"etag\"","ContentLength":len(archive)}).encode()
            if args[:2] == ["s3api", "get-object"]:
                Path(args[-1]).write_bytes(archive); return b''
            raise AssertionError(args)
        return call
    def event(self, identifier, timestamp, line, component="validator-remote-signer"):
        record = {"log":"2026-09-13T00:00:00Z stdout F " + line, "kubernetes":{"labels":{"node-operator.io/validator-set":"hoodi-example","node-operator.io/deployment-name":"node-operator","node-operator.io/release-revision":"b" * 40,"app.kubernetes.io/component":component}}}
        return {"id":identifier,"timestamp":timestamp,"message":json.dumps(record)}
    def fence(self, identifier="fence-1", opened=1950, closed=2050, timestamp=2050, result="closed", **overrides):
        fields = {"validator_set":"hoodi-example", "holder":"pod-uid-1", "lease":"validator-hoodi-example-primary", "connection_id":"0000000000000001", "opened_at_utc":"1970-01-01T00:00:01.95Z", "closed_at_utc":"1970-01-01T00:00:02.05Z", "opened_at_ms":str(opened), "closed_at_ms":str(closed), "result":result}
        fields.update(overrides)
        return self.event(identifier, timestamp, "fence_connection " + " ".join(f"{key}={value}" for key, value in fields.items()), "validator-signing-fence")
    def test_real_web3signer_log_shape_is_collected_but_withheld_without_fence_interval(self):
        self.duty()
        event = self.event("sign-1", 2000, "signing_audit audit_request_id=22222222-2222-2222-2222-222222222222 result=SUCCESS public_key=" + KEY + " artifact_type=ATTESTATION signing_root=0x" + "c" * 64 + " slot=320 source_epoch=9 target_epoch=10")
        work, delivery, _ = collector.collect(IDENTITY, self.assignment, "node-audit-123", "validator/", "ap-northeast-2", runner=self.runner([event]))
        # Existing runtime emits the signer record but no fence interval.  It
        # must never be upgraded to an observer proof by a boolean or guess.
        self.assertEqual(work, []); self.assertEqual(delivery, [])

    def test_collector_uses_pod_transport_for_all_archive_calls(self):
        self.duty()
        signing = self.event("sign-1", 2000, "signing_audit audit_request_id=x result=SUCCESS public_key=" + KEY + " artifact_type=ATTESTATION signing_root=0x" + "c" * 64 + " slot=320 source_epoch=9 target_epoch=10")
        archive = gzip.compress(json.dumps({"messageType":"DATA_MESSAGE", "logEvents":[signing, self.fence()]}).encode())
        commands = []
        def pod_call(args):
            commands.append(args)
            self.assertEqual(args[:3], ["kubectl", "-n", "validator-observability"])
            if args[3] == "get": return b"reader-uid"
            command = args[args.index("--") + 1:]
            if command[:3] == ["aws", "s3api", "list-objects-v2"]:
                return b'{"Contents":[{"Key":"validator/a.gz"}]}'
            if command[:3] == ["aws", "s3api", "head-object"]:
                return json.dumps({"VersionId":"version-1", "ETag":"etag", "ContentLength":len(archive)}).encode()
            self.assertEqual(command[:3], ["sh", "-c", transport.GET_SCRIPT])
            self.assertEqual(command[4:], ["node-audit-123", "validator/a.gz", "version-1", "ap-northeast-2"])
            return archive
        reader = transport.PodAWSTransport("validator-observability", "validator-audit-reader-test", "reader-uid", "node-audit-123", "validator/", "ap-northeast-2", pod_call)
        work, delivery, _ = collector.collect(IDENTITY, self.assignment, "node-audit-123", "validator/", "ap-northeast-2", runner=reader)
        self.assertEqual((len(work), len(delivery), len(commands)), (1, 1, 9))
        reader.call = lambda args: b"replacement-uid"
        with self.assertRaises(collector.ArchiveUnavailable):
            collector.collect(IDENTITY, self.assignment, "node-audit-123", "validator/", "ap-northeast-2", runner=reader)

    def test_download_length_must_match_selected_version_metadata(self):
        original = self.runner([])
        def truncated(args):
            value = original(args)
            if args[:2] == ["s3api", "head-object"]:
                metadata = json.loads(value); metadata["ContentLength"] += 1
                return json.dumps(metadata).encode()
            return value
        with self.assertRaises(collector.EvidenceError):
            collector.object_payload("node-audit-123", "validator/a.gz", "ap-northeast-2", truncated)

    def test_known_web3signer_invalid_request_is_skipped_not_treated_as_success_schema(self):
        self.duty()
        rejected = self.event("reject-1", 1990, "signing_audit audit_request_id=request-1 result=INVALID_REQUEST")
        signing = self.event("sign-1", 2000, "signing_audit audit_request_id=x result=SUCCESS public_key=" + KEY + " artifact_type=ATTESTATION signing_root=0x" + "c" * 64 + " slot=320 source_epoch=9 target_epoch=10")
        work, delivery, _ = collector.collect(IDENTITY, self.assignment, "node-audit-123", "validator/", "ap-northeast-2", runner=self.runner([rejected, signing, self.fence()]))
        self.assertEqual(len(work), 1); self.assertEqual(len(delivery), 1)
    def test_missing_fence_record_cannot_produce_a_signed_observation(self):
        self.duty(); event = self.event("sign-1", 2000, "signing_audit audit_request_id=x result=SUCCESS public_key=" + KEY + " artifact_type=ATTESTATION signing_root=0x" + "c" * 64 + " slot=320 source_epoch=9 target_epoch=10")
        work, delivery, _ = collector.collect(IDENTITY, self.assignment, "node-audit-123", "validator/", "ap-northeast-2", runner=self.runner([event]))
        self.assertEqual(work, []); self.assertEqual(delivery, [])
    def test_operator_supplied_mismatched_release_label_is_not_evidence(self):
        self.duty(); event = self.event("sign-1", 2000, "signing_audit audit_request_id=x result=SUCCESS public_key=" + KEY + " artifact_type=ATTESTATION signing_root=0x" + "c" * 64 + " slot=320 source_epoch=9 target_epoch=10")
        message = json.loads(event["message"]); message["kubernetes"]["labels"]["node-operator.io/release-revision"] = "c" * 40; event["message"] = json.dumps(message)
        work, delivery, _ = collector.collect(IDENTITY, self.assignment, "node-audit-123", "validator/", "ap-northeast-2", runner=self.runner([event]))
        self.assertEqual(work, []); self.assertEqual(delivery, [])

    def test_closed_fence_interval_uses_emitter_open_and_close_bounds(self):
        self.duty()
        signing = self.event("sign-1", 2000, "signing_audit audit_request_id=x result=SUCCESS public_key=" + KEY + " artifact_type=ATTESTATION signing_root=0x" + "c" * 64 + " slot=320 source_epoch=9 target_epoch=10")
        work, delivery, _ = collector.collect(IDENTITY, self.assignment, "node-audit-123", "validator/", "ap-northeast-2", runner=self.runner([signing, self.fence()]))
        self.assertEqual(len(work), 1); self.assertEqual(len(delivery), 1)

    def test_unmatched_signer_is_retained_for_a_later_archive_pass(self):
        self.duty()
        signing = self.event("sign-1", 2000, "signing_audit audit_request_id=x result=SUCCESS public_key=" + KEY + " artifact_type=ATTESTATION signing_root=0x" + "c" * 64 + " slot=320 source_epoch=9 target_epoch=10")
        work, delivery, _, state = collector.collect(IDENTITY, self.assignment, "node-audit-123", "validator/", "ap-northeast-2", runner=self.runner([signing]), include_state=True)
        self.assertEqual((work, delivery), ([], [])); self.assertEqual(len(state["signed"]), 1)
        work, delivery, _, state = collector.collect(IDENTITY, self.assignment, "node-audit-123", "validator/", "ap-northeast-2", prior_signed=state["signed"], prior_fences=state["fences"], prior_accepted=state["accepted"], runner=self.runner([self.fence()]), include_state=True)
        self.assertEqual(len(work), 1); self.assertEqual(len(delivery), 1); self.assertEqual(state["signed"], [])

    def test_firehose_outer_gzip_and_concatenated_cloudwatch_envelopes_are_decoded(self):
        self.duty()
        signing = self.event("sign-1", 2000, "signing_audit audit_request_id=x result=SUCCESS public_key=" + KEY + " artifact_type=ATTESTATION signing_root=0x" + "c" * 64 + " slot=320 source_epoch=9 target_epoch=10")
        inner = gzip.compress(json.dumps({"messageType":"DATA_MESSAGE", "logEvents":[signing]}).encode()) + gzip.compress(json.dumps({"messageType":"DATA_MESSAGE", "logEvents":[self.fence()]}).encode())
        archive = gzip.compress(inner)
        def runner(args):
            if args[:2] == ["s3api", "list-objects-v2"]: return b'{"Contents":[{"Key":"validator/a.gz","Size":1}],"IsTruncated":false}'
            if args[:2] == ["s3api", "head-object"]: return json.dumps({"VersionId":"v","ETag":"etag","ContentLength":len(archive)}).encode()
            if args[:2] == ["s3api", "get-object"]: Path(args[-1]).write_bytes(archive); return b""
            raise AssertionError(args)
        work, delivery, _ = collector.collect(IDENTITY, self.assignment, "node-audit-123", "validator/", "ap-northeast-2", runner=runner)
        self.assertEqual(len(work), 1); self.assertEqual(len(delivery), 1)

    def test_signing_before_fence_interval_is_not_retroactively_correlated(self):
        self.duty()
        signing = self.event("sign-1", 1949, "signing_audit audit_request_id=x result=SUCCESS public_key=" + KEY + " artifact_type=ATTESTATION signing_root=0x" + "c" * 64 + " slot=320 source_epoch=9 target_epoch=10")
        work, delivery, _ = collector.collect(IDENTITY, self.assignment, "node-audit-123", "validator/", "ap-northeast-2", runner=self.runner([signing, self.fence(timestamp=2050)]))
        self.assertEqual(work, []); self.assertEqual(delivery, [])

    def test_malformed_or_nonclosed_fence_cannot_produce_an_observation(self):
        self.duty()
        signing = self.event("sign-1", 2000, "signing_audit audit_request_id=x result=SUCCESS public_key=" + KEY + " artifact_type=ATTESTATION signing_root=0x" + "c" * 64 + " slot=320 source_epoch=9 target_epoch=10")
        work, delivery, _ = collector.collect(IDENTITY, self.assignment, "node-audit-123", "validator/", "ap-northeast-2", runner=self.runner([signing, self.fence(holder="")]))
        self.assertEqual(work, []); self.assertEqual(delivery, [])
        work, delivery, _ = collector.collect(IDENTITY, self.assignment, "node-audit-123", "validator/", "ap-northeast-2", runner=self.runner([signing, self.fence(result="upstream-dial-failed")]))
        self.assertEqual(work, []); self.assertEqual(delivery, [])

    def test_paginated_listing_reaches_current_observation_beyond_first_page(self):
        self.duty()
        signing = self.event("sign-1", 2000, "signing_audit audit_request_id=x result=SUCCESS public_key=" + KEY + " artifact_type=ATTESTATION signing_root=0x" + "c" * 64 + " slot=320 source_epoch=9 target_epoch=10")
        archives = {f"validator/old-{number:03d}.gz": gzip.compress(b'{"messageType":"DATA_MESSAGE","logEvents":[]}') for number in range(64)}
        target = "validator/current.gz"; archives[target] = gzip.compress(json.dumps({"messageType":"DATA_MESSAGE","logEvents":[signing, self.fence()]}).encode())
        pages = [list(archives)[:64], [target]]; calls = []
        def runner(args):
            if args[:2] == ["s3api", "list-objects-v2"]:
                self.assertIn("--no-paginate", args)
                token = args[args.index("--continuation-token") + 1] if "--continuation-token" in args else None
                calls.append(token)
                if token is None: return json.dumps({"Contents":[{"Key":key,"Size":len(archives[key])} for key in pages[0]],"IsTruncated":True,"NextContinuationToken":"page-2"}).encode()
                if token == "page-2": return json.dumps({"Contents":[{"Key":target,"Size":len(archives[target])}],"IsTruncated":False}).encode()
            if args[:2] == ["s3api", "head-object"]:
                key = args[args.index("--key") + 1]; return json.dumps({"VersionId":"v-" + key,"ETag":"etag","ContentLength":len(archives[key])}).encode()
            if args[:2] == ["s3api", "get-object"]:
                key = args[args.index("--key") + 1]; Path(args[-1]).write_bytes(archives[key]); return b""
            raise AssertionError(args)
        work, delivery, next_cursor = collector.collect(IDENTITY, self.assignment, "node-audit-123", "validator/", "ap-northeast-2", runner=runner)
        self.assertEqual(calls, [None, "page-2"]); self.assertEqual(next_cursor, None)
        self.assertEqual(len(work), 1); self.assertEqual(len(delivery), 1)

    def test_empty_archive_is_pending_but_api_denial_is_unavailable(self):
        self.duty()
        empty = lambda args: b'{"Contents":[],"IsTruncated":false}'
        objects, cursor = collector.archive_objects("node-audit-123", "validator/", "ap-northeast-2", runner=empty)
        self.assertEqual(objects, []); self.assertIsNone(cursor)
        with self.assertRaises(collector.ArchiveUnavailable):
            collector.archive_objects("node-audit-123", "validator/", "ap-northeast-2", runner=lambda args: (_ for _ in ()).throw(subprocess.CalledProcessError(1, args)))
        output, cursor_path, delivery = self.base / "workload.json", self.base / "cursor.json", self.base / "delivery.json"
        arguments = ["--assignment-proof", str(self.assignment), "--archive-bucket", "node-audit-123", "--aws-region", "ap-northeast-2", "--validator-set", "hoodi-example", "--validator-public-key", KEY, "--validator-index", "123", "--deployment-name", "node-operator", "--release-revision", "b" * 40, "--activation-slot", "0", "--workload-output", str(output), "--log-delivery-output", str(delivery), "--archive-cursor", str(cursor_path)]
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr): self.assertEqual(collector.main(arguments, empty), 75)
        self.assertIn("PENDING:", stderr.getvalue())
        output.unlink(); delivery.unlink(); cursor_path.unlink()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr): self.assertEqual(collector.main(arguments, lambda args: (_ for _ in ()).throw(subprocess.CalledProcessError(1, args))), 70)
        self.assertIn("archive is unavailable", stderr.getvalue())

    def test_fixed_proof_paths_refresh_and_cursor_rejects_another_selected_identity(self):
        self.duty()
        output, cursor_path, delivery = self.base / "workload.json", self.base / "cursor.json", self.base / "delivery.json"
        arguments = ["--assignment-proof", str(self.assignment), "--archive-bucket", "node-audit-123", "--aws-region", "ap-northeast-2", "--validator-set", "hoodi-example", "--validator-public-key", KEY, "--validator-index", "123", "--deployment-name", "node-operator", "--release-revision", "b" * 40, "--activation-slot", "0", "--workload-output", str(output), "--log-delivery-output", str(delivery), "--archive-cursor", str(cursor_path)]
        empty = lambda args: b'{"Contents":[],"IsTruncated":false}'
        self.assertEqual(collector.main(arguments, empty), 75)
        first = output.read_bytes()
        # A later collection updates the stable observer paths atomically rather
        # than failing merely because a prior pending snapshot exists.
        self.assertEqual(collector.main(arguments, empty), 75)
        self.assertEqual(output.read_bytes(), first)
        wrong = arguments.copy(); wrong[wrong.index("--release-revision") + 1] = "c" * 40
        calls = []
        self.assertEqual(collector.main(wrong, lambda args: calls.append(args) or b"{}"), 65)
        self.assertEqual(calls, [])

    def test_three_successive_assignment_snapshots_append_ledger_and_conflict_rejects_before_archive(self):
        output, cursor_path, delivery = self.base / "workload.json", self.base / "cursor.json", self.base / "delivery.json"
        arguments = ["--assignment-proof", str(self.assignment), "--archive-bucket", "node-audit-123", "--aws-region", "ap-northeast-2", "--validator-set", "hoodi-example", "--validator-public-key", KEY, "--validator-index", "123", "--deployment-name", "node-operator", "--release-revision", "b" * 40, "--activation-slot", "0", "--workload-output", str(output), "--log-delivery-output", str(delivery), "--archive-cursor", str(cursor_path)]
        empty = lambda args: b'{"Contents":[],"IsTruncated":false}'
        self.duty(((10, 320, "0"),)); self.assertEqual(collector.main(arguments, empty), 75)
        # The refreshed current/next snapshot repeats epoch 10 and introduces
        # 11: it is a new source hash, not a changed duty.
        self.duty(((10, 320, "0"), (11, 352, "1"))); self.assertEqual(collector.main(arguments, empty), 75)
        self.duty(((11, 352, "1"), (12, 384, "2"))); self.assertEqual(collector.main(arguments, empty), 75)
        state = collector.read_cursor(cursor_path, "node-audit-123", "validator/", "ap-northeast-2", IDENTITY | {"activation_slot":"0"})
        self.assertEqual(set(state["assignment_ledger"]), {"10:320", "11:352", "12:384"})
        self.assertEqual(len(state["assignment_ledger"]["10:320"]["sources"]), 2)
        self.duty(((10, 320, "9"),))
        calls = []
        self.assertEqual(collector.main(arguments, lambda args: calls.append(args) or b"{}"), 65)
        self.assertEqual(calls, [])

    def test_assignment_ledger_capacity_is_explicitly_pending_not_pruned(self):
        self.duty(((10, 320, "0"), (11, 352, "1")))
        rows, source = collector.assignment_source(self.assignment, IDENTITY)
        original = collector.MAX_ASSIGNMENT_DUTIES
        collector.MAX_ASSIGNMENT_DUTIES = 1
        try:
            with self.assertRaises(collector.EvidencePending):
                collector.merge_assignment_ledger({}, rows, source, "0")
        finally:
            collector.MAX_ASSIGNMENT_DUTIES = original

    def test_assignment_parser_rejects_groups_not_equal_to_producer_queried_epochs(self):
        self.duty(((10, 320, "0"), (11, 352, "1")))
        value=json.loads(self.assignment.read_text()); value["payload"]["queried_epochs"]=[10,12]; self.assignment.write_text(json.dumps(value))
        with self.assertRaises(collector.EvidenceError): collector.assignment_rows(self.assignment, IDENTITY)

    def test_repeated_cursor_and_compressed_size_limits_fail_closed(self):
        def repeated(args): return b'{"Contents":[],"IsTruncated":true,"NextContinuationToken":"again"}'
        with self.assertRaises(collector.EvidenceError):
            collector.archive_objects("node-audit-123", "validator/", "ap-northeast-2", runner=repeated)
        page_calls = []
        def many_pages(args):
            token = args[args.index("--continuation-token") + 1] if "--continuation-token" in args else "start"
            page_calls.append(token)
            number = int(token.removeprefix("page-")) if token != "start" else 0
            return json.dumps({"Contents":[], "IsTruncated":True, "NextContinuationToken":f"page-{number + 1}"}).encode()
        _, next_cursor = collector.archive_objects("node-audit-123", "validator/", "ap-northeast-2", runner=many_pages)
        self.assertEqual(page_calls, ["start", "page-1", "page-2", "page-3"])
        self.assertEqual(next_cursor, "page-4")
        self.duty()
        cursor_path = self.base / "archive-cursor.json"; snapshot, source = collector.assignment_source(self.assignment, IDENTITY)
        ledger = collector.merge_assignment_ledger({}, snapshot, source, "0")
        cursor_identity = IDENTITY | {"activation_slot":"0"}
        collector.write_cursor(cursor_path, "node-audit-123", "validator/", "ap-northeast-2", cursor_identity,
                               {"continuation_token": next_cursor, "assignment_ledger": ledger, "signed": [], "fences": [], "accepted": []})
        self.assertEqual(collector.read_cursor(cursor_path, "node-audit-123", "validator/", "ap-northeast-2", cursor_identity)["continuation_token"], "page-4")
        requested_get = False
        def oversized_head(args):
            nonlocal requested_get
            if args[:2] == ["s3api", "head-object"]: return json.dumps({"VersionId":"v","ETag":"etag","ContentLength":collector.MAX_OBJECT_BYTES + 1}).encode()
            if args[:2] == ["s3api", "get-object"]: requested_get = True; return b""
            raise AssertionError(args)
        with self.assertRaises(collector.EvidenceError):
            collector.object_payload("node-audit-123", "validator/a.gz", "ap-northeast-2", oversized_head)
        self.assertFalse(requested_get)
        expanded = gzip.compress(b"x" * (collector.MAX_EXPANDED_OBJECT_BYTES + 1))
        def bomb(args):
            if args[:2] == ["s3api", "head-object"]: return json.dumps({"VersionId":"v","ETag":"etag","ContentLength":len(expanded)}).encode()
            if args[:2] == ["s3api", "get-object"]: Path(args[-1]).write_bytes(expanded); return b""
            raise AssertionError(args)
        with self.assertRaises(collector.EvidenceError):
            collector.object_payload("node-audit-123", "validator/a.gz", "ap-northeast-2", bomb)


if __name__ == "__main__": unittest.main()

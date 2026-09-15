#!/usr/bin/env python3
# Check objective: Validate Fence candidate-to-release authorization evidence.
"""Offline candidate-C to release-R Fence authorization checks."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
import fence_build_inputs
import fence_release_authorization as fence

CANDIDATE = "c" * 40
RELEASE = "d" * 40
DIGEST = "sha256:" + "b" * 64
IMAGE = f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-fence@{DIGEST}"
ALTERNATE_IMAGE = f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/hoodi-example-baseline-validator-fence@{DIGEST}"


class FenceReleaseAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temporary.name) / "bundle"
        self.source = self.bundle / "source"
        (self.source / "release").mkdir(parents=True)
        (self.bundle / "rendered").mkdir()
        for relative in fence_build_inputs.INPUT_PATHS:
            destination = self.source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        self.record = self._record()
        self._write(self.record)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _record(self, image: str = IMAGE) -> dict:
        input_sha = fence_build_inputs.fence_input_sha256(self.source)
        sbom_sha = "e" * 64
        return {
            "schema_version": 1, "event_type": "validator-signing-fence-release-verification",
            "collected_at_utc": "2026-09-13T00:00:00Z", "image": image, "artifact_digest": DIGEST,
            "source_revision": CANDIDATE, "input_sha256": input_sha, "result": "PASS",
            "cryptographic_verification": {"tool": "cosign", "signature_count": 1,
                "identity": fence.IDENTITY, "issuer": fence.ISSUER, "slsa_provenance": True,
                "transparency_log_verified": True},
            "sbom": {"tool": "syft", "format": "cyclonedx-json", "component_count": 1, "sha256": sbom_sha},
            "vulnerability_scan": {"schema_version": "v1", "tool": "grype",
                "scanner": {"version": "1", "database_built": "2026-09-13T00:00:00Z", "database_schema_version": "6"},
                "artifact_digest": DIGEST, "sbom_sha256": sbom_sha, "scanned_at": "2026-09-13T00:00:00Z",
                "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}, "status": "passed"},
        }

    def _write(self, record: dict) -> None:
        record_path = self.bundle / "rendered/fence-release-verification.json"
        raw = json.dumps(record, sort_keys=True).encode() + b"\n"
        record_path.write_bytes(raw)
        auth = {"schema_version": 1, "candidate_revision": CANDIDATE,
                "record_sha256": hashlib.sha256(raw).hexdigest(),
                "publication": {"repository": "s1ns3nz0/node-operator", "workflow": "image-publish.yml", "run_id": "42", "artifact_id": "123"},
                "target": {"image_ref": record["image"], "manifest_digest": DIGEST, "input_sha256": record["input_sha256"]},
                "approvals": {"stage_approved": True, "activation_approved": False}}
        auth_path = self.source / "release/fence-publication-authorization.json"
        auth_path.write_text(json.dumps(auth, sort_keys=True) + "\n")
        entries = []
        for path in (fence.AUTH_PATH, fence.RECORD_PATH):
            data = (self.bundle / path).read_bytes()
            entries.append({"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
        (self.bundle / "bundle-manifest.json").write_text(json.dumps({"schema_version": "v1", "artifact": {"name": "bundle", "media_type": "application/x-tar"}, "source_revision": RELEASE, "entries": entries}))

    def test_candidate_record_is_bound_to_different_release_manifest(self) -> None:
        value = fence.validate_release_authorization(self.bundle, RELEASE, "stage")
        self.assertEqual(value["candidate_revision"], CANDIDATE)
        self.assertEqual(value["release_revision"], RELEASE)
        self.assertEqual(value["record"]["image"], IMAGE)
        with self.assertRaises(fence.FenceReleaseAuthorizationError):
            fence.validate_release_authorization(self.bundle, RELEASE, "activation")

    def test_deployment_scoped_fence_repository_is_bound_exactly(self) -> None:
        record = self._record(ALTERNATE_IMAGE)
        self._write(record)
        value = fence.validate_release_authorization(self.bundle, RELEASE, "stage")
        self.assertEqual(value["record"]["image"], ALTERNATE_IMAGE)

    def test_wrong_type_and_malformed_deployment_repositories_fail_closed(self) -> None:
        for image in (
            f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/hoodi-example-baseline-validator-prysm@{DIGEST}",
            f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/hoodi_001-baseline-validator-fence@{DIGEST}",
        ):
            self._write(self._record(image))
            with self.assertRaises(fence.FenceReleaseAuthorizationError):
                fence.validate_release_authorization(self.bundle, RELEASE, "stage")

    def test_wrong_source_input_digest_and_approval_fail_closed(self) -> None:
        for mutate in (
            lambda record: record.__setitem__("source_revision", "e" * 40),
            lambda record: record.__setitem__("input_sha256", "f" * 64),
            lambda record: record.__setitem__("artifact_digest", "sha256:" + "a" * 64),
        ):
            record = self._record(); mutate(record); self._write(record)
            with self.assertRaises(fence.FenceReleaseAuthorizationError):
                fence.validate_release_authorization(self.bundle, RELEASE, "stage")
        record = self._record(); self._write(record)
        auth_path = self.source / "release/fence-publication-authorization.json"
        auth = json.loads(auth_path.read_text()); auth["approvals"]["stage_approved"] = False; auth_path.write_text(json.dumps(auth))
        manifest = json.loads((self.bundle / "bundle-manifest.json").read_text()); data = auth_path.read_bytes(); manifest["entries"][0] = {"path": fence.AUTH_PATH, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}; (self.bundle / "bundle-manifest.json").write_text(json.dumps(manifest))
        with self.assertRaises(fence.FenceReleaseAuthorizationError):
            fence.validate_release_authorization(self.bundle, RELEASE, "stage")

    def test_manifest_hash_duplicate_json_and_symlink_are_rejected(self) -> None:
        record_path = self.bundle / fence.RECORD_PATH
        record_path.write_bytes(record_path.read_bytes() + b" ")
        with self.assertRaises(fence.FenceReleaseAuthorizationError):
            fence.validate_release_authorization(self.bundle, RELEASE, "stage")

    def test_collector_security_fields_and_raw_object_mismatch_fail_closed(self) -> None:
        for mutate in (
            lambda record: record.__setitem__("schema_version", True),
            lambda record: record["cryptographic_verification"].__setitem__("slsa_provenance", False),
            lambda record: record["vulnerability_scan"].__setitem__("sbom_sha256", "a" * 64),
            lambda record: record["vulnerability_scan"]["findings"].__setitem__("high", 1),
            lambda record: record["vulnerability_scan"]["findings"].__setitem__("unknown", 1),
            lambda record: record["vulnerability_scan"].__setitem__("scanned_at", {}),
        ):
            record = self._record(); mutate(record); self._write(record)
            with self.assertRaises(fence.FenceReleaseAuthorizationError):
                fence.validate_release_authorization(self.bundle, RELEASE, "stage")
        record = self._record(); self._write(record); raw = json.dumps(record, sort_keys=True).encode() + b"\n"
        auth = json.loads((self.source / "release/fence-publication-authorization.json").read_text())
        mismatched = self._record(); mismatched["schema_version"] = True
        with self.assertRaises(fence.FenceReleaseAuthorizationError):
            fence.validate_candidate_authorization(auth, mismatched, raw, self.source)
        self._write(self._record())
        auth_path = self.source / "release/fence-publication-authorization.json"
        auth_path.write_text('{"schema_version":1,"schema_version":1}')
        data = auth_path.read_bytes(); manifest = json.loads((self.bundle / "bundle-manifest.json").read_text()); manifest["entries"][0] = {"path": fence.AUTH_PATH, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}; (self.bundle / "bundle-manifest.json").write_text(json.dumps(manifest))
        with self.assertRaises(fence.FenceReleaseAuthorizationError):
            fence.validate_release_authorization(self.bundle, RELEASE, "stage")
        auth_path.unlink(); auth_path.symlink_to("missing.json")
        with self.assertRaises(fence.FenceReleaseAuthorizationError):
            fence.validate_release_authorization(self.bundle, RELEASE, "stage")


if __name__ == "__main__":
    unittest.main(verbosity=2)

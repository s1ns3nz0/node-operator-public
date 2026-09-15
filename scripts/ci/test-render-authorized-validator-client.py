#!/usr/bin/env python3
# Check objective: Validate manifest-bound validator client rendering authorization.
"""Exercise the manifest-bound client renderer authorization branch offline."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "release"))
import fence_build_inputs
import prysm_publication_record as prysm_record
import fence_release_authorization as fence

CANDIDATE = "c" * 40
RELEASE = "d" * 40
ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
SOURCE_DEPLOYMENT = "node-operator"
SELECTED_DEPLOYMENT = "hoodi-release-001"
PRYSM_DIGEST = "sha256:" + "b" * 64
FENCE_DIGEST = "sha256:" + "e" * 64
SOURCE_PRYSM_REPOSITORY = f"{SOURCE_DEPLOYMENT}-baseline-validator-prysm"
SOURCE_FENCE_REPOSITORY = f"{SOURCE_DEPLOYMENT}-baseline-validator-fence"
PRYSM_REPOSITORY = f"{SELECTED_DEPLOYMENT}-baseline-validator-prysm"
FENCE_REPOSITORY = f"{SELECTED_DEPLOYMENT}-baseline-validator-fence"
SOURCE_PRYSM_IMAGE = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{SOURCE_PRYSM_REPOSITORY}@{PRYSM_DIGEST}"
SOURCE_FENCE_IMAGE = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{SOURCE_FENCE_REPOSITORY}@{FENCE_DIGEST}"
PRYSM_IMAGE = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{PRYSM_REPOSITORY}@{PRYSM_DIGEST}"
FENCE_IMAGE = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{FENCE_REPOSITORY}@{FENCE_DIGEST}"


class AuthorizedRendererTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temporary.name) / "bundle"
        self.source = self.bundle / "source"
        self.rendered = self.bundle / "rendered"
        (self.source / "release").mkdir(parents=True)
        self.rendered.mkdir()
        shutil.copytree(ROOT / "deploy" / "validator", self.source / "deploy" / "validator")
        (self.source / "scripts" / "ops").mkdir(parents=True)
        shutil.copy2(ROOT / "scripts" / "ops" / "render-hoodi-validator-client.sh", self.source / "scripts" / "ops")
        shutil.copytree(ROOT / "scripts" / "release", self.source / "scripts" / "release")
        for relative in set(fence_build_inputs.INPUT_PATHS).union(prysm_record.BUILD_INPUTS):
            destination = self.source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        self._write_authority()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _json(value: object) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"

    def _fence_record(self) -> dict[str, object]:
        input_sha = fence_build_inputs.fence_input_sha256(self.source)
        sbom_sha = "a" * 64
        return {
            "schema_version": 1,
            "event_type": "validator-signing-fence-release-verification",
            "collected_at_utc": "2026-09-13T00:00:00Z",
            "image": SOURCE_FENCE_IMAGE,
            "artifact_digest": FENCE_DIGEST,
            "source_revision": CANDIDATE,
            "input_sha256": input_sha,
            "result": "PASS",
            "cryptographic_verification": {"tool": "cosign", "signature_count": 1,
                "identity": fence.IDENTITY, "issuer": fence.ISSUER,
                "slsa_provenance": True, "transparency_log_verified": True},
            "sbom": {"tool": "syft", "format": "cyclonedx-json", "component_count": 1, "sha256": sbom_sha},
            "vulnerability_scan": {"schema_version": "v1", "tool": "grype",
                "scanner": {"version": "1", "database_built": "2026-09-13T00:00:00Z", "database_schema_version": "6"},
                "artifact_digest": FENCE_DIGEST, "sbom_sha256": sbom_sha,
                "scanned_at": "2026-09-13T00:00:00Z",
                "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
                "status": "passed"},
        }

    def _write_authority(self) -> None:
        target = {"aws_account_id": ACCOUNT, "aws_region": REGION, "deployment_name": SOURCE_DEPLOYMENT,
                  "repository": SOURCE_PRYSM_REPOSITORY, "image_ref": SOURCE_PRYSM_IMAGE,
                  "manifest_digest": PRYSM_DIGEST}
        record = prysm_record.create_record(self.source, release_revision=CANDIDATE,
            build_revision=CANDIDATE, input_sha256=prysm_record.build_input_sha256(self.source),
            run_id="42", **target)
        prysm_raw = self._json(record)
        prysm_auth = {"schema_version": 1, "candidate_revision": CANDIDATE,
            "record_sha256": hashlib.sha256(prysm_raw).hexdigest(),
            "publication": {"repository": "s1ns3nz0/node-operator", "workflow": "image-publish.yml", "run_id": "42", "artifact_id": "7"},
            "target": {"image_ref": SOURCE_PRYSM_IMAGE, "manifest_digest": PRYSM_DIGEST, "input_sha256": record["input_sha256"]},
            "approvals": {"stage_approved": True, "activation_approved": False}}
        fence_record = self._fence_record()
        fence_raw = self._json(fence_record)
        fence_auth = {"schema_version": 1, "candidate_revision": CANDIDATE,
            "record_sha256": hashlib.sha256(fence_raw).hexdigest(),
            "publication": {"repository": "s1ns3nz0/node-operator", "workflow": "image-publish.yml", "run_id": "42", "artifact_id": "8"},
            "target": {"image_ref": SOURCE_FENCE_IMAGE, "manifest_digest": FENCE_DIGEST, "input_sha256": fence_record["input_sha256"]},
            "approvals": {"stage_approved": True, "activation_approved": False}}
        paths = {
            "source/release/prysm-publication-authorization.json": self._json(prysm_auth),
            "source/release/fence-publication-authorization.json": self._json(fence_auth),
            "rendered/prysm-mtls-publication-record.json": prysm_raw,
            "rendered/fence-release-verification.json": fence_raw,
        }
        for relative, raw in paths.items():
            (self.bundle / relative).write_bytes(raw)
        entries = [{"path": relative, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)} for relative, raw in paths.items()]
        manifest = {"schema_version": "v1", "artifact": {"name": "bundle", "media_type": "application/x-tar"},
                    "source_revision": RELEASE, "entries": entries}
        (self.bundle / "bundle-manifest.json").write_bytes(self._json(manifest))

    def _render(self, image: str = PRYSM_IMAGE, fence_image: str = FENCE_IMAGE, account: str = ACCOUNT) -> subprocess.CompletedProcess[str]:
        output = self.bundle / "out.yaml"
        return subprocess.run([
            str(self.source / "scripts" / "ops" / "render-hoodi-validator-client.sh"),
            "--validator-set", "hoodi-test-001", "--validator-public-key", "0x" + "a" * 96,
            "--aws-account-id", account, "--aws-region", REGION, "--prysm-validator-image", image,
            "--signing-fence-image", fence_image, "--kubernetes-api-cidr", "10.0.0.1/32",
            "--output", str(output)], text=True, capture_output=True, timeout=20)

    def test_stage_authorized_new_digests_render_without_historical_catalog(self) -> None:
        result = self._render()
        self.assertEqual(result.returncode, 0, result.stderr)
        output = (self.bundle / "out.yaml").read_text()
        self.assertIn(PRYSM_IMAGE, output)
        self.assertIn(FENCE_IMAGE, output)
        zero = subprocess.run(["ruby", "-ryaml", "-e", "docs=YAML.load_stream(File.read(ARGV[0])); expected=%w[validator-hoodi-test-001-client validator-hoodi-test-001-signing-fence]; found=docs.select{|d| %w[StatefulSet Deployment].include?(d['kind'])}.to_h{|d| [d.dig('metadata','name'), d.dig('spec','replicas')]}; abort('nonzero or missing protected workload') unless expected.all?{|n| found[n] == 0}", str(self.bundle / "out.yaml")], text=True, capture_output=True, timeout=10)
        self.assertEqual(zero.returncode, 0, zero.stderr)

    def test_wrong_destinations_and_malformed_or_partial_authority_fail_closed(self) -> None:
        wrong_digest = PRYSM_IMAGE.rsplit("@", 1)[0] + "@sha256:" + "f" * 64
        wrong_repo = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/other-repository@{PRYSM_DIGEST}"
        wrong_account = PRYSM_IMAGE.replace(ACCOUNT, "999999999999", 1)
        for image, account in ((wrong_digest, ACCOUNT), (wrong_repo, ACCOUNT), (wrong_account, "999999999999")):
            with self.subTest(image=image):
                self.assertNotEqual(self._render(image=image, account=account).returncode, 0)
        wrong_fence = FENCE_IMAGE.rsplit("@", 1)[0] + "@sha256:" + "f" * 64
        self.assertNotEqual(self._render(fence_image=wrong_fence).returncode, 0)
        auth = self.source / "release/prysm-publication-authorization.json"
        auth.write_bytes(b"{}\n")
        self.assertNotEqual(self._render().returncode, 0)
        self._write_authority()
        (self.source / "release/fence-publication-authorization.json").unlink()
        self.assertNotEqual(self._render().returncode, 0)
        self._write_authority()
        (self.rendered / "fence-release-verification.json").unlink()
        self.assertNotEqual(self._render().returncode, 0)
        self._write_authority()
        (self.source / "release/prysm-publication-authorization.json").unlink()
        (self.source / "release/fence-publication-authorization.json").unlink()
        self.assertNotEqual(self._render().returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

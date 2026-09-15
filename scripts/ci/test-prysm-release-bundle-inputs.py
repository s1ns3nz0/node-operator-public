#!/usr/bin/env python3
# Check objective: Verify Prysm candidate-record inputs in release Git trees.
"""Exercise the explicit candidate-record input to a disposable release Git tree."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
import prysm_publication_record as publication

DIGEST = "sha256:" + "c" * 64


class PrysmBundleInputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.fixture = root / "fixture"
        subprocess.run(["git", "clone", "--quiet", "--no-local", str(ROOT), str(self.fixture)], check=True)
        subprocess.run(["python3", str(ROOT / "scripts/ci/reset-release-authorization-fixture.py"), str(self.fixture)], check=True)
        subprocess.run(["git", "-C", str(self.fixture), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.fixture), "config", "user.name", "release test"], check=True)
        for relative in (
            "scripts/ci/build-release-bundle.sh",
            "scripts/ci/test-build-release-bundle.sh",
            "scripts/release/prysm_publication_record.py",
            "scripts/release/prysm_release_authorization.py",
        ):
            target = self.fixture / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        subprocess.run(["git", "-C", str(self.fixture), "add", "scripts"], check=True)
        subprocess.run(["git", "-C", str(self.fixture), "commit", "--allow-empty", "--quiet", "-m", "candidate helpers"], check=True)
        self.candidate = subprocess.check_output(["git", "-C", str(self.fixture), "rev-parse", "HEAD"], text=True).strip()
        target = {
            "aws_account_id": "123456789012", "aws_region": "ap-northeast-2",
            "deployment_name": "node-operator", "repository": "node-operator-baseline-validator-prysm",
            "image_ref": f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-prysm@{DIGEST}",
            "manifest_digest": DIGEST,
        }
        self.record = publication.create_record(self.fixture, release_revision=self.candidate,
                                                build_revision=self.candidate,
                                                input_sha256=publication.build_input_sha256(self.fixture),
                                                run_id="42", **target)
        self.record_path = root / "candidate-record.json"
        self.record_path.write_text(json.dumps(self.record, sort_keys=True) + "\n")
        self._commit_authorization(self.record_path.read_bytes())
        self.bin = root / "bin"; self.bin.mkdir()
        self._fake("syft", "#!/bin/sh\noutput=''; name=''; version=''\nwhile [ \"$#\" -gt 0 ]; do case \"$1\" in --output) output=\"${2#cyclonedx-json=}\"; shift 2;; --source-name) name=$2; shift 2;; --source-version) version=$2; shift 2;; *) shift;; esac; done\nprintf '{\"bomFormat\":\"CycloneDX\",\"metadata\":{\"component\":{\"name\":\"%s\",\"version\":\"%s\"},\"tools\":{\"components\":[{\"name\":\"syft\"}]}},\"components\":[]}\\n' \"$name\" \"$version\" > \"$output\"\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _fake(self, name: str, contents: str) -> None:
        path = self.bin / name
        path.write_text(contents)
        path.chmod(0o755)

    def _commit_authorization(self, record_bytes: bytes) -> None:
        auth = {
            "schema_version": 1, "candidate_revision": self.candidate,
            "record_sha256": hashlib.sha256(record_bytes).hexdigest(),
            "publication": {"repository": "s1ns3nz0/node-operator", "workflow": "image-publish.yml", "run_id": "42", "artifact_id": "123"},
            "target": {key: self.record["target"][key] for key in ("image_ref", "manifest_digest")}
                      | {"input_sha256": self.record["input_sha256"]},
            "approvals": {"stage_approved": True, "activation_approved": False},
        }
        path = self.fixture / "release/prysm-publication-authorization.json"
        path.write_text(json.dumps(auth, sort_keys=True) + "\n")
        subprocess.run(["git", "-C", str(self.fixture), "add", str(path.relative_to(self.fixture))], check=True)
        subprocess.run(["git", "-C", str(self.fixture), "commit", "--quiet", "-m", "authorize prior Prysm candidate"], check=True)
        self.release = subprocess.check_output(["git", "-C", str(self.fixture), "rev-parse", "HEAD"], text=True).strip()

    def _run(self, output: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = {**__import__("os").environ, "PATH": f"{self.bin}:{__import__('os').environ['PATH']}"}
        return subprocess.run([str(self.fixture / "scripts/ci/build-release-bundle.sh"), *arguments, str(output)],
                              cwd=self.fixture, env=environment, text=True, capture_output=True, timeout=90)

    def _publication_records(self) -> Path:
        directory = Path(self.temporary.name) / "publication-records"
        directory.mkdir(mode=0o700)
        for component, method, letter in (
            ("vault-bootstrap", "input-hash-and-registry-digest", "a"),
            ("vault-audit-relay", "cosign-and-slsa", "b"),
            ("gitops-oci-mirror", "input-hash-and-registry-digest", "c"),
        ):
            digest = "sha256:" + letter * 64
            value = {
                "schema_version": 1, "component": component, "kind": "image",
                "release_revision": self.release, "build_revision": self.release,
                "third_party_source_revision": None,
                "image_ref": f"ghcr.io/s1ns3nz0/node-operator/{component}@{digest}",
                "manifest_digest": digest, "input_sha256": letter * 64,
                "publication": {"workflow": "image-publish.yml", "run_id": "1", "invocation": "test"},
                "verification": {"method": method, "status": "passed"},
            }
            (directory / f"{component}-publication-record.json").write_text(json.dumps(value, sort_keys=True))
        return directory

    def test_prior_candidate_record_is_frozen_and_manifest_bound(self) -> None:
        output = Path(self.temporary.name) / "output"
        result = self._run(output, "--prysm-publication-record", str(self.record_path))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        extracted = Path(self.temporary.name) / "bundle"; extracted.mkdir()
        with tarfile.open(output / "node-operator-release-bundle.tar") as archive:
            archive.extractall(extracted, filter="data")
        record_path = extracted / "rendered/prysm-mtls-publication-record.json"
        self.assertEqual(record_path.read_bytes(), self.record_path.read_bytes())
        manifest = json.loads((extracted / "bundle-manifest.json").read_text())
        entry = next(item for item in manifest["entries"] if item["path"] == "rendered/prysm-mtls-publication-record.json")
        self.assertEqual(entry["sha256"], hashlib.sha256(self.record_path.read_bytes()).hexdigest())
        self.assertEqual(manifest["source_revision"], self.release)
        self.assertNotEqual(self.candidate, self.release)

    def test_missing_symlink_hash_and_context_fail_before_output(self) -> None:
        def assert_rejected(label: str, *arguments: str) -> None:
            output = Path(self.temporary.name) / label
            result = self._run(output, *arguments)
            self.assertNotEqual(result.returncode, 0, label)
            self.assertFalse(output.exists(), label)

        assert_rejected("missing")
        linked = Path(self.temporary.name) / "record-link.json"; linked.symlink_to(self.record_path)
        assert_rejected("symlink", "--prysm-publication-record", str(linked))
        damaged = Path(self.temporary.name) / "damaged-record.json"; damaged.write_bytes(self.record_path.read_bytes() + b" ")
        assert_rejected("hash", "--prysm-publication-record", str(damaged))

        other = publication.create_record(self.fixture, release_revision=self.candidate,
                                          build_revision=self.candidate,
                                          input_sha256=publication.build_input_sha256(self.fixture),
                                          run_id="43", aws_account_id="123456789012", aws_region="ap-northeast-2",
                                          deployment_name="node-operator", repository="node-operator-baseline-validator-prysm",
                                          image_ref=f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-prysm@{DIGEST}", manifest_digest=DIGEST)
        other_path = Path(self.temporary.name) / "other-record.json"; other_path.write_text(json.dumps(other, sort_keys=True) + "\n")
        self._commit_authorization(other_path.read_bytes())
        assert_rejected("context", "--prysm-publication-record", str(other_path))

    def test_legacy_release_without_authorization_accepts_no_record(self) -> None:
        subprocess.run(["git", "-C", str(self.fixture), "checkout", "--quiet", self.candidate], check=True)
        output = Path(self.temporary.name) / "legacy"
        result = self._run(output)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_authorized_record_flows_through_both_deterministic_builder_passes(self) -> None:
        output = Path(self.temporary.name) / "repeatable"
        environment = {**__import__("os").environ, "PATH": f"{self.bin}:{__import__('os').environ['PATH']}"}
        records = self._publication_records()
        result = subprocess.run([str(self.fixture / "scripts/ci/test-build-release-bundle.sh"),
                                 "--publication-records-dir", str(records),
                                 "--prysm-publication-record", str(self.record_path), str(output)],
                                cwd=self.fixture, env=environment, text=True, capture_output=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((output / "node-operator-release-bundle.tar").is_file())
        extracted = Path(self.temporary.name) / "repeatable-extract"
        extracted.mkdir()
        with tarfile.open(output / "node-operator-release-bundle.tar") as archive:
            archive.extractall(extracted, filter="data")
        self.assertEqual((extracted / "rendered/prysm-mtls-publication-record.json").read_bytes(),
                         self.record_path.read_bytes())


if __name__ == "__main__":
    unittest.main()

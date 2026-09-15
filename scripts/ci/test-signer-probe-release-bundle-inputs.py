#!/usr/bin/env python3
# Check objective: Verify frozen signer-probe evidence through bundle construction.
"""Exercise frozen signer-probe evidence through the real bundle builder."""
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
sys.path.insert(0, str(ROOT / "scripts" / "release"))
import signer_probe_build_inputs as inputs
import signer_probe_publication_record as publication

CANDIDATE = "c" * 40
DIGEST = "sha256:" + "e" * 64
IMAGE = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-signer-identity-probe@" + DIGEST
RECORD = "signer-identity-probe-publication-record.json"
STAGED_RECORD = "signer-probe-publication-record.json"


class SignerProbeBundleInputsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        temporary = Path(self.temporary.name)
        self.fixture = temporary / "fixture"
        subprocess.run(["git", "clone", "--quiet", "--no-local", str(ROOT), str(self.fixture)], check=True)
        subprocess.run(["python3", str(ROOT / "scripts/ci/reset-release-authorization-fixture.py"), str(self.fixture)], check=True)
        subprocess.run(["git", "-C", str(self.fixture), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.fixture), "config", "user.name", "bundle test"], check=True)
        for relative in (
            "scripts/ci/build-release-bundle.sh", "scripts/ci/test-build-release-bundle.sh",
            "scripts/release/fence_build_inputs.py", "scripts/release/signer_probe_build_inputs.py",
            "scripts/release/signer_probe_publication_record.py", "scripts/release/signer_probe_release_authorization.py",
            *inputs.INPUT_PATHS,
        ):
            destination = self.fixture / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        unreviewed = self.fixture / ".ci/validator-signer-identity-probe/unreviewed.txt"
        unreviewed.write_text("must not become a signer-probe build input\n")
        subprocess.run(["git", "-C", str(self.fixture), "add", "scripts", "go.mod", ".ci", "cmd"], check=True)
        subprocess.run(["git", "-C", str(self.fixture), "commit", "--quiet", "-m", "candidate signer probe inputs"], check=True)
        self.candidate = self.revision()
        self.record = publication.create_record(
            self.fixture, release_revision=self.candidate, build_revision=self.candidate,
            input_sha256=self.hash_inputs(), aws_account_id="123456789012", aws_region="ap-northeast-2",
            deployment_name="node-operator", repository="node-operator-baseline-validator-signer-identity-probe",
            image_ref=IMAGE, manifest_digest=DIGEST, run_id="42")
        self.record_path = temporary / RECORD
        self.record_path.write_bytes(self.raw(self.record))
        self.commit_authorization(self.record_path.read_bytes())
        self.bin = temporary / "bin"; self.bin.mkdir()
        self.fake("syft", "#!/bin/sh\nout=''; name=''; version=''; while [ \"$#\" -gt 0 ]; do case \"$1\" in --output) out=\"${2#cyclonedx-json=}\"; shift 2;; --source-name) name=$2; shift 2;; --source-version) version=$2; shift 2;; *) shift;; esac; done; printf '{\"bomFormat\":\"CycloneDX\",\"metadata\":{\"component\":{\"name\":\"%s\",\"version\":\"%s\"},\"tools\":{\"components\":[{\"name\":\"syft\"}]}},\"components\":[]}\\n' \"$name\" \"$version\" > \"$out\"\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def raw(value: object) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"

    def fake(self, name: str, text: str) -> None:
        path = self.bin / name; path.write_text(text); path.chmod(0o755)

    def revision(self) -> str:
        return subprocess.check_output(["git", "-C", str(self.fixture), "rev-parse", "HEAD"], text=True).strip()

    def hash_inputs(self) -> str:
        return subprocess.check_output(["python3", "-B", str(self.fixture / "scripts/release/signer_probe_build_inputs.py"), "--root", str(self.fixture)], text=True).strip()

    def commit_authorization(self, raw: bytes) -> None:
        auth = {"schema_version": 1, "candidate_revision": self.candidate,
                "record_sha256": hashlib.sha256(raw).hexdigest(),
                "publication": {"repository": "s1ns3nz0/node-operator", "workflow": "image-publish.yml", "run_id": "42", "artifact_id": "123"},
                "target": {key: self.record[key] for key in ("image_ref", "manifest_digest", "input_sha256")},
                "approvals": {"stage_approved": True}}
        path = self.fixture / "release/signer-probe-publication-authorization.json"
        path.write_bytes(self.raw(auth))
        subprocess.run(["git", "-C", str(self.fixture), "add", str(path.relative_to(self.fixture))], check=True)
        subprocess.run(["git", "-C", str(self.fixture), "commit", "--quiet", "-m", "authorize signer probe candidate"], check=True)
        self.release = self.revision()

    def invoke(self, output: Path, *args: str) -> subprocess.CompletedProcess[str]:
        env = {**__import__("os").environ, "PATH": f"{self.bin}:{__import__('os').environ['PATH']}"}
        return subprocess.run([str(self.fixture / "scripts/ci/build-release-bundle.sh"), *args, str(output)], cwd=self.fixture, env=env, text=True, capture_output=True, timeout=120)

    def test_frozen_candidate_record_is_manifest_bound_and_inputs_are_exact(self) -> None:
        output = Path(self.temporary.name) / "output"
        result = self.invoke(output, "--signer-probe-publication-record", str(self.record_path))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        extracted = Path(self.temporary.name) / "extract"; extracted.mkdir()
        with tarfile.open(output / "node-operator-release-bundle.tar") as archive:
            archive.extractall(extracted, filter="data")
        self.assertEqual((extracted / "rendered" / STAGED_RECORD).read_bytes(), self.record_path.read_bytes())
        manifest = json.loads((extracted / "bundle-manifest.json").read_text())
        entries = {entry["path"]: entry for entry in manifest["entries"]}
        self.assertEqual(manifest["source_revision"], self.release)
        self.assertNotEqual(self.candidate, self.release)
        self.assertEqual(entries["rendered/" + STAGED_RECORD]["sha256"], hashlib.sha256(self.record_path.read_bytes()).hexdigest())
        for relative in inputs.INPUT_PATHS:
            self.assertIn("source/" + relative, entries)
        self.assertNotIn("source/.ci/validator-signer-identity-probe/unreviewed.txt", entries)

    def test_missing_orphan_tampered_and_changed_selected_source_reject(self) -> None:
        def rejected(label: str, *args: str) -> None:
            output = Path(self.temporary.name) / label
            result = self.invoke(output, *args)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(output.exists())
        rejected("missing")
        bad = Path(self.temporary.name) / "bad.json"; bad.write_bytes(self.record_path.read_bytes() + b" ")
        rejected("tampered", "--signer-probe-publication-record", str(bad))
        subprocess.run(["git", "-C", str(self.fixture), "checkout", "--quiet", self.candidate], check=True)
        rejected("orphan", "--signer-probe-publication-record", str(self.record_path))
        subprocess.run(["git", "-C", str(self.fixture), "checkout", "--quiet", self.release], check=True)
        changed = self.fixture / inputs.INPUT_PATHS[0]; changed.write_bytes(changed.read_bytes() + b"\nchanged\n")
        subprocess.run(["git", "-C", str(self.fixture), "add", str(inputs.INPUT_PATHS[0])], check=True)
        subprocess.run(["git", "-C", str(self.fixture), "commit", "--quiet", "-m", "change selected signer input"], check=True)
        rejected("source", "--signer-probe-publication-record", str(self.record_path))

    def test_reproducibility_wrapper_forwards_frozen_record_to_both_indexed_builds(self) -> None:
        records = Path(self.temporary.name) / "publication-records"
        records.mkdir(mode=0o700)
        for component, method, letter in (
            ("vault-bootstrap", "input-hash-and-registry-digest", "a"),
            ("vault-audit-relay", "cosign-and-slsa", "b"),
            ("gitops-oci-mirror", "input-hash-and-registry-digest", "c"),
        ):
            digest = "sha256:" + letter * 64
            value = {"schema_version": 1, "component": component, "kind": "image",
                     "release_revision": self.release, "build_revision": self.release,
                     "third_party_source_revision": None,
                     "image_ref": f"ghcr.io/s1ns3nz0/node-operator/{component}@{digest}",
                     "manifest_digest": digest, "input_sha256": letter * 64,
                     "publication": {"workflow": "image-publish.yml", "run_id": "1", "invocation": "test"},
                     "verification": {"method": method, "status": "passed"}}
            (records / f"{component}-publication-record.json").write_text(json.dumps(value, sort_keys=True))
        output = Path(self.temporary.name) / "repro"
        env = {**__import__("os").environ, "PATH": f"{self.bin}:{__import__('os').environ['PATH']}"}
        result = subprocess.run([
            str(self.fixture / "scripts/ci/test-build-release-bundle.sh"),
            "--publication-records-dir", str(records), "--signer-probe-publication-record", str(self.record_path), str(output),
        ], cwd=self.fixture, env=env, text=True, capture_output=True, timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with tarfile.open(output / "node-operator-release-bundle.tar") as archive:
            self.assertEqual(archive.extractfile("rendered/" + STAGED_RECORD).read(), self.record_path.read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)

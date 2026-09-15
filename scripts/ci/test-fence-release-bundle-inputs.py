#!/usr/bin/env python3
# Check objective: Verify committed Fence evidence inputs in release Git trees.
"""Exercise committed Fence evidence inputs against disposable release Git trees."""
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
from fence_build_inputs import INPUT_PATHS

FENCE_INPUTS = (
    "go.mod",
    ".ci/validator-signing-fence/Dockerfile",
    "cmd/validator-signing-fence/main.go",
    "cmd/validator-signing-fence/main_test.go",
    "scripts/ci/collect-validator-signing-fence-release-evidence.sh",
    ".github/workflows/fence-security.yml",
    ".ci/fence-security/Dockerfile",
    ".ci/fence-security/blackbox.go",
    ".ci/fence-security/tools.env",
    ".ci/fence-security/zap-report.jq",
    "scripts/ci/install-fence-security-tools.sh",
    "scripts/ci/run-fence-security-sast.sh",
    "scripts/ci/run-fence-security-dast.sh",
)
DIGEST = "sha256:" + "f" * 64
IMAGE = f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-fence@{DIGEST}"


class FenceBundleInputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertEqual(FENCE_INPUTS, INPUT_PATHS)
        self.temporary = tempfile.TemporaryDirectory()
        temporary_root = Path(self.temporary.name)
        self.fixture = temporary_root / "fixture"
        subprocess.run(["git", "clone", "--quiet", "--no-local", str(ROOT), str(self.fixture)], check=True)
        subprocess.run(["python3", str(ROOT / "scripts/ci/reset-release-authorization-fixture.py"), str(self.fixture)], check=True)
        subprocess.run(["git", "-C", str(self.fixture), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.fixture), "config", "user.name", "release test"], check=True)
        for relative in (
            "scripts/ci/build-release-bundle.sh",
            "scripts/ci/test-build-release-bundle.sh",
            "scripts/release/fence_build_inputs.py",
            "scripts/release/fence_release_authorization.py",
        ):
            destination = self.fixture / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        # A committed neighbor must not expand the fixed 13-file input boundary.
        unreviewed = self.fixture / ".ci/fence-security/unreviewed.txt"
        unreviewed.write_text("must not enter release bundle\n")
        subprocess.run(["git", "-C", str(self.fixture), "add", "scripts", str(unreviewed.relative_to(self.fixture))], check=True)
        subprocess.run(["git", "-C", str(self.fixture), "commit", "--quiet", "-m", "candidate Fence helpers"], check=True)
        self.candidate = self._revision()
        input_sha = subprocess.check_output(
            ["python3", "-B", str(self.fixture / "scripts/release/fence_build_inputs.py"), "--root", str(self.fixture)],
            text=True,
        ).strip()
        self.record = self._record(input_sha, self.candidate)
        self.record_path = temporary_root / "candidate-fence-record.json"
        self.record_path.write_bytes(json.dumps(self.record, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        self._commit_authorization(self.record_path.read_bytes())
        self.bin = temporary_root / "bin"
        self.bin.mkdir()
        self._fake("syft", "#!/bin/sh\noutput=''; name=''; version=''\nwhile [ \"$#\" -gt 0 ]; do case \"$1\" in --output) output=\"${2#cyclonedx-json=}\"; shift 2;; --source-name) name=$2; shift 2;; --source-version) version=$2; shift 2;; *) shift;; esac; done\nprintf '{\"bomFormat\":\"CycloneDX\",\"metadata\":{\"component\":{\"name\":\"%s\",\"version\":\"%s\"},\"tools\":{\"components\":[{\"name\":\"syft\"}]}},\"components\":[]}\\n' \"$name\" \"$version\" > \"$output\"\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _fake(self, name: str, contents: str) -> None:
        executable = self.bin / name
        executable.write_text(contents)
        executable.chmod(0o755)

    def _revision(self) -> str:
        return subprocess.check_output(["git", "-C", str(self.fixture), "rev-parse", "HEAD"], text=True).strip()

    def _record(self, input_sha: str, revision: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "event_type": "validator-signing-fence-release-verification",
            "collected_at_utc": "2026-09-13T00:00:00Z",
            "image": IMAGE,
            "artifact_digest": DIGEST,
            "source_revision": revision,
            "input_sha256": input_sha,
            "result": "PASS",
            "cryptographic_verification": {"tool": "cosign", "signature_count": 1,
                "identity": "https://github.com/s1ns3nz0/node-operator/.github/workflows/image-publish.yml@refs/heads/main",
                "issuer": "https://token.actions.githubusercontent.com", "slsa_provenance": True,
                "transparency_log_verified": True},
            "sbom": {"tool": "syft", "format": "cyclonedx-json", "component_count": 0, "sha256": "a" * 64},
            "vulnerability_scan": {"schema_version": "v1", "tool": "grype", "scanner": {"version": "test", "database_built": "2026-09-13T00:00:00Z", "database_schema_version": "6"},
                "artifact_digest": DIGEST, "sbom_sha256": "a" * 64, "scanned_at": "2026-09-13T00:00:00Z",
                "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}, "status": "passed"},
        }

    def _commit_authorization(self, record_bytes: bytes) -> None:
        authorization = {
            "schema_version": 1, "candidate_revision": self.candidate,
            "record_sha256": hashlib.sha256(record_bytes).hexdigest(),
            "publication": {"repository": "s1ns3nz0/node-operator", "workflow": "image-publish.yml", "run_id": "42", "artifact_id": "123"},
            "target": {"image_ref": IMAGE, "manifest_digest": DIGEST, "input_sha256": self.record["input_sha256"]},
            "approvals": {"stage_approved": True, "activation_approved": False},
        }
        path = self.fixture / "release/fence-publication-authorization.json"
        path.write_text(json.dumps(authorization, sort_keys=True) + "\n")
        subprocess.run(["git", "-C", str(self.fixture), "add", str(path.relative_to(self.fixture))], check=True)
        subprocess.run(["git", "-C", str(self.fixture), "commit", "--quiet", "-m", "authorize prior Fence candidate"], check=True)
        self.release = self._revision()

    def _run(self, output: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = {**__import__("os").environ, "PATH": f"{self.bin}:{__import__('os').environ['PATH']}"}
        return subprocess.run([str(self.fixture / "scripts/ci/build-release-bundle.sh"), *arguments,
                               str(output)], cwd=self.fixture, env=environment, text=True, capture_output=True, timeout=90)

    def _extract(self, output: Path, name: str) -> Path:
        destination = Path(self.temporary.name) / name
        destination.mkdir()
        with tarfile.open(output / "node-operator-release-bundle.tar") as archive:
            archive.extractall(destination, filter="data")
        return destination

    def _publication_records(self) -> Path:
        directory = Path(self.temporary.name) / "publication-records"
        directory.mkdir(mode=0o700)
        for component, method, letter in (
            ("vault-bootstrap", "input-hash-and-registry-digest", "a"),
            ("vault-audit-relay", "cosign-and-slsa", "b"),
            ("gitops-oci-mirror", "input-hash-and-registry-digest", "c"),
        ):
            digest = "sha256:" + letter * 64
            record = {
                "schema_version": 1, "component": component, "kind": "image",
                "release_revision": self.release, "build_revision": self.release,
                "third_party_source_revision": None,
                "image_ref": f"ghcr.io/s1ns3nz0/node-operator/{component}@{digest}",
                "manifest_digest": digest, "input_sha256": letter * 64,
                "publication": {"workflow": "image-publish.yml", "run_id": "1", "invocation": "test"},
                "verification": {"method": method, "status": "passed"},
            }
            (directory / f"{component}-publication-record.json").write_text(json.dumps(record, sort_keys=True))
        return directory

    def test_authorized_prior_record_is_frozen_manifest_bound_and_reviewed_inputs_are_exact(self) -> None:
        output = Path(self.temporary.name) / "output"
        result = self._run(output, "--fence-publication-record", str(self.record_path))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        extracted = self._extract(output, "bundle")
        staged_record = extracted / "rendered/fence-release-verification.json"
        self.assertEqual(staged_record.read_bytes(), self.record_path.read_bytes())
        manifest = json.loads((extracted / "bundle-manifest.json").read_text())
        entries = {item["path"]: item for item in manifest["entries"]}
        self.assertEqual(entries["rendered/fence-release-verification.json"]["sha256"], hashlib.sha256(self.record_path.read_bytes()).hexdigest())
        self.assertIn("source/release/fence-publication-authorization.json", entries)
        self.assertEqual(manifest["source_revision"], self.release)
        self.assertNotEqual(self.candidate, self.release)
        packaged_inputs = {path.removeprefix("source/") for path in entries if path.startswith("source/")}
        self.assertTrue(set(FENCE_INPUTS).issubset(packaged_inputs))
        self.assertNotIn(".ci/fence-security/unreviewed.txt", packaged_inputs)
        self.assertFalse(any("__pycache__/" in path for path in entries))

    def test_missing_hash_symlink_and_orphan_evidence_fail_before_output(self) -> None:
        def rejected(label: str, *arguments: str) -> None:
            output = Path(self.temporary.name) / label
            result = self._run(output, *arguments)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(output.exists(), label)

        rejected("missing")
        linked = Path(self.temporary.name) / "record-link.json"
        linked.symlink_to(self.record_path)
        rejected("symlink", "--fence-publication-record", str(linked))
        damaged = Path(self.temporary.name) / "damaged-record.json"
        damaged.write_bytes(self.record_path.read_bytes() + b" ")
        rejected("hash", "--fence-publication-record", str(damaged))
        subprocess.run(["git", "-C", str(self.fixture), "checkout", "--quiet", self.candidate], check=True)
        rejected("orphan", "--fence-publication-record", str(self.record_path))

    def test_legacy_release_accepts_no_record_and_authorized_builds_are_byte_identical(self) -> None:
        subprocess.run(["git", "-C", str(self.fixture), "checkout", "--quiet", self.candidate], check=True)
        legacy = Path(self.temporary.name) / "legacy"
        result = self._run(legacy)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((legacy / "node-operator-release-bundle.tar").is_file())

        subprocess.run(["git", "-C", str(self.fixture), "checkout", "--quiet", self.release], check=True)
        first, second = Path(self.temporary.name) / "first", Path(self.temporary.name) / "second"
        for output in (first, second):
            result = self._run(output, "--fence-publication-record", str(self.record_path))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((first / "node-operator-release-bundle.tar").read_bytes(), (second / "node-operator-release-bundle.tar").read_bytes())

    def test_authorized_record_flows_through_reproducibility_repeats_and_indexed_repeats(self) -> None:
        output = Path(self.temporary.name) / "reproducible"
        environment = {**__import__("os").environ, "PATH": f"{self.bin}:{__import__('os').environ['PATH']}"}
        records = self._publication_records()
        result = subprocess.run([
            str(self.fixture / "scripts/ci/test-build-release-bundle.sh"),
            "--publication-records-dir", str(records),
            "--fence-publication-record", str(self.record_path), str(output),
        ], cwd=self.fixture, env=environment, text=True, capture_output=True, timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        extracted = self._extract(output, "reproducible-extract")
        self.assertEqual((extracted / "rendered/fence-release-verification.json").read_bytes(), self.record_path.read_bytes())

        missing = Path(self.temporary.name) / "missing-fence"
        failed = subprocess.run([
            str(self.fixture / "scripts/ci/test-build-release-bundle.sh"),
            "--publication-records-dir", str(records), str(missing),
        ], cwd=self.fixture, env=environment, text=True, capture_output=True, timeout=180)
        self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)

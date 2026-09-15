#!/usr/bin/env python3
# Check objective: Validate third-party Prysm mTLS publication records.
"""Offline tests for third-party Prysm mTLS publication records."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
import prysm_publication_record as record

SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
TARGET = {"aws_account_id": "123456789012", "aws_region": "ap-northeast-2", "deployment_name": "node-operator", "repository": "node-operator-baseline-validator-prysm", "image_ref": f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-prysm@{DIGEST}", "manifest_digest": DIGEST, "platform": "linux/amd64"}


class PrysmRecordTests(unittest.TestCase):
    def build(self):
        return record.create_record(ROOT, release_revision=SHA, build_revision=SHA, input_sha256=record.build_input_sha256(ROOT),
                                    aws_account_id=TARGET["aws_account_id"], aws_region=TARGET["aws_region"],
                                    deployment_name=TARGET["deployment_name"], repository=TARGET["repository"],
                                    image_ref=TARGET["image_ref"], manifest_digest=DIGEST, run_id="42")

    def test_full_positive_record_binds_real_lock_and_patches(self):
        value = self.build()
        self.assertEqual(record.validate_record(value, ROOT, expected_release_revision=SHA, expected_context=TARGET), value)
        self.assertEqual(value["source"]["commit"], json.loads((ROOT / ".ci/prysm-mtls/source.lock.json").read_text())["commit"])

    def test_identity_context_and_verification_tampering_rejected(self):
        mutations = (
            lambda value: value.update(component="prysm-validator"),
            lambda value: value["source"].update(patch_sha256="d" * 64),
            lambda value: value["target"].update(aws_region="ap-northeast-1"),
            lambda value: value["target"].update(repository="other-baseline-validator-prysm"),
            lambda value: value["target"].update(platform="linux/arm64"),
            lambda value: value["target"].update(image_ref="123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-prysm@sha256:" + "d" * 64),
            lambda value: value["publication"].update(workflow="other.yml"),
            lambda value: value["publication"].update(invocation="other-publish"),
            lambda value: value["publication"].update(run_id="0"),
            lambda value: value["publication"].update(run_id="01"),
            lambda value: value["publication"].update(run_id=True),
            lambda value: value["verification"].update(scan_passed=False),
            lambda value: value["verification"].update(cosign_verified=1),
            lambda value: value.update(build_revision="d" * 40),
            lambda value: value.update(input_sha256="c" * 64),
            lambda value: value.pop("input_sha256"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = self.build(); mutate(value)
                with self.assertRaises(record.PrysmPublicationRecordError): record.validate_record(value, ROOT, expected_release_revision=SHA, expected_context=TARGET)

    def test_safe_load_duplicate_json_and_atomic_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "records"; directory.mkdir(mode=0o700)
            path = directory / "prysm-mtls-publication-record.json"
            value = self.build(); record.write_record(path, value, ROOT)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            before = path.read_bytes()
            with self.assertRaises(record.PrysmPublicationRecordError): record.write_record(path, value, ROOT)
            self.assertEqual(path.read_bytes(), before)
            duplicate = directory / "duplicate.json"
            duplicate.write_bytes(before[:-2] + b',"component":"prysm-mtls"}\n')
            with self.assertRaises(record.PrysmPublicationRecordError): record.load_and_validate(duplicate, ROOT)
            link = directory / "link.json"; link.symlink_to(path)
            with self.assertRaises(record.PrysmPublicationRecordError): record.load_and_validate(link, ROOT)

    def test_patch_change_and_create_input_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            for relative in (".ci/prysm-mtls/source.lock.json", *record.PATCHES.values()):
                target = source / relative; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            patch = source / record.PATCHES["patch_sha256"]
            patch.write_bytes(patch.read_bytes() + b"changed")
            with self.assertRaises(record.PrysmPublicationRecordError): record.create_record(source, release_revision=SHA, build_revision=SHA, input_sha256="c" * 64, aws_account_id=TARGET["aws_account_id"], aws_region=TARGET["aws_region"], deployment_name=TARGET["deployment_name"], repository=TARGET["repository"], image_ref=TARGET["image_ref"], manifest_digest=DIGEST, run_id=1)
        with self.assertRaises(record.PrysmPublicationRecordError):
            record.create_record(ROOT, release_revision=SHA, build_revision=SHA, input_sha256="c" * 64, aws_account_id=TARGET["aws_account_id"], aws_region=TARGET["aws_region"], deployment_name=TARGET["deployment_name"], repository=TARGET["repository"], image_ref=TARGET["image_ref"], manifest_digest=DIGEST, run_id=1)

    def test_input_hash_is_stable_and_binds_dockerfile(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"; source.mkdir()
            for relative in record.BUILD_INPUTS:
                target = source / relative; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            first = record.build_input_sha256(source)
            self.assertEqual(first, record.build_input_sha256(source))
            dockerfile = source / ".ci/prysm-mtls/Dockerfile"
            dockerfile.write_bytes(dockerfile.read_bytes() + b"\n# mutation\n")
            self.assertNotEqual(first, record.build_input_sha256(source))

    def test_boolean_source_lock_schema_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"; source.mkdir()
            for relative in (".ci/prysm-mtls/source.lock.json", *record.PATCHES.values()):
                target = source / relative; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            lock = source / ".ci/prysm-mtls/source.lock.json"
            value = json.loads(lock.read_text()); value["schema_version"] = True; lock.write_text(json.dumps(value))
            with self.assertRaises(record.PrysmPublicationRecordError): record.source_identity(source)

    def test_cli_writes_once_and_rejects_bad_target_without_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "records"; directory.mkdir(mode=0o700)
            output = directory / "prysm-mtls-publication-record.json"
            command = [sys.executable, str(ROOT / "scripts/release/prysm_publication_record.py"),
                       "--source-root", str(ROOT), "--release-revision", SHA, "--build-revision", SHA,
                       "--input-sha256", record.build_input_sha256(ROOT), "--aws-account-id", TARGET["aws_account_id"],
                       "--aws-region", TARGET["aws_region"], "--deployment-name", TARGET["deployment_name"],
                       "--repository", TARGET["repository"], "--image-ref", TARGET["image_ref"],
                       "--manifest-digest", DIGEST, "--run-id", "42", "--output", str(output)]
            self.assertEqual(subprocess.run(command, text=True, capture_output=True).returncode, 0)
            before = output.read_bytes()
            self.assertNotEqual(subprocess.run(command, text=True, capture_output=True).returncode, 0)
            self.assertEqual(output.read_bytes(), before)
            bad = command.copy(); bad[bad.index("--repository") + 1] = "unexpected-repository"
            bad[-1] = str(directory / "bad-prysm-mtls-publication-record.json")
            self.assertNotEqual(subprocess.run(bad, text=True, capture_output=True).returncode, 0)
            self.assertFalse(Path(bad[-1]).exists())


if __name__ == "__main__":
    unittest.main()

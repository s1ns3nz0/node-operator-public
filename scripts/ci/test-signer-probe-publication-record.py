#!/usr/bin/env python3
# Check objective: Validate first-party signer-probe publication records.
"""Offline validation of first-party signer-probe publication records."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "release"))
import signer_probe_build_inputs as build_inputs
import signer_probe_publication_record as records

C = "c" * 40
D = "sha256:" + "d" * 64
ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
DEPLOYMENT = "node-operator"
REPOSITORY = f"{DEPLOYMENT}-baseline-validator-signer-identity-probe"
IMAGE = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{REPOSITORY}@{D}"


class SignerProbePublicationRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.source = Path(self.temporary.name) / "source"; self.source.mkdir()
        for relative in build_inputs.INPUT_PATHS:
            target = self.source / relative; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create(self) -> dict:
        return records.create_record(self.source, release_revision=C, build_revision=C,
            input_sha256=build_inputs.signer_probe_input_sha256(self.source), aws_account_id=ACCOUNT,
            aws_region=REGION, deployment_name=DEPLOYMENT, repository=REPOSITORY,
            image_ref=IMAGE, manifest_digest=D, run_id="42")

    def test_valid_first_party_record_binds_exact_local_inputs(self) -> None:
        record = self.create()
        self.assertEqual(record["component"], "validator-signer-identity-probe")
        self.assertIsNone(record["third_party_source_revision"])
        self.assertEqual(record["image_ref"], IMAGE)
        self.assertEqual(record["verification"], {"method": "cosign-and-slsa", "status": "passed"})
        self.assertEqual(records.validate_record(record, self.source, expected_release_revision=C), record)
        changed = self.source / build_inputs.INPUT_PATHS[0]
        changed.write_bytes(changed.read_bytes() + b"\nchanged\n")
        with self.assertRaises(records.SignerProbePublicationRecordError):
            records.validate_record(record, self.source)

    def test_wrong_identity_publication_and_context_reject(self) -> None:
        for key, value in (("component", "fence"), ("kind", "chart"), ("release_revision", "e" * 40),
                           ("build_revision", "e" * 40), ("third_party_source_revision", C),
                           ("manifest_digest", "sha256:" + "e" * 64), ("image_ref", IMAGE.replace(REPOSITORY, "other"))):
            record = self.create(); record[key] = value
            with self.subTest(key=key), self.assertRaises(records.SignerProbePublicationRecordError):
                records.validate_record(record, self.source, expected_release_revision=C)
        for run in (0, True, "0", "bad"):
            record = self.create(); record["publication"]["run_id"] = run
            with self.subTest(run=run), self.assertRaises(records.SignerProbePublicationRecordError):
                records.validate_record(record, self.source)
        with self.assertRaises(records.SignerProbePublicationRecordError):
            records.create_record(self.source, release_revision=C, build_revision=C,
                input_sha256=build_inputs.signer_probe_input_sha256(self.source), aws_account_id=ACCOUNT,
                aws_region=REGION, deployment_name=DEPLOYMENT, repository=REPOSITORY,
                image_ref=IMAGE, manifest_digest=D, run_id="42", invocation="wrong")

    def test_strict_file_loader_rejects_malformed_duplicate_and_symlink_records(self) -> None:
        path = Path(self.temporary.name) / "record.json"
        path.write_text(json.dumps(self.create()))
        self.assertEqual(records.load_and_validate(path, self.source)["image_ref"], IMAGE)
        path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaises(records.SignerProbePublicationRecordError):
            records.load_and_validate(path, self.source)
        path.unlink(); path.symlink_to("missing.json")
        with self.assertRaises(records.SignerProbePublicationRecordError):
            records.load_and_validate(path, self.source)


if __name__ == "__main__":
    unittest.main(verbosity=2)

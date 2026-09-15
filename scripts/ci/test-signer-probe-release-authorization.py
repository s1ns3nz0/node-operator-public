#!/usr/bin/env python3
# Check objective: Validate signer-probe candidate-to-release authorization evidence.
"""Offline C-to-R authorization checks for signer-probe publication records."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "release"))
import signer_probe_build_inputs as inputs
import signer_probe_publication_record as record_module
import signer_probe_release_authorization as authorization

CANDIDATE = "c" * 40
RELEASE = "d" * 40
ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
DEPLOYMENT = "node-operator"
DIGEST = "sha256:" + "e" * 64
REPOSITORY = f"{DEPLOYMENT}-baseline-validator-signer-identity-probe"
IMAGE = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{REPOSITORY}@{DIGEST}"


class SignerProbeReleaseAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temporary.name) / "bundle"
        self.source = self.bundle / "source"; (self.source / "release").mkdir(parents=True)
        self.rendered = self.bundle / "rendered"; self.rendered.mkdir()
        for relative in inputs.INPUT_PATHS:
            output = self.source / relative; output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, output)
        self.write_bundle()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def raw(value: object) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"

    def write_bundle(self) -> None:
        record = record_module.create_record(self.source, release_revision=CANDIDATE, build_revision=CANDIDATE,
            input_sha256=inputs.signer_probe_input_sha256(self.source), aws_account_id=ACCOUNT, aws_region=REGION,
            deployment_name=DEPLOYMENT, repository=REPOSITORY, image_ref=IMAGE, manifest_digest=DIGEST, run_id="42")
        record_raw = self.raw(record)
        auth = {"schema_version": 1, "candidate_revision": CANDIDATE,
                "record_sha256": hashlib.sha256(record_raw).hexdigest(),
                "publication": {"repository": "s1ns3nz0/node-operator", "workflow": "image-publish.yml", "run_id": "42", "artifact_id": "7"},
                "target": {"image_ref": IMAGE, "manifest_digest": DIGEST, "input_sha256": record["input_sha256"]},
                "approvals": {"stage_approved": True}}
        paths = {authorization.AUTH_PATH: self.raw(auth), authorization.RECORD_PATH: record_raw}
        for relative, raw in paths.items():
            destination = self.bundle / relative
            if destination.is_symlink():
                destination.unlink()
            destination.write_bytes(raw)
        entries = [{"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)} for path, raw in paths.items()]
        for relative in inputs.INPUT_PATHS:
            raw = (self.source / relative).read_bytes()
            entries.append({"path": f"source/{relative}", "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)})
        manifest = {"schema_version": "v1", "artifact": {"name": "bundle", "media_type": "application/x-tar"}, "source_revision": RELEASE, "entries": entries}
        (self.bundle / "bundle-manifest.json").write_bytes(self.raw(manifest))

    def assert_valid_release(self) -> None:
        self.assertEqual(
            authorization.validate_release_authorization(self.bundle, RELEASE, "stage")["record"]["image_ref"],
            IMAGE,
        )

    def test_candidate_to_release_binding_is_valid_only_for_stage(self) -> None:
        self.assertEqual(authorization.validate_authorization(json.loads((self.bundle / authorization.AUTH_PATH).read_text()))["candidate_revision"], CANDIDATE)
        value = authorization.validate_release_authorization(self.bundle, RELEASE, "stage")
        self.assertEqual(value["candidate_revision"], CANDIDATE)
        self.assertEqual(value["release_revision"], RELEASE)
        with self.assertRaises(authorization.SignerProbeReleaseAuthorizationError):
            authorization.validate_release_authorization(self.bundle, RELEASE, "activation")

    def test_parent_alias_is_canonicalized_after_rejecting_a_leaf_symlink(self) -> None:
        alias_parent = self.bundle.parent / "bundle-parent-alias"
        alias_parent.symlink_to(self.bundle.parent, target_is_directory=True)
        value = authorization.validate_release_authorization(alias_parent / self.bundle.name, RELEASE, "stage")
        self.assertEqual(value["record"]["image_ref"], IMAGE)
        root_alias = self.bundle.parent / "bundle-root-alias"
        root_alias.symlink_to(self.bundle, target_is_directory=True)
        with self.assertRaises(authorization.SignerProbeReleaseAuthorizationError):
            authorization.validate_release_authorization(root_alias, RELEASE, "stage")

    def test_every_populated_parent_symlink_rejects_after_a_valid_baseline(self) -> None:
        self.assert_valid_release()
        for relative in ("source", "source/release", "rendered"):
            with self.subTest(relative=relative):
                self.write_bundle()
                self.assert_valid_release()
                path = self.bundle / relative
                replacement = self.bundle.parent / (relative.replace("/", "-") + "-target")
                path.rename(replacement)
                path.symlink_to(replacement, target_is_directory=True)
                with self.assertRaises(authorization.SignerProbeReleaseAuthorizationError):
                    authorization.validate_release_authorization(self.bundle, RELEASE, "stage")
                path.unlink()
                replacement.rename(path)

    def test_raw_source_identity_and_authorization_fields_fail_closed(self) -> None:
        auth_path = self.bundle / authorization.AUTH_PATH
        record_path = self.bundle / authorization.RECORD_PATH
        auth = json.loads(auth_path.read_text()); record = json.loads(record_path.read_text())
        for field, value in (("record_sha256", "a" * 64), ("candidate_revision", "a" * 40)):
            changed = dict(auth); changed[field] = value
            with self.subTest(field=field), self.assertRaises(authorization.SignerProbeReleaseAuthorizationError):
                authorization.validate_candidate_authorization(changed, record, record_path.read_bytes(), self.source)
        for field, value in (("run_id", "43"), ("artifact_id", "0")):
            changed = json.loads(json.dumps(auth)); changed["publication"][field] = value
            with self.subTest(field=field), self.assertRaises(authorization.SignerProbeReleaseAuthorizationError):
                authorization.validate_candidate_authorization(changed, record, record_path.read_bytes(), self.source)
        for field, value in (("image_ref", IMAGE.replace(REPOSITORY, "other")), ("manifest_digest", "sha256:" + "a" * 64)):
            changed = json.loads(json.dumps(auth)); changed["target"][field] = value
            with self.subTest(field=field), self.assertRaises(authorization.SignerProbeReleaseAuthorizationError):
                authorization.validate_candidate_authorization(changed, record, record_path.read_bytes(), self.source)
        changed = json.loads(json.dumps(auth)); changed["target"]["image_ref"] = IMAGE.rsplit("@", 1)[0] + "@sha256:" + "a" * 64
        with self.assertRaises(authorization.SignerProbeReleaseAuthorizationError):
            authorization.validate_authorization(changed)
        changed_input = self.source / inputs.INPUT_PATHS[0]; changed_input.write_bytes(changed_input.read_bytes() + b"\nchanged\n")
        with self.assertRaises(authorization.SignerProbeReleaseAuthorizationError):
            authorization.validate_candidate_authorization(auth, record, record_path.read_bytes(), self.source)

    def test_manifest_duplicate_orphan_and_symlink_layouts_reject(self) -> None:
        record_path = self.bundle / authorization.RECORD_PATH
        record_path.write_bytes(record_path.read_bytes() + b" ")
        with self.assertRaises(authorization.SignerProbeReleaseAuthorizationError):
            authorization.validate_release_authorization(self.bundle, RELEASE, "stage")
        self.write_bundle()
        self.assert_valid_release()
        (self.bundle / authorization.AUTH_PATH).write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaises(authorization.SignerProbeReleaseAuthorizationError):
            authorization.validate_release_authorization(self.bundle, RELEASE, "stage")
        self.write_bundle()
        self.assert_valid_release()
        (self.bundle / authorization.AUTH_PATH).unlink()
        with self.assertRaises(authorization.SignerProbeReleaseAuthorizationError):
            authorization.validate_release_authorization(self.bundle, RELEASE, "stage")
        self.write_bundle()
        self.assert_valid_release()
        auth_path = self.bundle / authorization.AUTH_PATH; auth_path.unlink(); auth_path.symlink_to("missing.json")
        with self.assertRaises(authorization.SignerProbeReleaseAuthorizationError):
            authorization.validate_release_authorization(self.bundle, RELEASE, "stage")
        self.write_bundle()
        self.assert_valid_release()
        auth = json.loads((self.bundle / authorization.AUTH_PATH).read_text()); auth["approvals"]["stage_approved"] = False
        record = json.loads((self.bundle / authorization.RECORD_PATH).read_text())
        with self.assertRaises(authorization.SignerProbeReleaseAuthorizationError):
            authorization.validate_candidate_authorization(auth, record, (self.bundle / authorization.RECORD_PATH).read_bytes(), self.source)
        self.write_bundle()
        self.assert_valid_release()
        auth = json.loads((self.bundle / authorization.AUTH_PATH).read_text()); auth.pop("approvals")
        record = json.loads((self.bundle / authorization.RECORD_PATH).read_text())
        with self.assertRaises(authorization.SignerProbeReleaseAuthorizationError):
            authorization.validate_candidate_authorization(auth, record, (self.bundle / authorization.RECORD_PATH).read_bytes(), self.source)
        self.write_bundle()
        self.assert_valid_release()
        (self.source / inputs.INPUT_PATHS[1]).write_bytes(b"changed source without corresponding manifest entry")
        with self.assertRaises(authorization.SignerProbeReleaseAuthorizationError):
            authorization.validate_release_authorization(self.bundle, RELEASE, "stage")
        self.write_bundle()
        self.assert_valid_release()
        manifest_path = self.bundle / "bundle-manifest.json"; manifest = json.loads(manifest_path.read_text())
        manifest["entries"][0]["size"] += 1; manifest_path.write_bytes(self.raw(manifest))
        with self.assertRaises(authorization.SignerProbeReleaseAuthorizationError):
            authorization.validate_release_authorization(self.bundle, RELEASE, "stage")


if __name__ == "__main__":
    unittest.main(verbosity=2)

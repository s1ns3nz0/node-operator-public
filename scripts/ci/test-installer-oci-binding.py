#!/usr/bin/env python3
# Check objective: Bind OCI reconstruction to authenticated release metadata and reject unbound approval inputs.
"""Offline transport binding tests; authentication itself is a caller boundary."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
import installer_oci_binding as binding
from installer_oci_payload import prepare_payload


def sha(data):
    return hashlib.sha256(data).hexdigest()


class BindingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.bundle = self.root / "bundle"
        (self.bundle / "rendered").mkdir(parents=True)
        (self.bundle / "source").mkdir()
        (self.bundle / "source/approval.json").write_text("approved fixture")
        layout = self.root / "layout"
        (layout / "blobs/sha256").mkdir(parents=True)
        (layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')

        def blob(value, media_type):
            data = json.dumps(value).encode()
            digest = sha(data)
            (layout / "blobs/sha256" / digest).write_bytes(data)
            return {"digest": "sha256:" + digest, "size": len(data), "mediaType": media_type}

        config = blob({}, "application/vnd.oci.image.config.v1+json")
        descriptor = blob({"schemaVersion": 2, "config": config, "layers": []},
                          "application/vnd.oci.image.manifest.v1+json")
        (layout / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [descriptor]}))
        self.payload = self.root / "payload"
        prepare_payload({"app": (layout, descriptor["digest"])}, self.payload)
        (self.bundle / binding.PAYLOAD_MEMBER).write_bytes((self.payload / "payload-manifest.json").read_bytes())
        self.inventory = {"schema_version": 1, "complete": True, "unresolved_authority": [],
                          "artifacts": [{"component": "app", "required": True,
                                         "status": "source-approved", "authority": "fixture",
                                         "source": "registry.example/app@" + descriptor["digest"],
                                         "destination": "destination.example/app@" + descriptor["digest"]}]}
        self.revision = "a" * 40
        self.bind()

    def bind(self, mutate=None):
        entries = [{"path": str(path.relative_to(self.bundle)), "sha256": sha(path.read_bytes()),
                    "size": path.stat().st_size} for path in self.bundle.rglob("*")
                   if path.is_file() and path.name != "bundle-manifest.json"]
        manifest = {"schema_version": "v1", "source_revision": self.revision, "entries": entries}
        if mutate:
            mutate(manifest)
        data = json.dumps(manifest).encode()
        (self.bundle / "bundle-manifest.json").write_bytes(data)
        self.authenticated = sha(data)

    def verify(self):
        return binding.verify_bound_payload(self.bundle, self.revision, self.payload,
            expected_bundle_manifest_sha256=self.authenticated, account="000000000000",
            region="ap-northeast-2", deployment_name="release-check", reconstruct_dir=self.root / "restored")

    def test_bound_roundtrip(self):
        with patch.object(binding, "build_inventory", return_value=self.inventory) as inventory:
            self.assertEqual(self.verify()["verified_roots"], 1)
            inventory.assert_called_once()
        self.assertTrue((self.root / "restored/oci/app/index.json").is_file())

    def test_wrong_authenticated_hash(self):
        self.authenticated = "b" * 64
        self.assert_early_failure()

    def assert_early_failure(self):
        with patch.object(binding, "build_inventory") as inventory:
            with self.assertRaises((binding.BindingError, OSError)):
                self.verify()
            inventory.assert_not_called()
        self.assertFalse((self.root / "restored").exists())

    def test_tampered_bound_source(self):
        (self.bundle / "source/approval.json").write_text("tampered")
        self.assert_early_failure()

    def test_unbound_source_rejected_before_inventory(self):
        (self.bundle / "source/extra-approval.json").write_text("unbound")
        self.assert_early_failure()

    def test_payload_manifest_swap(self):
        (self.payload / "payload-manifest.json").write_text("{}")
        self.assert_early_failure()

    def test_duplicate_missing_and_unsafe_members(self):
        for mutate in (
            lambda value: value["entries"].append(value["entries"][0]),
            lambda value: value.update(entries=[]),
            lambda value: value["entries"][0].update(path="../escape"),
        ):
            with self.subTest(mutate=mutate):
                self.bind(mutate)
                self.assert_early_failure()

    def test_unbound_directory_symlink(self):
        (self.bundle / "external").symlink_to(self.root / "layout", target_is_directory=True)
        self.assert_early_failure()

    def test_other_approved_root_is_not_reconstructed(self):
        artifact = self.inventory["artifacts"][0]
        artifact["source"] = artifact["destination"] = "registry.example/app@sha256:" + "b" * 64
        with patch.object(binding, "build_inventory", return_value=self.inventory):
            with self.assertRaises(ValueError):
                self.verify()
        self.assertFalse((self.root / "restored").exists())

    def test_context_requires_payload_for_new_release(self):
        with self.assertRaises(binding.BindingError):
            with binding.payload_context(self.bundle, self.revision, {}, self.root, None, None):
                self.fail("must not fall back to a remote registry")

    def test_local_env_is_not_release_authority(self):
        (self.bundle / "env").write_text("REGION=ap-northeast-2\n")
        with patch.object(binding, "build_inventory", return_value=self.inventory):
            self.assertEqual(self.verify()["verified_roots"], 1)

    def test_context_cleans_only_owned_reconstruction(self):
        discovery = {"aws_account_id": "000000000000", "aws_region": "ap-northeast-2", "deployment_name": "release-check"}
        with patch.object(binding, "build_inventory", return_value=self.inventory):
            with binding.payload_context(self.bundle, self.revision, discovery, self.root, self.payload, self.authenticated) as layouts:
                self.assertTrue((layouts / "app/index.json").is_file())
            self.assertFalse(layouts.exists())
        self.assertTrue((self.payload / "payload-manifest.json").is_file())

    def test_context_cleans_after_mirror_exception(self):
        discovery = {"aws_account_id": "000000000000", "aws_region": "ap-northeast-2", "deployment_name": "release-check"}
        with patch.object(binding, "build_inventory", return_value=self.inventory):
            with self.assertRaisesRegex(RuntimeError, "downstream"):
                with binding.payload_context(self.bundle, self.revision, discovery, self.root, self.payload, self.authenticated) as layouts:
                    raise RuntimeError("downstream")
            self.assertFalse(layouts.exists())
        self.assertTrue((self.payload / "payload-manifest.json").is_file())


if __name__ == "__main__":
    unittest.main()

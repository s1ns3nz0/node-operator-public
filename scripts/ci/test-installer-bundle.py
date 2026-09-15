#!/usr/bin/env python3
# Check objective: Reject malformed release assets and verify bundle evidence binding offline.
"""Synthetic, offline tests for scripts/release/installer_bundle.py."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
SPEC = importlib.util.spec_from_file_location("installer_bundle", ROOT / "scripts/release/installer_bundle.py")
assert SPEC and SPEC.loader
bundle = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bundle
SPEC.loader.exec_module(bundle)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class InstallerBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp())
        self.download = self.temp / "download"
        self.download.mkdir()
        self.revision = "0" * 40
        self.contents = {"rendered/example.yaml": b"apiVersion: v1\n", "source/release.txt": b"review me\n"}
        self.executable_entries = set()
        self._write_release()

    def tearDown(self):
        shutil.rmtree(self.temp)

    def _manifest(self):
        return {"schema_version": "v1", "artifact": {"name": bundle.ARCHIVE_NAME, "media_type": "application/x-tar"}, "source_revision": self.revision,
                "entries": [{"path": name, "sha256": sha(data), "size": len(data)} for name, data in sorted(self.contents.items())]}

    def _write_tar(self, extra=None, symlink=False):
        archive = self.download / bundle.ARCHIVE_NAME
        manifest_bytes = (json.dumps(self._manifest()) + "\n").encode()
        with tarfile.open(archive, "w") as tar:
            values = {**self.contents, "bundle-manifest.json": manifest_bytes}
            if extra:
                values.update(extra)
            for name, data in values.items():
                item = tarfile.TarInfo(name)
                item.size = len(data)
                if name in self.executable_entries:
                    item.mode = 0o755
                tar.addfile(item, io.BytesIO(data))
            if symlink:
                item = tarfile.TarInfo("bad-link")
                item.type = tarfile.SYMTYPE
                item.linkname = "target"
                tar.addfile(item)
        return archive

    def _write_release(self):
        inner = self._manifest()
        archive = self._write_tar()
        digest = "sha256:" + sha(archive.read_bytes())
        outer = {**inner, "artifact": {**inner["artifact"], "digest": digest}}
        (self.download / "manifest.json").write_text(json.dumps(outer) + "\n")
        (self.download / "node-operator-release-bundle.sha256").write_text(f"{digest}  {bundle.ARCHIVE_NAME}\n")
        provenance = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": bundle.ARCHIVE_NAME, "digest": {"sha256": digest[7:]}}], "predicateType": "https://slsa.dev/provenance/v1", "predicate": {"buildDefinition": {"resolvedDependencies": [{"uri": "git+node-operator", "digest": {"gitCommit": self.revision}}]}, "runDetails": {"builder": {"id": "local://node-operator/scripts/ci/build-release-bundle.sh"}}}}
        raw = json.dumps(provenance).encode()
        (self.download / "provenance-input.json").write_bytes(raw)
        verification = {"schema_version": "v1", "artifact": {"name": bundle.ARCHIVE_NAME, "digest": digest}, "provenance": {"sha256": "sha256:" + sha(raw), "subject_digest": digest, "source_revision": self.revision, "builder_id": "local://node-operator/scripts/ci/build-release-bundle.sh"}, "transit": {"key": "node-operator-release", "signature": "vault:v1:fixture", "verified": True}, "signer": {"auth_method": "aws", "vault_role": "release-signer"}, "codebuild": {"build_id": "fixture"}}
        (self.download / "release-verification.json").write_text(json.dumps(verification))
        sbom = {"bomFormat": "CycloneDX", "metadata": {"component": {"name": bundle.ARCHIVE_NAME, "version": digest}}}
        (self.download / "sbom.cyclonedx.json").write_text(json.dumps(sbom))

    def test_valid_release_returns_tar_digest_and_canonical_manifest_digest(self):
        context = bundle.verify_release(self.download)
        self.assertEqual(context["release_sha"], self.revision)
        self.assertEqual(context["bundle_digest"], "sha256:" + sha((self.download / bundle.ARCHIVE_NAME).read_bytes()))
        self.assertTrue(context["manifest_digest"].startswith("sha256:"))

    def test_corrupt_tar_is_rejected(self):
        with (self.download / bundle.ARCHIVE_NAME).open("ab") as handle:
            handle.write(b"corrupt")
        with self.assertRaises(bundle.ReleaseVerificationError):
            bundle.verify_release(self.download)

    def test_traversal_manifest_entry_is_rejected(self):
        manifest = self.download / "manifest.json"
        value = json.loads(manifest.read_text())
        value["entries"][0]["path"] = "../escape"
        manifest.write_text(json.dumps(value))
        with self.assertRaises(bundle.ReleaseVerificationError):
            bundle.verify_release(self.download)

    def test_duplicate_json_key_is_rejected(self):
        (self.download / "manifest.json").write_text('{"schema_version":"v1","schema_version":"v1"}')
        with self.assertRaises(bundle.ReleaseVerificationError):
            bundle.verify_release(self.download)

    def test_tar_symlink_is_rejected(self):
        archive = self._write_tar(symlink=True)
        manifest = self._manifest()
        outer = {**manifest, "artifact": {**manifest["artifact"], "digest": "sha256:" + sha(archive.read_bytes())}}
        with self.assertRaises(bundle.ReleaseVerificationError):
            bundle.verify_bundle(archive, outer, outer["artifact"]["digest"])

    def _materialize(self, name="installed"):
        context = bundle.verify_release(self.download)
        return bundle.materialize_release(self.download, self.temp.resolve() / name, context["release_sha"], context["bundle_digest"])

    def test_materialize_valid_bundle_is_private_and_idempotently_reusable(self):
        destination = self._materialize()
        self.assertEqual((destination / "rendered/example.yaml").read_bytes(), self.contents["rendered/example.yaml"])
        self.assertTrue((destination / "bundle-manifest.json").is_file())
        self.assertEqual((destination.stat().st_mode & 0o777), 0o700)
        self.assertEqual(((destination / "rendered/example.yaml").stat().st_mode & 0o777), 0o600)
        context = bundle.verify_release(self.download)
        self.assertEqual(bundle.materialize_release(self.download, destination, context["release_sha"], context["bundle_digest"]), destination)

    def test_materialize_rejects_wrong_context_without_creating_destination(self):
        destination = self.temp.resolve() / "not-created"
        with self.assertRaises(bundle.ReleaseVerificationError):
            bundle.materialize_release(self.download, destination, "1" * 40, "sha256:" + "0" * 64)
        self.assertFalse(destination.exists())

    def test_materialize_rejects_tampered_reused_tree_and_unexpected_file(self):
        destination = self._materialize()
        (destination / "source/release.txt").write_text("tampered")
        context = bundle.verify_release(self.download)
        with self.assertRaises(bundle.ReleaseVerificationError):
            bundle.materialize_release(self.download, destination, context["release_sha"], context["bundle_digest"])
        (destination / "source/release.txt").write_bytes(self.contents["source/release.txt"])
        (destination / "unexpected").write_text("no")
        with self.assertRaises(bundle.ReleaseVerificationError):
            bundle.materialize_release(self.download, destination, context["release_sha"], context["bundle_digest"])

    def test_materialize_rejects_symlink_destination_and_unsafe_ancestor(self):
        context = bundle.verify_release(self.download)
        base = self.temp.resolve()
        target = base / "target"
        target.mkdir()
        linked = base / "linked"
        linked.symlink_to(target, target_is_directory=True)
        with self.assertRaises(bundle.ReleaseVerificationError):
            bundle.materialize_release(self.download, linked, context["release_sha"], context["bundle_digest"])
        parent_target = base / "parent-target"
        parent_target.mkdir()
        unsafe_parent = base / "unsafe-parent"
        unsafe_parent.symlink_to(parent_target, target_is_directory=True)
        with self.assertRaises(bundle.ReleaseVerificationError):
            bundle.materialize_release(self.download, unsafe_parent / "installed", context["release_sha"], context["bundle_digest"])

    def test_materialize_rejects_modified_file_mode_on_reuse(self):
        destination = self._materialize()
        output = destination / "rendered/example.yaml"
        output.chmod(0o700)
        context = bundle.verify_release(self.download)
        with self.assertRaises(bundle.ReleaseVerificationError):
            bundle.materialize_release(self.download, destination, context["release_sha"], context["bundle_digest"])

    def test_materialize_rejects_symlink_inside_reused_tree(self):
        destination = self._materialize()
        output = destination / "source/release.txt"
        output.unlink()
        output.symlink_to(destination / "rendered/example.yaml")
        context = bundle.verify_release(self.download)
        with self.assertRaises(bundle.ReleaseVerificationError):
            bundle.materialize_release(self.download, destination, context["release_sha"], context["bundle_digest"])

    def test_materialize_preserves_only_executable_semantics(self):
        self.executable_entries = {"source/release.txt"}
        self._write_release()
        destination = self._materialize()
        self.assertEqual(((destination / "source/release.txt").stat().st_mode & 0o777), 0o700)

    def test_materialize_rejects_extra_empty_directory(self):
        destination = self._materialize()
        (destination / "unrecorded").mkdir(mode=0o700)
        context = bundle.verify_release(self.download)
        with self.assertRaises(bundle.ReleaseVerificationError):
            bundle.materialize_release(self.download, destination, context["release_sha"], context["bundle_digest"])

    def test_materialize_rejects_reused_tree_through_symlink_ancestor(self):
        destination = self._materialize()
        alias = self.temp.resolve() / "alias"
        alias.symlink_to(destination.parent, target_is_directory=True)
        context = bundle.verify_release(self.download)
        with self.assertRaises(bundle.ReleaseVerificationError):
            bundle.materialize_release(self.download, alias / destination.name, context["release_sha"], context["bundle_digest"])

    def test_materialize_does_not_replace_destination_created_at_publish(self):
        import installer_files
        original = installer_files.publish_directory
        observed = {}
        def race(source, destination):
            destination.mkdir(mode=0o700)
            observed["inode"] = destination.stat().st_ino
            return original(source, destination)
        with patch.object(installer_files, "publish_directory", side_effect=race), self.assertRaises(bundle.ReleaseVerificationError):
            self._materialize("raced")
        destination = self.temp.resolve() / "raced"
        self.assertEqual(destination.stat().st_ino, observed["inode"])
        self.assertEqual(list(destination.iterdir()), [])


if __name__ == "__main__":
    unittest.main()

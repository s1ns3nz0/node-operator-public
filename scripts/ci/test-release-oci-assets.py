#!/usr/bin/env python3
# Check objective: Permit only complete digest-bound OCI assets before any release publication call.
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
from release_oci_assets import assets

spec = importlib.util.spec_from_file_location("payload_fixture", Path(__file__).with_name("test-installer-oci-payload.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class AssetTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.TestPayload()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.root = self.fixture.tmp
        self.fixture.prepare()
        self.payload = self.root / "payload"
        self.bundle = self.root / "release/node-operator-release-bundle.tar"
        self.bundle.parent.mkdir()
        self.pack()
        directory = self.bundle.parent
        (directory / "signer-output").mkdir()
        (directory / "node-operator-release-bundle.sha256").write_text(self.digest + "  " + self.bundle.name + "\n")
        (directory / "manifest.json").write_text(json.dumps({"artifact": {"digest": self.digest}}))
        (directory / "sbom.cyclonedx.json").write_text(json.dumps({"metadata": {"component": {"version": self.digest}}}))
        provenance = json.dumps({"subject": [{"name": self.bundle.name, "digest": {"sha256": self.digest[7:]}}]}).encode()
        (directory / "provenance-input.json").write_bytes(provenance)
        (directory / "signer-output/release-verification.json").write_text(json.dumps({"artifact": {"name": self.bundle.name, "digest": self.digest}, "provenance": {"sha256": "sha256:" + hashlib.sha256(provenance).hexdigest()}}))

    def pack(self, bound=True, duplicate=False):
        with tarfile.open(self.bundle, "w") as archive:
            if bound:
                raw = (self.payload / "payload-manifest.json").read_bytes()
                for _ in range(2 if duplicate else 1):
                    item = tarfile.TarInfo("rendered/installer-oci-payload-manifest.json")
                    item.size = len(raw)
                    archive.addfile(item, io.BytesIO(raw))
        self.digest = "sha256:" + hashlib.sha256(self.bundle.read_bytes()).hexdigest()

    def test_complete_graph_yields_only_chunk_paths(self):
        result = assets(self.bundle, self.digest, self.payload)
        self.assertTrue(result)
        self.assertTrue(all(path.parent == self.payload / "chunks" for path in result))

    def test_missing_payload_and_wrong_approved_digest_rejected(self):
        for digest, payload in ((self.digest, None), ("sha256:" + "0" * 64, self.payload)):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                assets(self.bundle, digest, payload)

    def test_legacy_cannot_upload_unbound_payload(self):
        self.pack(bound=False)
        self.assertEqual(assets(self.bundle, self.digest, None), [])
        with self.assertRaises(ValueError):
            assets(self.bundle, self.digest, self.payload)

    def test_duplicate_or_substituted_manifest_rejected(self):
        self.pack(duplicate=True)
        with self.assertRaises(ValueError):
            assets(self.bundle, self.digest, self.payload)
        self.pack()
        path = self.payload / "payload-manifest.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(ValueError):
            assets(self.bundle, self.digest, self.payload)

    def test_duplicate_or_excessive_chunks_rejected_before_graph_work(self):
        path = self.payload / "payload-manifest.json"
        original = json.loads(path.read_bytes())
        for count in (2, 995):
            manifest = dict(original, chunks=[original["chunks"][0]] * count)
            path.write_text(json.dumps(manifest))
            self.pack()
            with patch("release_oci_assets.verify_payload") as verify, self.assertRaises(ValueError):
                assets(self.bundle, self.digest, self.payload)
            verify.assert_not_called()

    def test_corrupt_graph_blocks_shell_before_remote_write(self):
        binary = self.root / "bin"
        binary.mkdir()
        marker = self.root / "gh-called.json"
        gh = binary / "gh"
        gh.write_text("#!/usr/bin/env python3\nimport json,os,sys\nfrom pathlib import Path\nPath(os.environ['TEST_GH_MARKER']).write_text(json.dumps(sys.argv[1:]))\n")
        gh.chmod(0o700)
        environment = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"],
            RUNNER_TEMP=str(self.root), GITHUB_REF_NAME="v0.2.0", APPROVED_ARTIFACT_DIGEST=self.digest,
            OCI_PAYLOAD_DIR=str(self.payload), TEST_GH_MARKER=str(marker))
        command = ["bash", str(ROOT / "scripts/release/create-github-release.sh")]
        good = subprocess.run(command, env=environment, capture_output=True)
        self.assertEqual(good.returncode, 0, good.stderr.decode())
        arguments = json.loads(marker.read_text())
        self.assertIn(str(next((self.payload / "chunks").iterdir())), arguments)
        marker.unlink()
        sbom = self.bundle.parent / "sbom.cyclonedx.json"
        saved = sbom.read_bytes()
        for mode in ("missing", "substituted", "symlink"):
            if sbom.exists() or sbom.is_symlink():
                sbom.unlink()
            if mode == "substituted":
                sbom.write_text('{}')
            elif mode == "symlink":
                sbom.symlink_to(self.bundle.parent / "manifest.json")
            rejected = subprocess.run(command, env=environment, capture_output=True)
            self.assertNotEqual(rejected.returncode, 0, mode)
            self.assertFalse(marker.exists())
        sbom.unlink()
        sbom.write_bytes(saved)
        next((self.payload / "chunks").iterdir()).write_bytes(b"corrupted")
        bad = subprocess.run(command, env=environment, capture_output=True)
        self.assertNotEqual(bad.returncode, 0)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()

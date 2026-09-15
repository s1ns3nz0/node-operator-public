#!/usr/bin/env python3
# Check objective: Authenticate downloaded releases and OCI chunks before exposing executable installer files.
"""Fake HTTP transport with real OpenSSL, tar and OCI verification."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import unittest
from unittest.mock import patch
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
import installer_release_download as download
from installer_oci_payload import prepare_payload
spec = importlib.util.spec_from_file_location("signature_fixture", Path(__file__).with_name("test-installer-release-signature.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.signed = fixture.SignatureTests("test_real_signature_binds_manifest")
        self.signed.setUp()
        self.addCleanup(self.signed.doCleanups)
        self.root = self.signed.root
        self.output = self.root / "downloaded"
        layout = self.root / "layout"
        (layout / "blobs/sha256").mkdir(parents=True)
        (layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
        def blob(value, media):
            raw = json.dumps(value).encode()
            digest = hashlib.sha256(raw).hexdigest()
            (layout / "blobs/sha256" / digest).write_bytes(raw)
            return {"mediaType": media, "digest": "sha256:" + digest, "size": len(raw)}
        config = blob({}, "application/vnd.oci.image.config.v1+json")
        root = blob({"schemaVersion": 2, "config": config, "layers": []}, "application/vnd.oci.image.manifest.v1+json")
        (layout / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [root]}))
        self.payload = self.root / "payload"
        prepare_payload({"app": (layout, root["digest"])}, self.payload)
        payload_raw = (self.payload / "payload-manifest.json").read_bytes()
        manifest = json.loads(self.signed.manifest)
        self.entrypoint = "source/scripts/release/node-operator-install.sh"
        manifest["entries"][0]["path"] = self.entrypoint
        manifest["entries"].append({"path": download.PAYLOAD_MEMBER, "size": len(payload_raw), "sha256": hashlib.sha256(payload_raw).hexdigest()})
        self.signed.manifest = json.dumps(manifest).encode()
        with tarfile.open(self.root / "node-operator-release-bundle.tar", "w") as archive:
            for name, raw in (("bundle-manifest.json", self.signed.manifest), (self.entrypoint, self.signed.script), (download.PAYLOAD_MEMBER, payload_raw)):
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                member.mode = 0o755 if name == self.entrypoint else 0o600
                archive.addfile(member, io.BytesIO(raw))
        self.signed.sign()
        self.inventory = {"schema_version": 1, "complete": True, "unresolved_authority": [],
            "artifacts": [{"component": "app", "required": True, "status": "source-approved", "authority": "synthetic-fixture",
                "source": "example.invalid/app@" + root["digest"], "destination": "example.invalid/app@" + root["digest"]}]}
        self.urls = []

    def fetch(self, url, destination, maximum):
        self.urls.append(url)
        name = url.rsplit("/", 1)[-1]
        source = self.payload / "chunks" / name if name.startswith("oci-payload-") else self.root / name
        raw = source.read_bytes()
        self.assertLessEqual(len(raw), maximum)
        destination.write_bytes(raw)

    def prepare(self):
        with patch.object(download, "_download", side_effect=self.fetch), patch("installer_oci_binding.build_inventory", return_value=self.inventory):
            return download.prepare_release("v0.2.0", self.output, self.signed.revision,
                trusted_public_key=self.signed.public, trusted_key_sha256=self.signed.key_hash)

    def test_real_crypto_and_payload_roundtrip(self):
        result = self.prepare()
        self.assertEqual(result["verified_roots"], 1)
        self.assertTrue((self.output / "bundle" / self.entrypoint).is_file())
        self.assertTrue((self.output / "authenticated-release.json").is_file())
        self.assertTrue(all(url.startswith("https://github.com/s1ns3nz0/node-operator/releases/download/v0.2.0/") for url in self.urls))

    def test_bad_signature_stops_before_chunk_download(self):
        path = self.root / "provenance-input.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(len(self.urls), 3)
        self.assertFalse(self.output.exists())

    def test_signed_duplicate_payload_key_stops_before_chunk_download(self):
        raw = (self.payload / "payload-manifest.json").read_bytes()
        raw = b'{"chunks":[],' + raw.lstrip()[1:]
        manifest = json.loads(self.signed.manifest)
        entry = next(item for item in manifest["entries"] if item["path"] == download.PAYLOAD_MEMBER)
        entry.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        with tarfile.open(self.root / "node-operator-release-bundle.tar", "w") as archive:
            for name, data in (("bundle-manifest.json", json.dumps(manifest).encode()),
                               (self.entrypoint, self.signed.script), (download.PAYLOAD_MEMBER, raw)):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = 0o755 if name == self.entrypoint else 0o600
                archive.addfile(member, io.BytesIO(data))
        self.signed.sign()
        with self.assertRaisesRegex(ValueError, "duplicate metadata key"):
            self.prepare()
        self.assertEqual(len(self.urls), 3)
        self.assertFalse(self.output.exists())

    def test_corrupt_chunk_does_not_publish_partial_release(self):
        chunk = next((self.payload / "chunks").iterdir())
        raw = chunk.read_bytes()
        chunk.write_bytes(b"X" + raw[1:])
        with self.assertRaises(download.DownloadError):
            self.prepare()
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob(".release-download-*")))

    def test_stream_bounds_and_no_authorization_header(self):
        class Response(io.BytesIO):
            status = 200
            headers = {}
        opener = Mock()
        opener.open.return_value = Response(b"oversized")
        with patch.object(download.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(download.DownloadError):
                download._download("https://github.com/example", self.root / "too-large", 3)
        request = opener.open.call_args.args[0]
        self.assertIsNone(request.get_header("Authorization"))

    def test_redirect_does_not_downgrade_or_leave_asset_hosts(self):
        handler = download._ReleaseRedirect()
        for url in ("http://github.com/file", "https://example.invalid/file", "https://github.com:8443/file", "https://user:pass@github.com/file"):
            with self.subTest(url=url), self.assertRaises(download.DownloadError):
                handler.redirect_request(None, None, 302, "", {}, url)

    def test_verified_process_handoff_preserves_token_and_passes_payload(self):
        verified = self.prepare()
        with patch.dict(os.environ, {"GITHUB_TOKEN": "preserve-fixture"}), patch.object(download.os, "execve") as execute:
            download.launch_installer(verified)
            self.assertEqual(execute.call_args.args[0], self.output / "bundle" / self.entrypoint)
            environment = execute.call_args.args[2]
            self.assertEqual(environment["GITHUB_TOKEN"], "preserve-fixture")
            self.assertEqual(environment["NODE_OPERATOR_OCI_PAYLOAD_DIR"], str(self.output / "oci-payload"))
            self.assertEqual(environment["NODE_OPERATOR_AUTHENTICATED_BUNDLE_MANIFEST_SHA256"], verified["authenticated_bundle_manifest_sha256"])

    def test_cli_is_nonexecuting_by_default_and_bounds_launch_failure(self):
        arguments = ["download", "--tag", "v0.2.0", "--destination", str(self.output),
                     "--expected-revision", self.signed.revision,
                     "--trusted-public-key", str(self.signed.public),
                     "--trusted-key-sha256", self.signed.key_hash]
        with patch.object(download, "prepare_release", return_value={}), \
             patch.object(download, "launch_installer", side_effect=OSError("private fixture detail")) as launch, \
             patch("sys.stdout", new_callable=io.StringIO), \
             patch("sys.stderr", new_callable=io.StringIO) as stderr:
            with patch("sys.argv", arguments):
                self.assertEqual(download.main(), 0)
                launch.assert_not_called()
            with patch("sys.argv", arguments + ["--launch"]):
                self.assertEqual(download.main(), 69)
                launch.assert_called_once()
                self.assertIn("Verified files remain", stderr.getvalue())
                self.assertNotIn("private fixture detail", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

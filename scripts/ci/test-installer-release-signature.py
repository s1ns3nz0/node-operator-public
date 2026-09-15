#!/usr/bin/env python3
# Check objective: Verify real offline release signatures and reject altered bundles, provenance and untrusted keys.
"""Real OpenSSL crypto fixtures; no live Vault or AWS access."""
import base64
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
from installer_release_signature import SignatureError, verify_release, extract_verified_bundle


def sha(value):
    return hashlib.sha256(value).hexdigest()


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.revision = "a" * 40
        self.private = self.root / "fixture-private.pem"
        self.public = self.root / "public.pem"
        self.command("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(self.private))
        self.command("openssl", "ec", "-in", str(self.private), "-pubout", "-out", str(self.public))
        self.key_hash = sha(self.public.read_bytes())
        self.make_bundle()
        self.sign()

    def command(self, *arguments):
        return subprocess.run(arguments, check=True, capture_output=True, timeout=30)

    def make_bundle(self, duplicate=False, symlink=False):
        self.script = b"#!/bin/sh\nprintf 'fixture only\\n'\n"
        self.manifest = json.dumps({"schema_version": "v1", "source_revision": self.revision,
            "entries": [{"path": "source/install.sh", "sha256": sha(self.script), "size": len(self.script)}]}).encode()
        with tarfile.open(self.root / "node-operator-release-bundle.tar", "w") as archive:
            member = tarfile.TarInfo("bundle-manifest.json")
            member.size = len(self.manifest)
            if symlink:
                member.type = tarfile.SYMTYPE
                member.linkname = "elsewhere"
            archive.addfile(member, io.BytesIO(self.manifest) if not symlink else None)
            if duplicate:
                archive.addfile(member, io.BytesIO(self.manifest))
            script = tarfile.TarInfo("source/install.sh")
            script.mode = 0o755
            script.size = len(self.script)
            archive.addfile(script, io.BytesIO(self.script))

    def sign(self, builder="local://node-operator/scripts/ci/build-release-bundle.sh",
             build_type="https://node-operator.example/release-bundle/v1"):
        digest = sha((self.root / "node-operator-release-bundle.tar").read_bytes())
        self.provenance = {"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": "node-operator-release-bundle.tar", "digest": {"sha256": digest}}],
            "predicate": {"buildDefinition": {"buildType": build_type, "resolvedDependencies": [{"uri": "git+node-operator", "digest": {"gitCommit": self.revision}}]},
                          "runDetails": {"builder": {"id": builder}}}}
        raw = json.dumps(self.provenance).encode()
        (self.root / "provenance-input.json").write_bytes(raw)
        self.command("openssl", "dgst", "-sha256", "-sign", str(self.private), "-out", str(self.root / "fixture.sig"), str(self.root / "provenance-input.json"))
        signature = "vault:v1:" + base64.b64encode((self.root / "fixture.sig").read_bytes()).decode()
        result = {"schema_version": "v1", "artifact": {"name": "node-operator-release-bundle.tar", "digest": "sha256:" + digest},
            "provenance": {"sha256": "sha256:" + sha(raw), "subject_digest": "sha256:" + digest, "source_revision": self.revision, "builder_id": builder},
            "transit": {"key": "node-operator-release", "signature": signature, "verified": True}}
        (self.root / "release-verification.json").write_text(json.dumps(result))

    def verify(self, **kwargs):
        return verify_release(self.root, kwargs.get("revision", self.revision), trusted_public_key=kwargs.get("key", self.public), trusted_key_sha256=kwargs.get("key_hash", self.key_hash))

    def test_real_signature_binds_manifest(self):
        self.assertEqual(self.verify()["authenticated_bundle_manifest_sha256"], sha(self.manifest))

    def test_valid_signature_with_unapproved_builder_contract_is_rejected(self):
        for kwargs in ({"builder": "unexpected-builder"}, {"build_type": "unexpected-build-type"}):
            with self.subTest(kwargs=kwargs):
                self.sign(**kwargs)
                with self.assertRaisesRegex(SignatureError, "builder contract"):
                    self.verify()

    def test_changed_provenance_not_rescued_by_result_claim(self):
        self.provenance["predicate"]["runDetails"]["builder"]["id"] = "attacker"
        (self.root / "provenance-input.json").write_text(json.dumps(self.provenance))
        with self.assertRaises(SignatureError):
            self.verify()

    def test_changed_bundle(self):
        with (self.root / "node-operator-release-bundle.tar").open("ab") as handle:
            handle.write(b"changed")
        with self.assertRaises(SignatureError):
            self.verify()

    def test_wrong_revision_and_trust_hash(self):
        for kwargs in ({"revision": "b" * 40}, {"key_hash": "b" * 64}):
            with self.subTest(kwargs=kwargs), self.assertRaises(SignatureError):
                self.verify(**kwargs)

    def test_wrong_public_key_and_private_key_rejected(self):
        other_private = self.root / "other.pem"
        other_public = self.root / "other.pub"
        self.command("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(other_private))
        self.command("openssl", "pkey", "-in", str(other_private), "-pubout", "-out", str(other_public))
        for key in (other_public, self.private):
            with self.subTest(key=key.name), self.assertRaises(SignatureError):
                self.verify(key=key, key_hash=sha(key.read_bytes()))

    def test_signed_duplicate_or_symlink_manifest_rejected(self):
        for options in ({"duplicate": True}, {"symlink": True}):
            self.make_bundle(**options)
            self.sign()
            with self.subTest(options=options), self.assertRaises(SignatureError):
                self.verify()

    def test_duplicate_metadata_key_rejected(self):
        path = self.root / "release-verification.json"
        path.write_text('{"schema_version":"v1",' + path.read_text()[1:])
        with self.assertRaises(SignatureError):
            self.verify()

    def extract(self):
        return extract_verified_bundle(self.root, self.root / "extracted", self.revision,
            trusted_public_key=self.public, trusted_key_sha256=self.key_hash)

    def test_verified_extraction_preserves_safe_executable(self):
        self.extract()
        script = self.root / "extracted/source/install.sh"
        self.assertEqual(script.read_bytes(), self.script)
        self.assertEqual(script.stat().st_mode & 0o777, 0o700)
        with self.assertRaises(SignatureError):
            self.extract()

    def test_signed_unbound_file_cannot_escape_or_publish(self):
        with tarfile.open(self.root / "node-operator-release-bundle.tar", "a") as archive:
            extra = tarfile.TarInfo("../outside")
            extra.size = 1
            archive.addfile(extra, io.BytesIO(b"x"))
        self.sign()
        with self.assertRaises(SignatureError):
            self.extract()
        self.assertFalse((self.root / "extracted").exists())
        self.assertFalse((self.root / "outside").exists())

    def test_signed_wrong_member_hash_cannot_publish(self):
        with tarfile.open(self.root / "node-operator-release-bundle.tar", "w") as archive:
            for name, raw in (("bundle-manifest.json", self.manifest), ("source/install.sh", b"x" * len(self.script))):
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
        self.sign()
        with self.assertRaises(SignatureError):
            self.extract()
        self.assertFalse((self.root / "extracted").exists())


if __name__ == "__main__":
    unittest.main()

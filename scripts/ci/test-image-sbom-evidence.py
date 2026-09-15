#!/usr/bin/env python3
# Check objective: Reject incomplete or tampered image SBOM and archive evidence.
"""Offline tests for local Docker-archive SBOM evidence receipts."""
import importlib.util
import io
import hashlib
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/image_sbom_evidence.py"
SPEC = importlib.util.spec_from_file_location("image_sbom_evidence", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)
REVISION = "a" * 40
CONFIG = "sha256:" + "b" * 64


def sbom(archive_sha: str) -> dict:
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "metadata": {"tools": [{"vendor": "anchore", "name": "syft", "version": "test"}], "component": {"type": "file", "name": "subject", "version": "sha256:" + archive_sha}},
        "components": [
            {"type": "file", "name": "/usr/bin/example", "hashes": [{"alg": "SHA-256", "content": "a" * 64}]},
            {"type": "operating-system", "name": "debian", "version": "13"},
            {"type": "library", "name": "openssl", "version": "3.0", "purl": "pkg:apk/alpine/openssl@3.0"},
        ],
    }


def docker_archive(path: Path, members: list[tuple[tarfile.TarInfo, bytes]], duplicate_manifest: bool = False, duplicate_layer: bool = False, layers=None) -> None:
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as contents:
        for member, content in members:
            contents.addfile(member, io.BytesIO(content) if member.isreg() else None)
    manifest = json.dumps([{"Config": "config.json", "RepoTags": [], "Layers": ["layer.tar"] if layers is None else layers}]).encode()
    with tarfile.open(path, mode="w") as archive:
        outer = [("manifest.json", manifest), ("layer.tar", layer.getvalue())]
        if duplicate_manifest:
            outer.append(("manifest.json", manifest))
        if duplicate_layer:
            outer.append(("layer.tar", layer.getvalue()))
        for name, value in outer:
            info = tarfile.TarInfo(name); info.size = len(value)
            archive.addfile(info, io.BytesIO(value))


class SbomEvidenceTests(unittest.TestCase):
    def test_actual_publication_opa_queries_fail_closed(self):
        # Exercise the query from each real publisher, not a test-only policy call.
        temp, archive, document, receipt = self.make()
        with temp:
            MODULE.create(archive, document, REVISION, CONFIG, "release-build", receipt)
            valid = json.loads(receipt.read_text())
            for publisher in ("publish-scanner-image.sh", "publish-toolchain-image.sh"):
                source = (ROOT / "scripts/release" / publisher).read_text()
                queries = re.findall(r"'(true = data\.nodeoperator\.image_sbom\.allow)'", source)
                self.assertEqual(len(queries), 1, publisher)
                denied = dict(valid, claims=dict(valid["claims"], signature=True))
                for value, allowed in ((valid, True), (denied, False), ({}, False)):
                    receipt.write_text(json.dumps(value))
                    result = subprocess.run([
                        "opa", "eval", "--fail", "--format", "json", "--data",
                        str(ROOT / "policy/image_sbom.rego"), "--input", str(receipt), queries[0],
                    ], capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode == 0, allowed, publisher + result.stdout + result.stderr)

    def make(self):
        temp = tempfile.TemporaryDirectory()
        base = Path(temp.name); archive = base / "image.tar"; archive.write_bytes(b"synthetic docker archive")
        digest = MODULE._sha256(archive, MODULE.MAX_ARCHIVE); document = base / "sbom.json"; document.write_text(json.dumps(sbom(digest)))
        return temp, archive, document, base / "receipt.json"

    def test_create_verify_and_cli(self):
        temp, archive, document, receipt = self.make()
        with temp:
            result = subprocess.run([sys.executable, str(SCRIPT), "create", "--archive", str(archive), "--sbom", str(document), "--revision", REVISION, "--image-config-digest", CONFIG, "--subject", "release-build", "--output", str(receipt)], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([sys.executable, str(SCRIPT), "verify", "--archive", str(archive), "--sbom", str(document), "--revision", REVISION, "--image-config-digest", CONFIG, "--subject", "release-build", "--receipt", str(receipt)], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_tampering_or_invalid_schema_fails_closed(self):
        temp, archive, document, receipt = self.make()
        with temp:
            MODULE.create(archive, document, REVISION, CONFIG, "release-build", receipt)
            archive.write_bytes(b"tampered")
            with self.assertRaises(MODULE.EvidenceError):
                MODULE.verify(archive, document, REVISION, CONFIG, "release-build", receipt)
            archive.write_bytes(b"synthetic docker archive")
            document.write_bytes(b"{}")
            with self.assertRaises(MODULE.EvidenceError):
                MODULE.verify(archive, document, REVISION, CONFIG, "release-build", receipt)
            document.write_text(json.dumps(sbom(MODULE._sha256(archive, MODULE.MAX_ARCHIVE))))
            with self.assertRaises(MODULE.EvidenceError):
                MODULE.verify(archive, document, "A" * 40, CONFIG, "release-build", receipt)
            receipt.write_text("{}")
            with self.assertRaises(MODULE.EvidenceError):
                MODULE.verify(archive, document, REVISION, CONFIG, "release-build", receipt)
            document.write_text('{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}')
            with self.assertRaises(MODULE.EvidenceError):
                MODULE.create(archive, document, REVISION, CONFIG, "release-build", receipt)

    def test_symlink_and_missing_component_identity_are_rejected(self):
        temp, archive, document, receipt = self.make()
        with temp:
            bad = sbom(MODULE._sha256(archive, MODULE.MAX_ARCHIVE)); bad["components"][2].pop("purl"); document.write_text(json.dumps(bad))
            with self.assertRaises(MODULE.EvidenceError):
                MODULE.create(archive, document, REVISION, CONFIG, "release-build", receipt)
            link = document.parent / "link.tar"; link.symlink_to(archive)
            with self.assertRaises(MODULE.EvidenceError):
                MODULE.create(link, document, REVISION, CONFIG, "release-build", receipt)

    def test_file_hash_must_be_a_valid_sha256(self):
        temp, archive, document, receipt = self.make()
        with temp:
            for hashes in ([{}], [{"alg": "SHA-256", "content": "invalid"}], []):
                bad = sbom(MODULE._sha256(archive, MODULE.MAX_ARCHIVE))
                bad["components"][0]["hashes"] = hashes
                document.write_text(json.dumps(bad))
                with self.assertRaises(MODULE.EvidenceError):
                    MODULE.create(archive, document, REVISION, CONFIG, "release-build", receipt)

    def test_hydrates_only_a_final_regular_file_component_from_the_same_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); archive = base / "image.tar"; member = tarfile.TarInfo("usr/share/keyrings/removed.gpg")
            member.size = 0; docker_archive(archive, [(member, b"")])
            document = base / "sbom.json"; value = sbom(MODULE._sha256(archive, MODULE.MAX_ARCHIVE))
            value["components"][0] = {"type": "file", "name": "/usr/share/keyrings/removed.gpg"}
            document.write_text(json.dumps(value))
            MODULE.hydrate_file_hashes(archive, document)
            self.assertEqual(json.loads(document.read_text())["components"][0]["hashes"], [{"alg": "SHA-256", "content": hashlib.sha256(b"").hexdigest()}])
            link = tarfile.TarInfo("usr/share/keyrings/removed.gpg"); link.type = tarfile.SYMTYPE; link.linkname = "elsewhere"
            docker_archive(archive, [(link, b"")]); document.write_text(json.dumps(value))
            with self.assertRaises(MODULE.EvidenceError):
                MODULE.hydrate_file_hashes(archive, document)

    def test_hydration_rejects_nonempty_ancestor_whiteout_and_duplicate_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); archive = base / "image.tar"; document = base / "sbom.json"
            value = sbom("a" * 64); value["components"][0] = {"type": "file", "name": "/usr/share/keyrings/removed.gpg"}
            def regular(name: str, content: bytes = b""):
                member = tarfile.TarInfo(name); member.size = len(content); return member, content
            link = tarfile.TarInfo("usr"); link.type = tarfile.SYMTYPE; link.linkname = "elsewhere"
            cases = (
                ([(regular("usr/share/keyrings/removed.gpg", b"not-empty"))], {}),
                ([(regular(".wh.usr"))], {}),
                ([(link, b"")], {}),
                ([(regular("usr/share/keyrings/removed.gpg")), (regular("usr/share/keyrings/removed.gpg"))], {}),
                ([(regular("usr/share/keyrings/removed.gpg")), (regular("usr/share/keyrings/.wh.removed.gpg")), (regular("usr/share/keyrings/removed.gpg"))], {}),
                ([(regular("usr/share/keyrings/removed.gpg"))], {"duplicate_manifest": True}),
                ([(regular("usr/share/keyrings/removed.gpg"))], {"duplicate_layer": True}),
                ([(regular("usr/share/keyrings/removed.gpg"))], {"layers": ["layer.tar", {"invalid": True}]}),
            )
            for members, kwargs in cases:
                with self.subTest(kwargs=kwargs, entries=len(members)):
                    docker_archive(archive, members, **kwargs); document.write_text(json.dumps(value))
                    with self.assertRaises(MODULE.EvidenceError):
                        MODULE.hydrate_file_hashes(archive, document)


if __name__ == "__main__":
    unittest.main()

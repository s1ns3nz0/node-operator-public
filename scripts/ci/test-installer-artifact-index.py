#!/usr/bin/env python3
# Check objective: Release artifact indexes are deterministic, release-bound, private, and never overwrite staged evidence.
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/release/create-installer-artifact-index.py"
CATALOG = ROOT / ".ci/gitops/approved-oci-artifacts.json"
SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64


def record(component, method, **changes):
    value = {"schema_version": 1, "component": component, "kind": "image", "release_revision": SHA, "build_revision": "c" * 40, "third_party_source_revision": None, "image_ref": f"example.invalid/{component}@{DIGEST}", "manifest_digest": DIGEST, "input_sha256": "d" * 64, "publication": {"workflow": "release", "run_id": "123", "invocation": "fixture"}, "verification": {"method": method, "status": "passed"}}
    value.update(changes)
    return value


class ArtifactIndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.private = self.base / "private"; self.private.mkdir(mode=0o700)
        self.bootstrap = self.base / "bootstrap.json"; self.relay = self.base / "relay.json"; self.gitops_oci_mirror = self.base / "gitops-oci-mirror.json"
        self._write_records()

    def tearDown(self): self.tmp.cleanup()
    def _write_records(self, bootstrap=None, relay=None, gitops_oci_mirror=None):
        self.bootstrap.write_text(json.dumps(bootstrap or record("vault-bootstrap", "input-hash-and-registry-digest")))
        self.relay.write_text(json.dumps(relay or record("vault-audit-relay", "cosign-and-slsa")))
        self.gitops_oci_mirror.write_text(json.dumps(gitops_oci_mirror or record("gitops-oci-mirror", "input-hash-and-registry-digest")))
    def invoke(self, output=None, catalog=CATALOG):
        return subprocess.run([str(SCRIPT), "--release-sha", SHA, "--approved-catalog", str(catalog), "--vault-bootstrap-record", str(self.bootstrap), "--audit-relay-record", str(self.relay), "--gitops-oci-mirror-record", str(self.gitops_oci_mirror), "--output", str(output or self.private / "installer-artifact-index.json")], text=True, capture_output=True)
    def test_deterministic_complete_index(self):
        one = self.private / "installer-artifact-index.json"; self.assertEqual(self.invoke(one).returncode, 0)
        two_dir = self.base / "private-two"; two_dir.mkdir(mode=0o700); two = two_dir / one.name
        self.assertEqual(self.invoke(two).returncode, 0); self.assertEqual(one.read_bytes(), two.read_bytes())
        index = json.loads(one.read_text()); self.assertEqual(index["release_revision"], SHA); self.assertEqual(len(index["components"]), 11)
        self.assertEqual(index["components"]["vault-bootstrap"]["build_revision"], "c" * 40)
        self.assertIsNone(index["components"]["vault-bootstrap"]["third_party_source_revision"])
        self.assertEqual(index["components"]["vault-server"]["image_ref"].split("@", 1)[1], index["components"]["vault-server"]["manifest_digest"])
        self.assertEqual(one.stat().st_mode & 0o777, 0o600)
    def test_missing_or_wrong_dynamic_record_is_rejected(self):
        self.bootstrap.unlink(); self.assertNotEqual(self.invoke().returncode, 0)
        self._write_records(bootstrap=record("vault-bootstrap", "input-hash-and-registry-digest", release_revision="e" * 40)); self.assertNotEqual(self.invoke().returncode, 0)
        self._write_records(); self.gitops_oci_mirror.unlink(); self.assertNotEqual(self.invoke().returncode, 0)
        wrong = record("gitops-oci-mirror", "input-hash-and-registry-digest"); wrong["component"] = "vault-bootstrap"
        self._write_records(gitops_oci_mirror=wrong); self.assertNotEqual(self.invoke().returncode, 0)
    def test_malformed_hash_and_untruthful_method_are_rejected(self):
        self._write_records(relay=record("vault-audit-relay", "cosign-and-slsa", input_sha256="bad")); self.assertNotEqual(self.invoke().returncode, 0)
        self._write_records(relay=record("vault-audit-relay", "input-hash-and-registry-digest")); self.assertNotEqual(self.invoke().returncode, 0)
    def test_ambiguous_catalog_and_historical_bootstrap_are_not_selected(self):
        catalog = json.loads(CATALOG.read_text()); catalog["artifacts"].append(dict(catalog["artifacts"][-1], source="docker.io/hashicorp/vault@" + DIGEST))
        path = self.base / "catalog.json"; path.write_text(json.dumps(catalog)); self.assertNotEqual(self.invoke(catalog=path).returncode, 0)
        self.assertEqual(self.invoke().returncode, 0)
        index = json.loads((self.private / "installer-artifact-index.json").read_text()); self.assertEqual(index["components"]["vault-bootstrap"]["image_ref"], record("vault-bootstrap", "input-hash-and-registry-digest")["image_ref"])
    def test_unsafe_output_and_no_overwrite_are_rejected(self):
        unsafe = self.base / "unsafe"; unsafe.mkdir(mode=0o755); self.assertNotEqual(self.invoke(unsafe / "installer-artifact-index.json").returncode, 0)
        output = self.private / "installer-artifact-index.json"; self.assertEqual(self.invoke(output).returncode, 0); before = output.read_bytes(); self.assertNotEqual(self.invoke(output).returncode, 0); self.assertEqual(output.read_bytes(), before)


if __name__ == "__main__": unittest.main()

#!/usr/bin/env python3
# Check objective: Select only complete and immutable release-approved OCI roots from local archives.
"""Check objective: Select only complete, immutable release-approved OCI roots."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
from installer_oci_selection import SelectionError, approved_roots, select_layouts

DIGEST = "sha256:" + "a" * 64


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.inventory = {"schema_version": 1, "complete": True, "unresolved_authority": [],
                          "artifacts": [{"component": "vault-server", "required": True,
                                         "status": "source-approved", "authority": "installer-artifact-index",
                                         "source": "registry.example/server@" + DIGEST,
                                         "destination": "destination.example/server@" + DIGEST}]}

    def layout(self, name):
        root = self.root / name
        (root / "blobs/sha256").mkdir(parents=True)
        (root / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
        (root / "blobs/sha256" / DIGEST[7:]).write_bytes(b"candidate only; payload verifier checks digest")
        return root

    def test_select_is_deterministic_and_does_not_approve_bytes(self):
        self.layout("z-layout")
        first = self.layout("a-layout")
        self.assertEqual(select_layouts(self.inventory, self.root), {"vault-server": (first, DIGEST)})

    def test_missing_authority_or_bytes_fails(self):
        with self.assertRaises(SelectionError):
            select_layouts(self.inventory, self.root)
        for field, value in (("complete", False), ("unresolved_authority", ["missing"])):
            record = copy.deepcopy(self.inventory)
            record[field] = value
            with self.assertRaises(SelectionError):
                approved_roots(record)

    def test_mismatch_duplicate_and_unsafe_name_fail(self):
        for changes in ({"destination": "dest/x@sha256:" + "b" * 64},
                        {"component": "../escape"}, {"source": "registry/x:latest"}):
            record = copy.deepcopy(self.inventory)
            record["artifacts"][0].update(changes)
            with self.assertRaises(SelectionError):
                approved_roots(record)
        self.inventory["artifacts"] *= 2
        with self.assertRaises(SelectionError):
            approved_roots(self.inventory)

    def test_chart_can_use_approved_destination_digest(self):
        self.inventory["artifacts"][0]["source"] = None
        self.assertEqual(approved_roots(self.inventory), {"vault-server": DIGEST})

    def test_symlink_manifest_is_rejected(self):
        layout = self.layout("layout")
        blob = layout / "blobs/sha256" / DIGEST[7:]
        blob.unlink()
        blob.symlink_to(layout / "oci-layout")
        with self.assertRaises(SelectionError):
            select_layouts(self.inventory, self.root)


if __name__ == "__main__":
    unittest.main()

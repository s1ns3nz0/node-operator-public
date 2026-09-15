#!/usr/bin/env python3
# Check objective: Verify release publication-record retrieval contracts.
"""Offline contract tests for fetch-release-publication-records.py."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/fetch-release-publication-records.py"
SHA = "a" * 40
RUN = "123"
DIGEST = "sha256:" + "b" * 64


def record(component: str, invocation: str, method: str, image_ref: str | None = None) -> bytes:
    return (json.dumps({"schema_version": 1, "component": component, "kind": "image",
        "release_revision": SHA, "build_revision": SHA, "third_party_source_revision": None,
        "image_ref": image_ref or f"ghcr.io/example/{component}@{DIGEST}", "manifest_digest": DIGEST,
        "input_sha256": "c" * 64,
        "publication": {"workflow": "image-publish.yml", "run_id": RUN, "invocation": invocation},
        "verification": {"method": method, "status": "passed"}}, sort_keys=True) + "\n").encode()


class FetchRecords(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.bin = self.root / "bin"; self.bin.mkdir()
        self.fixtures = self.root / "fixtures"; self.fixtures.mkdir()
        self.output = self.root / "records"
        self.write_fixtures()
        fake = self.bin / "gh"
        fake.write_text("#!/usr/bin/env python3\nimport os,pathlib,sys\nbase=pathlib.Path(os.environ['FAKE_GH_DIR'])\nif sys.argv[1:4] != ['api','--hostname','github.com']: raise SystemExit(92)\narg=sys.argv[-1]\nname={'repos/example/repo/actions/runs/123':'run.json','repos/example/repo/actions/runs/123/artifacts?per_page=100&page=1':'artifacts.json'}.get(arg)\nif name: sys.stdout.buffer.write((base/name).read_bytes()); raise SystemExit(0)\nif arg.startswith('repos/example/repo/actions/artifacts/') and arg.endswith('/zip'):\n sys.stdout.buffer.write((base/('artifact-'+arg.split('/')[-2]+'.zip')).read_bytes()); raise SystemExit(0)\nraise SystemExit(91)\n")
        fake.chmod(0o755)

    def tearDown(self): self.tmp.cleanup()

    def write_fixtures(self, *, run=None, artifacts=None, zips=None):
        run = run or {"id": 123, "repository": {"full_name": "example/repo"}, "head_repository": {"full_name": "example/repo"}, "head_sha": SHA, "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "success", "path": ".github/workflows/image-publish.yml@refs/heads/main"}
        artifacts = artifacts or {"total_count": 3, "artifacts": [{"id": 1, "name": f"toolchain-publication-record-vault-bootstrap-{SHA}", "expired": False, "workflow_run": {"id": 123, "head_sha": SHA}}, {"id": 2, "name": f"toolchain-publication-record-gitops-oci-mirror-{SHA}", "expired": False, "workflow_run": {"id": 123, "head_sha": SHA}}, {"id": 3, "name": "vault-audit-relay-release-evidence", "expired": False, "workflow_run": {"id": 123, "head_sha": SHA}}]}
        (self.fixtures / "run.json").write_text(json.dumps(run)); (self.fixtures / "artifacts.json").write_text(json.dumps(artifacts))
        zips = zips or {1: [("vault-bootstrap-publication-record.json", record("vault-bootstrap", "toolchain-publish", "input-hash-and-registry-digest"))], 2: [("gitops-oci-mirror-publication-record.json", record("gitops-oci-mirror", "toolchain-publish", "input-hash-and-registry-digest"))], 3: [("scan.json", b"{}"), ("vault-audit-relay-publication-record.json", record("vault-audit-relay", "relay-publish", "cosign-and-slsa"))]}
        for key, members in zips.items():
            with zipfile.ZipFile(self.fixtures / f"artifact-{key}.zip", "w") as archive:
                for name, contents in members: archive.writestr(name, contents)

    def invoke(self):
        env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"], FAKE_GH_DIR=str(self.fixtures), GH_TOKEN="not-to-be-echoed")
        return subprocess.run([str(SCRIPT), "--repository", "example/repo", "--source-sha", SHA, "--run-id", RUN, "--output-dir", str(self.output)], text=True, capture_output=True, env=env)

    def assert_fails(self):
        result = self.invoke(); self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr); self.assertFalse(self.output.exists()); self.assertNotIn("not-to-be-echoed", result.stdout + result.stderr)

    def test_fetches_exact_validated_records(self):
        result = self.invoke(); self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(item.name for item in self.output.iterdir()), ["gitops-oci-mirror-publication-record.json", "vault-audit-relay-publication-record.json", "vault-bootstrap-publication-record.json"])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(item.stat().st_mode) == 0o600 for item in self.output.iterdir()))

    def test_accepts_deployment_scoped_relay_repository_record(self):
        relay = record("vault-audit-relay", "relay-publish", "cosign-and-slsa", f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-example-baseline-vault-audit-relay@{DIGEST}")
        self.write_fixtures(zips={1: [("vault-bootstrap-publication-record.json", record("vault-bootstrap", "toolchain-publish", "input-hash-and-registry-digest"))], 2: [("gitops-oci-mirror-publication-record.json", record("gitops-oci-mirror", "toolchain-publish", "input-hash-and-registry-digest"))], 3: [("vault-audit-relay-publication-record.json", relay)]})
        self.assertEqual(self.invoke().returncode, 0)

    def test_rejects_untrusted_run_variants(self):
        for key, value in (("head_sha", "d" * 40), ("head_branch", "feature"), ("event", "pull_request"), ("conclusion", "failure"), ("head_repository", {"full_name": "fork/repo"})):
            with self.subTest(key=key):
                run = json.loads((self.fixtures / "run.json").read_text()); run[key] = value; self.write_fixtures(run=run); self.assert_fails()

    def test_accepts_plain_workflow_path_and_rejects_unknown_suffix(self):
        run = json.loads((self.fixtures / "run.json").read_text()); run["path"] = ".github/workflows/image-publish.yml"; self.write_fixtures(run=run)
        self.assertEqual(self.invoke().returncode, 0)
        shutil.rmtree(self.output)
        run["path"] += "@unexpected"; self.write_fixtures(run=run); self.assert_fails()

    def test_rejects_bad_artifact_metadata_and_archive_members(self):
        base = json.loads((self.fixtures / "artifacts.json").read_text())
        cases = [
            {"total_count": 4, "artifacts": base["artifacts"] + [base["artifacts"][0]]},
            {"total_count": 3, "artifacts": [{**item, "expired": True} if item["id"] == 1 else item for item in base["artifacts"]]},
            {"total_count": 3, "artifacts": [{**item, "workflow_run": {"id": 9}} if item["id"] == 1 else item for item in base["artifacts"]]},
            {"total_count": 3, "artifacts": [{**item, "workflow_run": {"id": 123, "head_sha": "d" * 40}} if item["id"] == 1 else item for item in base["artifacts"]]},
        ]
        for artifacts in cases:
            with self.subTest(artifacts=artifacts): self.write_fixtures(artifacts=artifacts); self.assert_fails()
        bad = {1: [("../vault-bootstrap-publication-record.json", record("vault-bootstrap", "toolchain-publish", "input-hash-and-registry-digest"))], 2: [("gitops-oci-mirror-publication-record.json", record("gitops-oci-mirror", "toolchain-publish", "input-hash-and-registry-digest")), ("gitops-oci-mirror-publication-record.json", b"{}")], 3: [("vault-audit-relay-publication-record.json", record("vault-audit-relay", "relay-publish", "cosign-and-slsa"))]}
        self.write_fixtures(zips=bad); self.assert_fails()
        relay_duplicate = {1: [("vault-bootstrap-publication-record.json", record("vault-bootstrap", "toolchain-publish", "input-hash-and-registry-digest"))], 2: [("gitops-oci-mirror-publication-record.json", record("gitops-oci-mirror", "toolchain-publish", "input-hash-and-registry-digest"))], 3: [("scan.json", b"{}"), ("scan.json", b"{}"), ("vault-audit-relay-publication-record.json", record("vault-audit-relay", "relay-publish", "cosign-and-slsa"))]}
        self.write_fixtures(zips=relay_duplicate); self.assert_fails()

    def test_rejects_record_mismatch_and_never_overwrites(self):
        bad = record("vault-bootstrap", "toolchain-publish", "input-hash-and-registry-digest").replace(SHA.encode(), ("d" * 40).encode())
        self.write_fixtures(zips={1: [("vault-bootstrap-publication-record.json", bad)], 2: [("gitops-oci-mirror-publication-record.json", record("gitops-oci-mirror", "toolchain-publish", "input-hash-and-registry-digest"))], 3: [("vault-audit-relay-publication-record.json", record("vault-audit-relay", "relay-publish", "cosign-and-slsa"))]}); self.assert_fails()
        self.write_fixtures(); self.output.mkdir(); (self.output / "sentinel").write_text("keep")
        result = self.invoke(); self.assertNotEqual(result.returncode, 0); self.assertEqual((self.output / "sentinel").read_text(), "keep")

    def test_rejects_malformed_zip_and_record_fields(self):
        (self.fixtures / "artifact-1.zip").write_bytes(b"not a ZIP")
        self.assert_fails()
        self.write_fixtures()
        bad = json.loads(record("vault-bootstrap", "toolchain-publish", "input-hash-and-registry-digest")); bad["verification"]["status"] = "failed"
        self.write_fixtures(zips={1: [("vault-bootstrap-publication-record.json", json.dumps(bad).encode())], 2: [("gitops-oci-mirror-publication-record.json", record("gitops-oci-mirror", "toolchain-publish", "input-hash-and-registry-digest"))], 3: [("vault-audit-relay-publication-record.json", record("vault-audit-relay", "relay-publish", "cosign-and-slsa"))]})
        self.assert_fails()


if __name__ == "__main__": unittest.main()

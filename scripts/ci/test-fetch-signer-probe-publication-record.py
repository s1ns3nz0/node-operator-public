#!/usr/bin/env python3
# Check objective: Verify signer-probe publication-record retrieval with fake GitHub data.
"""Offline, fake-GitHub tests for signer-probe publication-record retrieval."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "release"))
import signer_probe_build_inputs as inputs
import signer_probe_publication_record as record_module
import signer_probe_release_authorization as authorization

SCRIPT = ROOT / "scripts" / "ci" / "fetch-signer-probe-publication-record.py"
CANDIDATE = "c" * 40
RUN_ID = "42"
ARTIFACT_ID = "123"
ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
DEPLOYMENT = "node-operator"
REPOSITORY = f"{DEPLOYMENT}-baseline-validator-signer-identity-probe"
DIGEST = "sha256:" + "e" * 64
IMAGE = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{REPOSITORY}@{DIGEST}"
RECORD_NAME = "signer-identity-probe-publication-record.json"


class FetchSignerProbePublicationRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        for relative in inputs.INPUT_PATHS:
            destination = self.source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        self.fixtures = self.root / "fixtures"; self.fixtures.mkdir()
        self.bin = self.root / "bin"; self.bin.mkdir()
        self.authorization = self.root / "signer-probe-publication-authorization.json"
        self.output = self.root / "output"
        self.record = self._record()
        self.raw = json.dumps(self.record, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        self.write_fixtures()
        self._write_fake_gh()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _record(self) -> dict:
        return record_module.create_record(
            self.source, release_revision=CANDIDATE, build_revision=CANDIDATE,
            input_sha256=inputs.signer_probe_input_sha256(self.source), aws_account_id=ACCOUNT,
            aws_region=REGION, deployment_name=DEPLOYMENT, repository=REPOSITORY,
            image_ref=IMAGE, manifest_digest=DIGEST, run_id=RUN_ID,
        )

    def _auth(self, raw: bytes) -> dict:
        return {
            "schema_version": 1, "candidate_revision": CANDIDATE,
            "record_sha256": hashlib.sha256(raw).hexdigest(),
            "publication": {"repository": "s1ns3nz0/node-operator", "workflow": "image-publish.yml",
                            "run_id": RUN_ID, "artifact_id": ARTIFACT_ID},
            "target": {"image_ref": IMAGE, "manifest_digest": DIGEST,
                       "input_sha256": self.record["input_sha256"]},
            "approvals": {"stage_approved": True},
        }

    def write_fixtures(self, *, run: dict | None = None, artifacts: dict | None = None,
                       members: list[tuple[str, bytes]] | None = None, auth: dict | None = None,
                       member_type: int | None = stat.S_IFREG) -> None:
        run = run or {
            "id": int(RUN_ID), "repository": {"full_name": "s1ns3nz0/node-operator"},
            "head_repository": {"full_name": "s1ns3nz0/node-operator"}, "head_sha": CANDIDATE,
            "head_branch": "main", "event": "workflow_dispatch", "status": "completed",
            "conclusion": "success", "path": ".github/workflows/image-publish.yml",
        }
        artifacts = artifacts or {"total_count": 1, "artifacts": [{
            "id": int(ARTIFACT_ID), "name": f"signer-probe-publication-record-{CANDIDATE}",
            "expired": False, "workflow_run": {"id": int(RUN_ID), "head_sha": CANDIDATE},
        }]}
        members = members or [(RECORD_NAME, self.raw)]
        (self.fixtures / "run.json").write_text(json.dumps(run))
        (self.fixtures / "artifacts.json").write_text(json.dumps(artifacts))
        with zipfile.ZipFile(self.fixtures / "artifact.zip", "w") as archive:
            for name, raw in members:
                info = zipfile.ZipInfo(name); info.create_system = 3
                if member_type is not None:
                    info.external_attr = (member_type | 0o600) << 16
                archive.writestr(info, raw)
        self.authorization.write_text(json.dumps(auth or self._auth(self.raw)))

    def _write_fake_gh(self) -> None:
        fake = self.bin / "gh"
        fake.write_text("""#!/usr/bin/env python3
import os, pathlib, sys
base = pathlib.Path(os.environ['FAKE_GH_DIR'])
endpoint = sys.argv[-1]
if sys.argv[1:4] != ['api', '--hostname', 'github.com']: raise SystemExit(92)
pathlib.Path(os.environ['FAKE_GH_LOG']).open('a').write(endpoint + '\\n')
pathlib.Path(os.environ['FAKE_GH_TOKEN_LOG']).write_text(os.environ.get('GITHUB_TOKEN', ''))
names = {
 'repos/s1ns3nz0/node-operator/actions/runs/42': 'run.json',
 'repos/s1ns3nz0/node-operator/actions/runs/42/artifacts?per_page=100&page=1': 'artifacts.json',
 'repos/s1ns3nz0/node-operator/actions/artifacts/123/zip': 'artifact.zip',
}
name = names.get(endpoint)
if name is None: raise SystemExit(91)
sys.stdout.buffer.write((base / name).read_bytes())
""")
        fake.chmod(0o755)

    def invoke(self) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                           FAKE_GH_DIR=str(self.fixtures), FAKE_GH_LOG=str(self.root / "gh.log"),
                           FAKE_GH_TOKEN_LOG=str(self.root / "token.log"), GITHUB_TOKEN="test-token-preserved")
        return subprocess.run(
            [str(SCRIPT), "--authorization-path", str(self.authorization), "--source-root", str(self.source),
             "--output-dir", str(self.output)], text=True, capture_output=True, env=environment, timeout=20,
        )

    def assert_fails_without_output(self) -> None:
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.output.exists())
        self.assertNotIn("test-token-preserved", result.stdout + result.stderr)

    def test_retrieves_exact_authorized_candidate_record(self) -> None:
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.output / RECORD_NAME
        self.assertEqual(record.read_bytes(), self.raw)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
        self.assertEqual((self.root / "token.log").read_text(), "test-token-preserved")

    def test_rejects_wrong_run_and_artifact_binding(self) -> None:
        baseline_run = json.loads((self.fixtures / "run.json").read_text())
        baseline_artifacts = json.loads((self.fixtures / "artifacts.json").read_text())
        cases = [
            ("wrong source", {**baseline_run, "head_sha": "d" * 40}, baseline_artifacts),
            ("wrong branch", {**baseline_run, "head_branch": "feature"}, baseline_artifacts),
            ("wrong event", {**baseline_run, "event": "pull_request"}, baseline_artifacts),
            ("wrong conclusion", {**baseline_run, "conclusion": "failure"}, baseline_artifacts),
            ("wrong artifact id", baseline_run, {"total_count": 1, "artifacts": [{**baseline_artifacts["artifacts"][0], "id": 124}]}),
            ("wrong name", baseline_run, {"total_count": 1, "artifacts": [{**baseline_artifacts["artifacts"][0], "name": "other"}]}),
            ("expired", baseline_run, {"total_count": 1, "artifacts": [{**baseline_artifacts["artifacts"][0], "expired": True}]}),
            ("duplicate name", baseline_run, {"total_count": 2, "artifacts": baseline_artifacts["artifacts"] * 2}),
        ]
        for label, run, artifacts in cases:
            with self.subTest(label=label):
                self.write_fixtures(run=run, artifacts=artifacts)
                self.assert_fails_without_output()

    def test_rejects_tampered_source_hash_and_unsafe_zip(self) -> None:
        bad_auth = self._auth(self.raw); bad_auth["record_sha256"] = "f" * 64
        self.write_fixtures(auth=bad_auth); self.assert_fails_without_output()
        self.write_fixtures(); bad_record = dict(self.record); bad_record["source_revision"] = "d" * 40
        bad_raw = json.dumps(bad_record, sort_keys=True).encode() + b"\n"
        self.write_fixtures(members=[(RECORD_NAME, bad_raw)], auth=self._auth(bad_raw)); self.assert_fails_without_output()
        self.write_fixtures(members=[("../" + RECORD_NAME, self.raw)]); self.assert_fails_without_output()
        self.write_fixtures(member_type=None); self.assertEqual(self.invoke().returncode, 0)
        shutil.rmtree(self.output)
        self.write_fixtures(member_type=stat.S_IFLNK); self.assert_fails_without_output()
        self.write_fixtures(members=[(RECORD_NAME, self.raw), ("other.json", b"{}")]); self.assert_fails_without_output()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            self.write_fixtures(members=[(RECORD_NAME, self.raw), (RECORD_NAME, self.raw)])
        self.assert_fails_without_output()
        self.write_fixtures()
        changed = self.source / inputs.INPUT_PATHS[0]
        changed.write_bytes(changed.read_bytes() + b"\nchanged-after-publication\n")
        self.assert_fails_without_output()

    def test_rejects_unsafe_authorization_and_output_collision_before_gh(self) -> None:
        self.authorization.write_text('{"schema_version":1,"schema_version":1}')
        self.assert_fails_without_output()
        self.assertFalse((self.root / "gh.log").exists(), "invalid authorization must fail before GitHub access")
        self.write_fixtures(); bad = self._auth(self.raw); bad["approvals"]["stage_approved"] = False
        self.write_fixtures(auth=bad); self.assert_fails_without_output()
        self.assertFalse((self.root / "gh.log").exists(), "unauthorized stage must fail before GitHub access")
        self.write_fixtures(); self.output.mkdir(); (self.output / "sentinel").write_text("keep")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.output / "sentinel").read_text(), "keep")


if __name__ == "__main__":
    unittest.main(verbosity=2)

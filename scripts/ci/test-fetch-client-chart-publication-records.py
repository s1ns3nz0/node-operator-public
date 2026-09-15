#!/usr/bin/env python3
# Check objective: Verify client-chart publication-record retrieval with fake GitHub data.
"""Offline fake-GitHub checks for client-chart evidence retrieval."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "release"))
import client_chart_release_authorization as authz

SCRIPT = ROOT / "scripts" / "ci" / "fetch-client-chart-publication-records.py"
SOURCE = "1848c9d37b3bba99fc18eb9e0bed8b53bac39998"; RUN = "34657770665"; ARTIFACT = "10285458234"; NUMBER = "37"
MANIFEST = "sha256:" + "a" * 64; ARCHIVE = "sha256:" + "b" * 64
IMAGE = f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-client/node-operator-client@{MANIFEST}"


class FetchClientChartTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name).resolve()
        self.fixtures = self.root / "fixtures"; self.fixtures.mkdir(); self.bin = self.root / "bin"; self.bin.mkdir()
        self.output = self.root / "output"; self.authorization = self.root / "authorization.json"
        self.evidence = self._evidence(); self._write(self.evidence); self._fake_gh()

    def tearDown(self) -> None: self.temp.cleanup()

    def _evidence(self, image: str = IMAGE, subject_digest: str = MANIFEST) -> dict[str, bytes]:
        predicate = {"buildDefinition": {"buildType": "https://node-operator.example/gitops-chart/v1", "resolvedDependencies": [{"uri": "git+https://github.com/s1ns3nz0/node-operator-gitops", "digest": {"gitCommit": SOURCE}}]}, "runDetails": {"builder": {"id": authz.BUILDER}}}
        statement = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": image.rsplit("@", 1)[0], "digest": {"sha256": subject_digest.split(":", 1)[1]}}], "predicateType": "https://slsa.dev/provenance/v1", "predicate": predicate}
        values = {
            authz.NAMES[0]: {"schema_version": "v1", "oci_digest": MANIFEST, "chart_archive_digest": ARCHIVE, "chart_version": "0.1.37"},
            authz.NAMES[1]: {"bomFormat": "CycloneDX", "metadata": {"component": {"name": "node-operator-client-0.1.37.tgz", "version": ARCHIVE}, "tools": {"components": [{"name": "syft"}]}}},
            authz.NAMES[2]: {"matches": [], "ignoredMatches": [], "descriptor": {"name": "grype", "version": "1", "db": {"status": {"valid": True}}, "configuration": {"ignore": ["accepted"], "exclude": [], "only-fixed": False, "only-notfixed": False, "show-suppressed": True}}, "source": {"type": "file", "target": "node-operator-client-0.1.37.tgz"}},
            authz.NAMES[3]: predicate,
            authz.NAMES[4]: {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()).decode(), "signatures": [{"sig": "test"}]},
        }
        return {name: json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n" for name, value in values.items()}

    def _write(self, evidence: dict[str, bytes], *, image: str = IMAGE, run: dict | None = None, artifacts: dict | None = None, members: list[tuple[str, bytes]] | None = None) -> None:
        hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in evidence.items()}
        value = {"schema_version": 1, "source_revision": SOURCE, "publication": {"repository": authz.REPOSITORY, "workflow": authz.WORKFLOW, "run_id": RUN, "artifact_id": ARTIFACT, "artifact_name": "gitops-chart-evidence-node-operator-redeploy-20260912b", "run_number": NUMBER}, "target": {"image_ref": image, "manifest_digest": MANIFEST, "chart_archive_digest": ARCHIVE, "chart_version": "0.1.37"}, "evidence_sha256": hashes, "approvals": {"stage_approved": True, "activation_approved": False}}
        self.authorization.write_text(json.dumps(value, sort_keys=True))
        run = run or {"id": int(RUN), "run_number": int(NUMBER), "repository": {"full_name": authz.REPOSITORY}, "head_repository": {"full_name": authz.REPOSITORY}, "head_sha": SOURCE, "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "success", "path": ".github/workflows/publish-oci.yml"}
        artifacts = artifacts or {"total_count": 1, "artifacts": [{"id": int(ARTIFACT), "name": value["publication"]["artifact_name"], "expired": False, "workflow_run": {"id": int(RUN), "head_sha": SOURCE}}]}
        (self.fixtures / "run.json").write_text(json.dumps(run)); (self.fixtures / "artifacts.json").write_text(json.dumps(artifacts))
        with zipfile.ZipFile(self.fixtures / "artifact.zip", "w") as archive:
            for name, raw in members or list(evidence.items()):
                info = zipfile.ZipInfo(name); info.create_system = 3; info.external_attr = (stat.S_IFREG | 0o600) << 16; archive.writestr(info, raw)

    def _fake_gh(self) -> None:
        fake = self.bin / "gh"
        fake.write_text("""#!/usr/bin/env python3
import os, pathlib, sys
base=pathlib.Path(os.environ['FAKE_GH_DIR']); endpoint=sys.argv[-1]
names={'repos/s1ns3nz0/node-operator-gitops/actions/runs/34657770665':'run.json','repos/s1ns3nz0/node-operator-gitops/actions/runs/34657770665/artifacts?per_page=100&page=1':'artifacts.json','repos/s1ns3nz0/node-operator-gitops/actions/artifacts/10285458234/zip':'artifact.zip'}
name=names.get(endpoint)
if name is None: raise SystemExit(91)
sys.stdout.buffer.write((base/name).read_bytes())
"""); fake.chmod(0o755)

    def invoke(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(SCRIPT), "--authorization-path", str(self.authorization), "--output-dir", str(self.output)], text=True, capture_output=True, env={**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"], "FAKE_GH_DIR": str(self.fixtures), "GH_TOKEN": "not-printed"}, timeout=20)

    def assert_fail(self) -> None:
        result = self.invoke(); self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr); self.assertFalse(self.output.exists()); self.assertNotIn("not-printed", result.stdout + result.stderr)

    def test_retrieves_exact_authorized_five_file_evidence(self) -> None:
        result = self.invoke(); self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({path.name for path in self.output.iterdir()}, set(authz.NAMES))
        for name, raw in self.evidence.items(): self.assertEqual((self.output / name).read_bytes(), raw)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)

    def test_accepts_scoped_target_and_rejects_sibling_or_forged_provenance(self) -> None:
        scoped = f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-example-baseline-gitops-client/node-operator-client@{MANIFEST}"
        evidence = self._evidence(scoped); self._write(evidence, image=scoped)
        self.assertEqual(self.invoke().returncode, 0)
        self.output.rename(self.root / "accepted")
        sibling = f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-example-baseline-gitops-client/node-operator-client-forged@{MANIFEST}"
        self._write(self._evidence(sibling), image=sibling); self.assert_fail()
        self._write(self._evidence(), image=scoped); self.assert_fail()
        self._write(self._evidence(scoped, "sha256:" + "f" * 64), image=scoped); self.assert_fail()

    def test_current_nine_file_layout_and_unknown_extras(self) -> None:
        extras = ("gitops-chart-signature-verified.json", "gitops-chart-sbom-verified.json", "gitops-chart-release-predicate.json", "gitops-chart-release-verified.json")
        with zipfile.ZipFile(self.fixtures / "artifact.zip", "a") as archive:
            for name in extras:
                archive.writestr(name, b"{}")
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({path.name for path in self.output.iterdir()}, set(authz.NAMES))
        self.output.rename(self.root / "accepted-current-layout")
        with zipfile.ZipFile(self.fixtures / "artifact.zip", "a") as archive:
            archive.writestr("unexpected.json", b"{}")
        self.assert_fail()
        for image in (
            f"999999999999.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-example-baseline-gitops-client/node-operator-client@{MANIFEST}",
            f"123456789012.dkr.ecr.us-east-1.amazonaws.com/node-operator-example-baseline-gitops-client/node-operator-client@{MANIFEST}",
            f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/2invalid-deployment-baseline-gitops-client/node-operator-client@{MANIFEST}",
        ):
            with self.subTest(image=image):
                self._write(self._evidence(image), image=image); self.assert_fail()

    def test_rejects_run_artifact_and_zip_binding_failures(self) -> None:
        baseline_run = json.loads((self.fixtures / "run.json").read_text()); baseline_artifacts = json.loads((self.fixtures / "artifacts.json").read_text())
        cases = [
            ({**baseline_run, "run_number": 38}, baseline_artifacts, None),
            ({**baseline_run, "head_sha": "f" * 40}, baseline_artifacts, None),
            ({**baseline_run, "head_branch": "feature"}, baseline_artifacts, None),
            ({**baseline_run, "path": ".github/workflows/image-publish.yml"}, baseline_artifacts, None),
            (baseline_run, {"total_count": 1, "artifacts": [{**baseline_artifacts["artifacts"][0], "id": 1}]}, None),
            (baseline_run, baseline_artifacts, [("../gitops-chart-subject.json", self.evidence[authz.NAMES[0]])]),
            (baseline_run, baseline_artifacts, list(self.evidence.items()) + [(authz.NAMES[0], self.evidence[authz.NAMES[0]])]),
        ]
        for run, artifacts, members in cases:
            with self.subTest(run=run): self._write(self.evidence, run=run, artifacts=artifacts, members=members); self.assert_fail()

    def test_rejects_tamper_and_never_clobbers_output(self) -> None:
        self._write(self.evidence)
        tampered = dict(self.evidence); tampered[authz.NAMES[0]] += b" "
        with zipfile.ZipFile(self.fixtures / "artifact.zip", "w") as archive:
            for name, raw in tampered.items(): archive.writestr(name, raw)
        self.assert_fail()
        self._write(self.evidence); self.output.mkdir(); (self.output / "sentinel").write_text("keep")
        result = self.invoke(); self.assertNotEqual(result.returncode, 0); self.assertEqual((self.output / "sentinel").read_text(), "keep")


if __name__ == "__main__": unittest.main(verbosity=2)

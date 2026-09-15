#!/usr/bin/env python3
# Check objective: Verify review evidence cache recovery rejects stale, forged, malformed, and oversized artifacts.
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/refresh-review-evidence.py"
HEAD = "a" * 40
BASE = "b" * 40
TRUSTED = "c" * 40
GATE_ID = 900
SOURCE_ID = 800


def write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


class RefreshEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.fixtures = self.work / "fixtures"
        self.fixtures.mkdir()
        self.event = self.work / "event.json"
        write_json(self.event, {"workflow_run": {
            "name": "CI Evidence Review Signal", "path": ".github/workflows/review-signal.yml",
            "event": "pull_request_review", "conclusion": "success", "repository": {"full_name": "owner/repo"},
            "pull_requests": [{"number": 7}],
        }})
        write_json(self.fixtures / "pull.json", {"state": "open", "head": {"sha": HEAD}, "base": {"sha": BASE}})
        created = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        write_json(self.fixtures / "artifacts.json", {"artifacts": [{
            "id": 700, "name": f"ci-evidence-gate-{HEAD}", "expired": False, "created_at": created,
            "workflow_run": {"id": GATE_ID},
        }]})
        write_json(self.fixtures / "gate.json", {
            "repository": {"full_name": "owner/repo"}, "name": "CI Evidence Gate",
            "path": ".github/workflows/evidence-gate.yml", "event": "workflow_run", "status": "completed",
            "conclusion": "failure", "head_sha": TRUSTED,
        })
        write_json(self.fixtures / "source.json", {
            "repository": {"full_name": "owner/repo"}, "name": "CI",
            "path": ".github/workflows/continuous-integration.yml", "event": "pull_request", "status": "completed",
            "conclusion": "success", "head_sha": HEAD, "pull_requests": [{"number": 7}],
        })
        self.write_archive()
        binary = self.work / "bin"
        binary.mkdir()
        gh = binary / "gh"
        gh.write_text("""#!/usr/bin/env python3
import os
from pathlib import Path
import sys
endpoint = sys.argv[-1]
fixtures = Path(os.environ[\"FIXTURES\"])
mapping = {
  \"repos/owner/repo/pulls/7\": \"pull.json\",
  \"repos/owner/repo/actions/artifacts?per_page=100\": \"artifacts.json\",
  \"repos/owner/repo/actions/runs/900\": \"gate.json\",
  \"repos/owner/repo/actions/runs/800\": \"source.json\",
}
if endpoint == \"repos/owner/repo/actions/artifacts/700/zip\":
    sys.stdout.buffer.write((fixtures / \"artifact.zip\").read_bytes())
elif endpoint in mapping:
    sys.stdout.write((fixtures / mapping[endpoint]).read_text())
else:
    sys.exit(1)
""", encoding="utf-8")
        gh.chmod(0o700)
        self.environment = dict(os.environ, PATH=f"{binary}:{os.environ['PATH']}", FIXTURES=str(self.fixtures),
                                GH_TOKEN="fixture", GITHUB_REPOSITORY="owner/repo", GITHUB_SHA=TRUSTED,
                                GITHUB_EVENT_PATH=str(self.event), GITHUB_OUTPUT=str(self.work / "output"),
                                EVIDENCE_ROOT=str(self.work / "evidence"))

    def write_archive(self, context=None, evidence=None, extra=None):
        context = context or {"schema_version": 1, "subject_sha": HEAD, "base_sha": BASE,
                              "trusted_sha": TRUSTED, "source_run_id": SOURCE_ID, "gate_run_id": GATE_ID}
        evidence = evidence or {"subject": {"commit_sha": HEAD}, "evidence": {}, "scm": {}, "policy": {}}
        with zipfile.ZipFile(self.fixtures / "artifact.zip", "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("published/evidence.json", json.dumps(evidence))
            archive.writestr("published/cache-context.json", json.dumps(context))
            for name, content in (extra or {}).items():
                archive.writestr(name, content)

    def execute(self):
        return subprocess.run([sys.executable, str(SCRIPT)], env=self.environment, text=True, capture_output=True)

    def test_valid_failure_policy_cache_is_accepted(self):
        result = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.work / "output").read_text(),
                         f"subject_sha={HEAD}\npr_number=7\ncache_ready=true\n")
        self.assertEqual(json.loads((self.work / "evidence/cache/evidence.json").read_text())["subject"]["commit_sha"], HEAD)

    def test_stale_context_bindings_are_rejected_without_fallback(self):
        for field, value in (("subject_sha", "d" * 40), ("base_sha", "e" * 40), ("trusted_sha", "f" * 40)):
            with self.subTest(field=field):
                context = {"schema_version": 1, "subject_sha": HEAD, "base_sha": BASE,
                           "trusted_sha": TRUSTED, "source_run_id": SOURCE_ID, "gate_run_id": GATE_ID}
                context[field] = value
                self.write_archive(context=context)
                result = self.execute()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("subject_sha=" + HEAD, (self.work / "output").read_text())
                self.assertNotIn("cache_ready", (self.work / "output").read_text())
                self.assertFalse((self.work / "evidence/cache").exists())
                (self.work / "output").unlink()

    def test_forged_gate_workflow_is_rejected(self):
        gate = json.loads((self.fixtures / "gate.json").read_text())
        gate["path"] = ".github/workflows/attacker.yml"
        write_json(self.fixtures / "gate.json", gate)
        self.assertNotEqual(self.execute().returncode, 0)

    def test_missing_or_oversized_cache_member_is_rejected(self):
        with zipfile.ZipFile(self.fixtures / "artifact.zip", "w") as archive:
            archive.writestr("published/evidence.json", "{}")
        self.assertNotEqual(self.execute().returncode, 0)
        (self.work / "output").unlink()
        self.write_archive(evidence={"subject": {"commit_sha": HEAD}, "evidence": {}, "scm": {},
                                     "policy": {"padding": "x" * (513 * 1024)}})
        self.assertNotEqual(self.execute().returncode, 0)

    def test_expired_or_stale_newest_artifact_is_rejected(self):
        artifact = json.loads((self.fixtures / "artifacts.json").read_text())["artifacts"][0]
        artifact["expired"] = True
        write_json(self.fixtures / "artifacts.json", {"artifacts": [artifact]})
        self.assertNotEqual(self.execute().returncode, 0)
        (self.work / "output").unlink()
        artifact["expired"] = False
        artifact["created_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=25)).isoformat()
        write_json(self.fixtures / "artifacts.json", {"artifacts": [artifact]})
        self.assertNotEqual(self.execute().returncode, 0)
        (self.work / "output").unlink()
        artifact["created_at"] = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=6)).isoformat()
        write_json(self.fixtures / "artifacts.json", {"artifacts": [artifact]})
        self.assertNotEqual(self.execute().returncode, 0)


if __name__ == "__main__":
    unittest.main()

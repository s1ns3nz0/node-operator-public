#!/usr/bin/env python3
# Check objective: Verify expiring exact Vault runtime scan applicability decisions with synthetic inputs.
"""Synthetic tests for the expiring, exact Vault scan applicability decision."""
import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name("assess-vault-runtime-applicability.py")
spec = importlib.util.spec_from_file_location("assessor", SCRIPT)
assessor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assessor)
DIGEST = "sha256:" + "a" * 64


class ApplicabilityTests(unittest.TestCase):
    def make_fixture(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        (root / ".ci/vault-runtime-applicability").mkdir(parents=True)
        evidence = root / "evidence"; evidence.mkdir()
        deps = b"fmt\ngithub.com/ProtonMail/go-crypto/openpgp\n"
        binary = "b" * 64
        entry = {"digest": DIGEST, "binary_path": "/out/vault", "binary_sha256": binary,
                 "dependency_sha256": hashlib.sha256(deps).hexdigest(), "dependency_count": 2,
                 "dependency_path": "/usr/share/vault/dependencies.txt"}
        manifest = {"schema_version": "v1", "advisory_id": assessor.ADVISORY_ID, "advisory_url": "https://pkg.go.dev/vuln/GO-2026-5932", "affected_package_prefix": assessor.PREFIX, "expires_at": "2026-10-09T00:00:00Z", "candidates": {x: copy.deepcopy(entry) for x in ("server", "agent", "injector")}}
        manifest["candidates"]["agent"]["dependency_path"] = None
        advisory = {"id": assessor.ADVISORY_ID, "affected": [{"package": {"name": "golang.org/x/crypto"}, "ecosystem_specific": {"imports": [{"path": assessor.PREFIX}]}}]}
        advisory_bytes = json.dumps(advisory, sort_keys=True).encode()
        manifest["advisory_sha256"] = hashlib.sha256(advisory_bytes).hexdigest()
        (root / ".ci/vault-runtime-applicability/GO-2026-5932.json").write_bytes(advisory_bytes)
        (evidence / "advisory-current.json").write_bytes(advisory_bytes)
        (root / ".ci/vault-runtime-applicability.json").write_text(json.dumps(manifest))
        allow = {"schema_version": "v1", "registry": "registry.test", "candidates": {x: {"repository": "node-operator-baseline-vault-runtime-" + x, "digest": DIGEST, "entrypoint": "/bin/vault", "user": "100:1000"} for x in ("server", "agent", "injector")}}
        (root / ".ci/vault-runtime-candidates.json").write_text(json.dumps(allow))
        sbom = {"bomFormat": "CycloneDX", "metadata": {"component": {"version": DIGEST}}, "components": [{"name": "fixture"}]}
        raw = {"matches": [{"vulnerability": {"id": assessor.ADVISORY_ID, "severity": "Unknown"}, "artifact": {"name": "golang.org/x/crypto", "version": "v0.56.0"}}], "ignoredMatches": [], "descriptor": {"name": "grype", "version": "test", "db": {"status": {"valid": True, "built": "2026-09-09T00:00:00Z", "schemaVersion": 6}}, "configuration": {"exclude": [], "only-fixed": False, "only-notfixed": False, "show-suppressed": True}}, "source": {"target": {"manifestDigest": DIGEST}}}
        (evidence / "sbom.json").write_text(json.dumps(sbom)); (evidence / "grype.json").write_text(json.dumps(raw))
        summary = assessor._summary.summarize((evidence / "sbom.json").read_bytes(), raw, DIGEST)
        (evidence / "scan-summary.json").write_text(json.dumps(summary))
        subject = "registry.test/node-operator-baseline-vault-runtime-server@" + DIGEST
        (evidence / "runtime-identity.json").write_text(json.dumps({"subject": subject, "RepoDigests": [subject], "Os": "linux", "Architecture": "amd64", "user": "100:1000", "entrypoint": ["/bin/vault"]}))
        (evidence / "binary.sha256").write_text(binary + "  /out/vault\n"); (evidence / "dependencies.txt").write_bytes(deps)
        return temp, root, evidence

    def assess(self, root, evidence):
        return assessor.assess("server", evidence, root=root, now=datetime(2026, 9, 9, tzinfo=timezone.utc))

    def test_exact_unknown_is_not_affected_and_raw_is_retained(self):
        temp, root, evidence = self.make_fixture()
        with temp:
            result = self.assess(root, evidence)
            self.assertEqual(result["status"], "passed"); self.assertEqual(result["raw_scan_status"], "blocked")
            self.assertEqual(len(result["not_affected"]), 1); self.assertFalse(result["deployment_authorized"])

    def test_clean_unknown_zero_passes_without_waiver(self):
        temp, root, evidence = self.make_fixture()
        with temp:
            raw = json.loads((evidence / "grype.json").read_text()); raw["matches"] = []
            (evidence / "grype.json").write_text(json.dumps(raw)); (evidence / "scan-summary.json").write_text(json.dumps(assessor._summary.summarize((evidence / "sbom.json").read_bytes(), raw, DIGEST)))
            self.assertEqual(self.assess(root, evidence)["not_affected"], [])

    def test_medium_and_low_findings_coexist_with_exact_unknown(self):
        temp, root, evidence = self.make_fixture()
        with temp:
            raw = json.loads((evidence / "grype.json").read_text())
            raw["matches"] += [{"vulnerability": {"id": "M1", "severity": "Medium"}}, {"vulnerability": {"id": "M2", "severity": "Medium"}}, {"vulnerability": {"id": "M3", "severity": "Medium"}}, {"vulnerability": {"id": "L1", "severity": "Low"}}]
            self._write_raw(evidence, raw)
            result = self.assess(root, evidence)
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["raw_findings"]["medium"], 3)

    def test_negative_evidence_cases(self):
        mutations = {
            "wrongdigest": lambda r,e: self._candidate(r, "digest", "sha256:" + "c" * 64),
            "binary": lambda r,e: (e / "binary.sha256").write_text("0" * 64 + "  /out/vault\n"),
            "closure": lambda r,e: (e / "dependencies.txt").write_bytes(b"golang.org/x/crypto/openpgp\n"),
            "expired": lambda r,e: self._manifest(r, "expires_at", "2026-01-01T00:00:00Z"),
            "runtimeuid": lambda r,e: self._identity(r,e,"user","0:0"),
            "ignoredMatches": lambda r,e: self._raw(r,e,"ignoredMatches",[{"x":1}]),
            "severityraised": lambda r,e: self._raw(r,e,"matches",[{"vulnerability":{"id":assessor.ADVISORY_ID,"severity":"High"},"artifact":{"name":"golang.org/x/crypto","version":"v0.56.0"}}]),
            "newUnknown": lambda r,e: self._raw(r,e,"matches",[{"vulnerability":{"id":assessor.ADVISORY_ID,"severity":"Unknown"},"artifact":{"name":"golang.org/x/crypto","version":"v0.56.0"}},{"vulnerability":{"id":"OTHER","severity":"Unknown"},"artifact":{"name":"x","version":"v1"}}]),
            "differentpackage": lambda r,e: self._raw(r,e,"matches",[{"vulnerability":{"id":assessor.ADVISORY_ID,"severity":"Unknown"},"artifact":{"name":"other/module","version":"v0.56.0"}}]),
            "modifiedversion": lambda r,e: self._raw(r,e,"matches",[{"vulnerability":{"id":assessor.ADVISORY_ID,"severity":"Unknown"},"artifact":{"name":"golang.org/x/crypto","version":"v0.57.0"}}]),
            "duplicateGOunknown": lambda r,e: self._raw(r,e,"matches",[{"vulnerability":{"id":assessor.ADVISORY_ID,"severity":"Unknown"},"artifact":{"name":"golang.org/x/crypto","version":"v0.56.0"}},{"vulnerability":{"id":assessor.ADVISORY_ID,"severity":"Unknown"},"artifact":{"name":"golang.org/x/crypto","version":"v0.56.0"}}]),
            "nonstandardseverity": lambda r,e: self._raw(r,e,"matches",[{"vulnerability":{"id":assessor.ADVISORY_ID,"severity":"weird"},"artifact":{"name":"golang.org/x/crypto","version":"v0.56.0"}}]),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                temp, root, evidence = self.make_fixture()
                with temp:
                    mutate(root,evidence)
                    with self.assertRaises(ValueError): self.assess(root,evidence)

    def _manifest(self, root, key, value):
        m=json.loads((root / ".ci/vault-runtime-applicability.json").read_text()); m[key]=value; (root / ".ci/vault-runtime-applicability.json").write_text(json.dumps(m))
    def _identity(self, root, evidence, key, value):
        x=json.loads((evidence / "runtime-identity.json").read_text()); x[key]=value; (evidence / "runtime-identity.json").write_text(json.dumps(x))
    def _candidate(self, root, key, value):
        m=json.loads((root / ".ci/vault-runtime-applicability.json").read_text()); m["candidates"]["server"][key]=value; (root / ".ci/vault-runtime-applicability.json").write_text(json.dumps(m))
    def _raw(self, root, evidence, key, value):
        x=json.loads((evidence / "grype.json").read_text()); x[key]=value; self._write_raw(evidence, x)
    def _write_raw(self, evidence, raw):
        (evidence / "grype.json").write_text(json.dumps(raw))
        try:
            summary = assessor._summary.summarize((evidence / "sbom.json").read_bytes(), raw, DIGEST)
        except ValueError:
            return
        (evidence / "scan-summary.json").write_text(json.dumps(summary))

    def test_tampered_summary_advisory_and_current_advisory_are_rejected(self):
        for what in ("summary", "advisory", "current"):
            with self.subTest(what=what):
                temp, root, evidence = self.make_fixture()
                with temp:
                    target = (evidence / "scan-summary.json" if what == "summary" else evidence / "advisory-current.json" if what == "current" else root / ".ci/vault-runtime-applicability/GO-2026-5932.json")
                    target.write_text("{}")
                    with self.assertRaises(ValueError): self.assess(root, evidence)

    def test_missing_required_evidence_is_rejected(self):
        temp, root, evidence = self.make_fixture()
        with temp:
            (evidence / "advisory-current.json").unlink()
            with self.assertRaises(ValueError): self.assess(root, evidence)

    def test_affected_prefix_in_a_matching_reviewed_closure_is_rejected(self):
        temp, root, evidence = self.make_fixture()
        with temp:
            deps = (evidence / "dependencies.txt").read_bytes() + b"golang.org/x/crypto/openpgp\n"
            (evidence / "dependencies.txt").write_bytes(deps)
            self._candidate(root, "dependency_sha256", hashlib.sha256(deps).hexdigest())
            self._candidate(root, "dependency_count", deps.count(b"\n"))
            with self.assertRaises(ValueError): self.assess(root, evidence)

    def test_all_components_with_portable_synthetic_evidence(self):
        for component in ("server", "agent", "injector"):
            with self.subTest(component=component):
                temp, root, evidence = self.make_fixture()
                with temp:
                    subject = "registry.test/node-operator-baseline-vault-runtime-" + component + "@" + DIGEST
                    self._identity(root, evidence, "subject", subject)
                    self._identity(root, evidence, "RepoDigests", [subject])
                    result = assessor.assess(component, evidence, root=root,
                                             now=datetime(2026, 9, 9, tzinfo=timezone.utc))
                    self.assertEqual(result["status"], "passed")
                    self.assertEqual(result["raw_scan_status"], "blocked")

    def test_cli_cannot_override_production_manifest(self):
        process = subprocess.run([sys.executable, str(SCRIPT), "server", "/no/such/evidence", "--manifest", "/tmp/fake"], text=True, capture_output=True)
        self.assertNotEqual(process.returncode, 0)


if __name__ == "__main__": unittest.main()

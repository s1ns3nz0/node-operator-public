#!/usr/bin/env python3
# Check objective: Validate Prysm mTLS publishing with fake commands.
"""Offline fake-command behaviour test for the Prysm mTLS publisher."""
from __future__ import annotations
import base64, copy, importlib.util, json, os, pathlib, shutil, subprocess, tempfile, unittest
from datetime import datetime, timezone
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
SHA = "a" * 40

class TestPublisher(unittest.TestCase):
    def test_large_sbom_comparison_uses_files_and_rejects_tampering(self):
        # Execute the production comparison, with evidence larger than Linux's
        # per-argument limit; do not replace jq with a fake command.
        lines = (ROOT / "scripts/release/publish-prysm-mtls-image.sh").read_text().splitlines()
        command = next(line for line in lines if line.startswith("jq ") and '"$evidence/sbom-verified.json"' in line)
        self.assertIn('--slurpfile expected', command)
        evidence = self.tmp / "large-sbom"; evidence.mkdir()
        expected = {"bomFormat": "CycloneDX", "components": [{"name": "x" * 1024}] * 2048}
        raw = json.dumps(expected)
        (evidence / "sbom.json").write_text(raw)
        statement = {"subject": [{"digest": {"sha256": "b" * 64}}], "predicateType": "https://cyclonedx.org/bom", "predicate": expected}
        payload = base64.b64encode(json.dumps(statement).encode()).decode()
        (evidence / "sbom-verified.json").write_text(json.dumps({"payload": payload}))
        def run():
            return subprocess.run(["bash", "-eu", "-c", command], env=dict(os.environ, evidence=str(evidence), digest="sha256:" + "b" * 64), capture_output=True).returncode
        self.assertEqual(run(), 0)
        for invalid in (json.dumps({"bomFormat": "tampered"}), raw + "\n{}", "[]", ""):
            (evidence / "sbom.json").write_text(invalid)
            self.assertNotEqual(run(), 0)

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp()); self.bin = self.tmp / "bin"; self.bin.mkdir(); self.tools = self.tmp / "tools"; self.tools.mkdir()
        self.release = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        self.fixture = self.tmp / "fixture"
        shutil.copytree(ROOT / ".ci/prysm-mtls", self.fixture / ".ci/prysm-mtls")
        shutil.copy2(ROOT / ".ci/prysm-mtls-applicability.json", self.fixture / ".ci/prysm-mtls-applicability.json")
        shutil.copytree(ROOT / ".ci/prysm-mtls-applicability", self.fixture / ".ci/prysm-mtls-applicability")
        (self.fixture / "scripts/release").mkdir(parents=True); (self.fixture / "scripts/ci/lib").mkdir(parents=True)
        for relative in ("scripts/release/publish-prysm-mtls-image.sh", "scripts/release/prysm_publication_record.py", "scripts/ci/scan-release-sbom.sh", "scripts/ci/verify-release-scan-attestation.sh", "scripts/ci/assess-prysm-mtls-applicability.py", "scripts/ci/summarize-vault-runtime-scan.py", "scripts/ci/lib/common.sh"):
            target = self.fixture / relative; target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(ROOT / relative, target)
        self.assertEqual((self.fixture / "scripts/release/publish-prysm-mtls-image.sh").read_bytes(), (ROOT / "scripts/release/publish-prysm-mtls-image.sh").read_bytes())
        self.commit = json.loads((ROOT / ".ci/prysm-mtls/source.lock.json").read_text())["commit"]
        self.fake("curl", "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do [ \"$1\" = --output ] && { shift; echo '{\"value\":\"token\"}' > \"$1\"; exit; }; shift; done\n")
        self.fake("curl", "#!/bin/sh\nout=; last=; while [ \"$#\" -gt 0 ]; do [ \"$1\" = --output ] && { shift; out=$1; shift; continue; }; last=$1; shift; done; case $last in *vuln.go*) cp .ci/prysm-mtls-applicability/GO-2026-5932.json \"$out\";; *) echo '{\"value\":\"token\"}' > \"$out\";; esac\n")
        self.fake("aws", "#!/bin/sh\nif [ \"$1 $2\" = 'sts assume-role-with-web-identity' ]; then echo '{\"Credentials\":{\"AccessKeyId\":\"key\",\"SecretAccessKey\":\"secret\",\"SessionToken\":\"session\"}}'; elif [ \"$1 $2\" = 'sts get-caller-identity' ]; then [ \"$FAKE_MODE\" = bad-sts ] && echo '{\"Account\":\"000000000000\",\"Arn\":\"bad\"}' || echo '{\"Account\":\"123456789012\",\"Arn\":\"arn:aws:sts::123456789012:assumed-role/test-role/x\"}'; elif [ \"$1 $2\" = 'ecr get-login-password' ]; then echo password; else d=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; [ \"$FAKE_MODE\" = bad-digest ] && d=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc; for x; do case $x in imageTag=*) t=${x#imageTag=}; t=${t%%,*};; esac; done; printf '{\"imageDetails\":[{\"registryId\":\"123456789012\",\"repositoryName\":\"node-operator-baseline-validator-prysm\",\"imageDigest\":\"%s\",\"imageTags\":[\"%s\"],\"imageManifestMediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"imagePushedAt\":1}]}\\n' \"$d\" \"$t\"; fi\n")
        self.fake("docker", "#!/bin/sh\ncase $1 in build|tag|push) exit 0;; login) cat >/dev/null;; run) echo 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  /validator'; echo github.com/OffchainLabs/prysm/v7/cmd/validator;; image) case $4 in *RepoDigests*) [ \"$FAKE_MODE\" = wrong-pushed-digest ] && echo '[]' || echo '[\"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-prysm@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"]';; *'.Os'*) echo linux;; *'.Architecture'*) echo amd64;; *'.Config.User'*) echo 1000:1000;; *'.Config.Entrypoint'*) echo '[\"/validator\"]';; *org.opencontainers.image.revision*) echo \"$FAKE_COMMIT\";; *prysm-mtls-patch-sha256*) jq -r .patch_sha256 .ci/prysm-mtls/source.lock.json;; *) jq -r .security_patch_sha256 .ci/prysm-mtls/source.lock.json;; esac;; esac\n")
        self.fake("syft", "#!/bin/sh\nfor x; do case $x in cyclonedx-json=*) o=${x#*=};; sha256:*) d=${x##*@};; esac; done; printf '{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1\",\"metadata\":{\"component\":{\"version\":\"%s\"}},\"components\":[{}]}\\n' \"$d\" > \"$o\"\n")
        self.fake("grype", "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do [ \"$1\" = --file ] && { shift; [ \"$FAKE_MODE\" = scan-fail ] && m='{\"vulnerability\":{\"severity\":\"High\"}}' || m=''; printf '{\"matches\":[%s],\"descriptor\":{\"name\":\"grype\",\"version\":\"1\",\"db\":{\"status\":{\"built\":\"2026\",\"valid\":true,\"schemaVersion\":\"1\"}}}}\\n' \"$m\" > \"$1\"; exit; }; shift; done\n")
        self.fake("grype", "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do [ \"$1\" = --file ] && { shift; o=$1; break; }; shift; done\nd=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; m=''; [ \"$FAKE_MODE\" = scan-fail ] && m='{\"vulnerability\":{\"severity\":\"High\"}}'; [ \"$FAKE_MODE\" = v2 ] && m='{\"vulnerability\":{\"id\":\"GO-2026-5932\",\"severity\":\"Unknown\"},\"artifact\":{\"name\":\"golang.org/x/crypto\",\"version\":\"v0.56.0\"}}'; printf '{\"matches\":[%s],\"ignoredMatches\":[],\"descriptor\":{\"name\":\"grype\",\"version\":\"1\",\"db\":{\"status\":{\"built\":\"2026\",\"valid\":true,\"schemaVersion\":\"1\"}},\"configuration\":{\"exclude\":[],\"only-fixed\":false,\"only-notfixed\":false,\"show-suppressed\":true}},\"source\":{\"target\":{\"manifestDigest\":\"%s\"}}}\\n' \"$m\" \"$d\" > \"$o\"\n")
        cosign = "#!/bin/bash\necho \"cosign:$1\" >> \"$FAKE_AUDIT\"\n[ \"$1\" = version ] && exit 0\n[ \"$1\" = sign ] || [ \"$1\" = attest ] && exit 0\nfor x; do [ \"${prev:-}\" = --type ] && typ=$x; prev=$x; done; sub=${!#}; d=${sub##*@sha256:}; e=$(dirname \"$(find \"$RUNNER_TEMP\" -name provenance.json | head -1)\")\nif [ \"$1\" = verify ]; then printf '[{\"critical\":{\"image\":{\"docker-manifest-digest\":\"sha256:%s\"},\"identity\":{\"docker-reference\":\"%s\"}}}]\\n' \"$d\" \"$sub\"; exit; fi\ncase $typ in slsaprovenance1) p=$(cat \"$e/provenance.json\"); t=https://slsa.dev/provenance/v1;; cyclonedx) p=$(cat \"$e/sbom.json\"); t=https://cyclonedx.org/bom;; *) p=$(cat \"$e/scan.json\"); t=https://github.com/s1ns3nz0/node-operator/attestations/scan-summary/v1;; esac\n[ \"$FAKE_MODE\" = bad-provenance ] && [ \"$typ\" = slsaprovenance1 ] && p='{}'; [ \"$FAKE_MODE\" = bad-scan ] && [ \"$typ\" != slsaprovenance1 ] && [ \"$typ\" != cyclonedx ] && p='{}'\np=$(jq -cn --arg d \"$d\" --arg t \"$t\" --argjson p \"$p\" '{_type:\"https://in-toto.io/Statement/v1\",subject:[{digest:{sha256:$d}}],predicateType:$t,predicate:$p}' | base64 | tr -d '\\n'); printf '{\"payload\":\"%s\"}\\n' \"$p\"\n"
        cosign = cosign.replace('--arg t "$t"', '--arg t "$t" --arg n "${sub%@*}"').replace('subject:[{digest:{sha256:$d}}]', 'subject:[{name:$n,digest:{sha256:$d}}]')
        cosign = cosign.replace('case $typ in slsaprovenance1)', 'case $typ in https://github.com/s1ns3nz0/node-operator/attestations/prysm-raw-grype/v1) p=$(cat "$e/grype.json"); t=$typ;; https://github.com/s1ns3nz0/node-operator/attestations/prysm-applicability/v2) p=$(cat "$e/applicability-assessment.json"); t=$typ;; slsaprovenance1)')
        self.fake("cosign", cosign, self.tools)
        for name in ("syft", "grype"): shutil.copy2(self.bin / name, self.tools / name)
        installer = self.fixture / "scripts/ci/install-validator-signing-fence-release-tools.sh"
        installer.write_text("#!/bin/sh\nmkdir -p \"$1\"\ncp \"$FAKE_TOOLS\"/* \"$1\"/\n")
        installer.chmod(0o700)
        self.fake("git", "#!/bin/sh\necho git >> \"$FAKE_AUDIT\"\necho \"$FAKE_RELEASE\"\n")
    def tearDown(self): shutil.rmtree(self.tmp)
    def fake(self, name, text, directory=None):
        p = (directory or self.bin) / name; p.write_text(text); p.chmod(0o700)
    def invoke(self, mode, **overrides):
        runner = self.tmp / mode; runner.mkdir(exist_ok=True)
        audit = runner / "cosign.log"
        env = os.environ | {"PATH": f"{self.bin}:{os.environ['PATH']}", "FAKE_TOOLS":str(self.tools),"RUNNER_TEMP":str(runner),"GITHUB_REF":"refs/heads/main","GITHUB_SHA":self.release,"GITHUB_RUN_ID":"42","GITHUB_RUN_ATTEMPT":"1","ACCOUNT_ID":"123456789012","AWS_REGION":"ap-northeast-2","AWS_ROLE_ARN":"arn:aws:iam::123456789012:role/test-role","DEPLOYMENT_NAME":"node-operator","ACTIONS_ID_TOKEN_REQUEST_URL":"https://oidc.example","ACTIONS_ID_TOKEN_REQUEST_TOKEN":"token","FAKE_MODE":mode,"FAKE_COMMIT":self.commit,"FAKE_RELEASE":self.release,"FAKE_AUDIT":str(audit),"GITHUB_STEP_SUMMARY":"/dev/null"} | overrides
        return subprocess.run(["bash",str(self.fixture / "scripts/release/publish-prysm-mtls-image.sh")],cwd=self.fixture,env=env,text=True,capture_output=True), runner
    def test_bound_publisher(self):
        result, runner = self.invoke("ok"); self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((runner / "prysm-publication-records/prysm-mtls-publication-record.json").is_file())
        self.assertFalse(list(runner.glob(".prysm-mtls-release.*")), "success left private credentials")
        non_masked = "\n".join(line for line in (result.stdout + result.stderr).splitlines() if not line.startswith("::add-mask::"))
        self.assertNotIn("secret", non_masked)
        for mode in ("bad-sts","bad-digest","wrong-pushed-digest","bad-scan","bad-provenance","scan-fail"):
            result, runner = self.invoke(mode); self.assertNotEqual(result.returncode,0,mode); self.assertFalse((runner / "prysm-publication-records/prysm-mtls-publication-record.json").exists(),mode); self.assertFalse(list(runner.glob(".prysm-mtls-release.*")),mode)
            if mode == "scan-fail": self.assertNotIn("cosign:", (runner / "cosign.log").read_text(), "scanner failure reached signing")
    def test_invalid_context_rejects_before_any_external_command(self):
        for label, override in (("run-zero", {"GITHUB_RUN_ID": "0"}), ("run-leading-zero", {"GITHUB_RUN_ID": "042"}), ("wrong-region", {"AWS_REGION": "us-east-1"})):
            result, runner = self.invoke(label, **override)
            self.assertNotEqual(result.returncode, 0, label)
            self.assertFalse((runner / "cosign.log").exists(), label)
    def test_exact_unknown_emits_v2_record_and_retains_evidence(self):
        result, runner = self.invoke("v2")
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads((runner / "prysm-publication-records/prysm-mtls-publication-record.json").read_text())
        self.assertEqual(record["schema_version"], 2)
        self.assertFalse(record["verification"]["scan_passed"])
        self.assertEqual(record["applicability"]["decision"], "not_affected")
        spec = importlib.util.spec_from_file_location("prysm_record", ROOT / "scripts/release/prysm_publication_record.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.validate_record(record, self.fixture)
        for key, value in (("subject", "wrong"), ("advisory_id", "GO-other"), ("advisory_sha256", "0" * 64), ("decision", "affected")):
            forged = copy.deepcopy(record)
            forged["applicability"][key] = value
            with self.assertRaises(module.PrysmPublicationRecordError):
                module.validate_record(forged, self.fixture)
        with patch.object(module, "datetime") as clock:
            clock.fromisoformat.side_effect = datetime.fromisoformat
            clock.now.return_value = datetime(2100, 1, 1, tzinfo=timezone.utc)
            with self.assertRaises(module.PrysmPublicationRecordError):
                module.validate_record(record, self.fixture)
        for name in ("sbom.json", "grype.json", "scan.json", "runtime-identity.json", "binary.sha256", "dependencies.txt", "advisory-current.json", "applicability-assessment.json"):
            self.assertTrue((runner / "prysm-publication-records/evidence" / name).is_file(), name)
if __name__ == "__main__": unittest.main()

#!/usr/bin/env python3
# Check objective: Reject untrusted CI image evidence before consumer admission.
"""Mocked consumer verification tests; they do not prove real keyless Cosign trust."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/verify-ci-image-evidence.sh"
IMAGE = "ghcr.io/s1ns3nz0/node-operator/security-scanners"
DIGEST = "sha256:" + "a" * 64
REVISION = "b" * 40
RECEIPT_TYPE = "https://github.com/s1ns3nz0/node-operator/attestations/image-build-receipt/v1"


class ConsumerTests(unittest.TestCase):
    def setup(self):
        temporary = tempfile.TemporaryDirectory(); root = Path(temporary.name); tools = root / "bin"; tools.mkdir(); log = root / "log"
        sbom = root / "sbom.json"; sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "flag": True, "numeric": 1.0, "metadata": {"component": {"version": "archive"}}}))
        receipt = root / "receipt.json"; receipt.write_text(json.dumps({"schema_version": 1, "stage": "build", "subject": "security-scanners", "source_revision": REVISION, "docker_archive_sha256": "d" * 64, "image_config_digest": "sha256:" + "c" * 64, "sbom_sha256": hashlib.sha256(sbom.read_bytes()).hexdigest(), "claims": {"signature": False, "registry_manifest_digest": False, "sca": False}}))
        (tools / "cosign").write_text("""#!/usr/bin/env python3
import base64,json,os,sys
args=sys.argv[1:]; open(os.environ['TEST_LOG'],'a').write(' '.join(args)+'\\n')
if args[0]=='version': print(os.environ.get('TEST_VERSION','GitVersion: v3.1.2')); raise SystemExit()
if os.environ.get('TEST_FAIL') == args[0]: raise SystemExit(9)
subject=args[-1]; image,digest=subject.split('@',1)
if args[0]=='verify': print(json.dumps([{'critical':{'type':'https://sigstore.dev/cosign/sign/v1','identity':{'docker-reference':subject},'image':{'docker-manifest-digest':digest}}}])); raise SystemExit()
typ=args[args.index('--type')+1]; predicate=json.load(open(os.environ['TEST_SBOM'] if typ=='cyclonedx' else os.environ['TEST_RECEIPT']))
if os.environ.get('TEST_BAD') == typ: predicate={}
if os.environ.get('TEST_TYPE_CONFUSION') == typ: predicate['flag']=1
if os.environ.get('TEST_INTEGRAL_FLOAT') == typ: predicate['numeric']=1
kind='https://cyclonedx.org/bom' if typ=='cyclonedx' else typ
name='wrong-subject' if os.environ.get('TEST_WRONG_SUBJECT') == typ else image
statement={'_type':os.environ.get('TEST_STATEMENT_TYPE','https://in-toto.io/Statement/v0.1'),'subject':[{'name':name,'digest':{'sha256':digest.split(':',1)[1]}}],'predicateType':kind,'predicate':predicate}
if os.environ.get('TEST_MALFORMED') == typ: print('not-json')
else: print(json.dumps({'payloadType':'application/vnd.in-toto+json','payload':base64.b64encode(json.dumps(statement,separators=(',',':')).encode()).decode()}))
""")
        (tools / "cosign").chmod(0o755)
        env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"], TEST_LOG=str(log), TEST_SBOM=str(sbom), TEST_RECEIPT=str(receipt))
        return temporary, root, sbom, receipt, log, env

    def run_case(self, mutate=None, **changes):
        temporary, root, sbom, receipt, log, env = self.setup()
        with temporary:
            if mutate: mutate(receipt)
            env.update(changes)
            result = subprocess.run(["bash", str(SCRIPT), IMAGE + "@" + DIGEST, REVISION, str(sbom), str(receipt)], text=True, capture_output=True, env=env, timeout=20)
            return result, log.read_text() if log.exists() else ""

    def test_verifies_signature_and_both_producer_predicates_before_success(self):
        result, log = self.run_case()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS verified producer CI image evidence", result.stdout)
        self.assertLess(log.index("verify --output json"), log.index("verify-attestation --type cyclonedx"))
        self.assertIn(RECEIPT_TYPE, log); self.assertIn("--certificate-github-workflow-sha " + REVISION, log)
        self.assertNotIn("insecure", log)

    def test_command_failure_and_wrong_cosign_version_fail_closed(self):
        for changes in ({"TEST_FAIL": "verify"}, {"TEST_VERSION": "GitVersion: v3.1.1"}, {"TEST_VERSION": "GitVersion: v3.1.1\nBuildInfo: v3.1.2"}, {"TEST_VERSION": "GitVersion: v3.1.2-dev"}):
            with self.subTest(changes=changes): self.assertNotEqual(self.run_case(**changes)[0].returncode, 0)

    def test_malformed_and_mismatched_attestation_fail(self):
        self.assertNotEqual(self.run_case(TEST_MALFORMED="cyclonedx")[0].returncode, 0)
        self.assertNotEqual(self.run_case(TEST_BAD=RECEIPT_TYPE)[0].returncode, 0)

    def test_receipt_boolean_cannot_replace_cryptographic_binding(self):
        # A predicate mismatch still fails even though every receipt boolean is false.
        result, _ = self.run_case(TEST_BAD="cyclonedx")
        self.assertNotEqual(result.returncode, 0)

    def test_invalid_local_receipt_schema_is_rejected(self):
        def mutate_boolean(receipt):
            value = json.loads(receipt.read_text()); value["schema_version"] = True; receipt.write_text(json.dumps(value))
        def mutate_zero(receipt):
            value = json.loads(receipt.read_text()); value["claims"]["signature"] = 0; receipt.write_text(json.dumps(value))
        def mutate_extra(receipt):
            value = json.loads(receipt.read_text()); value["extra"] = "not-producer-schema"; receipt.write_text(json.dumps(value))
        def mutate_missing(receipt):
            value = json.loads(receipt.read_text()); del value["docker_archive_sha256"]; receipt.write_text(json.dumps(value))
        def mutate_nan(receipt): receipt.write_text('{"schema_version":NaN}')
        def mutate_overflow(receipt): receipt.write_text('{"schema_version":1e999}')
        def mutate_unsafe_integer(receipt): receipt.write_text('{"schema_version":9007199254740992}')
        for mutate in (mutate_boolean, mutate_zero, mutate_extra, mutate_missing, mutate_nan, mutate_overflow, mutate_unsafe_integer):
            with self.subTest(mutate=mutate.__name__): self.assertNotEqual(self.run_case(mutate=mutate)[0].returncode, 0)

    def test_wrong_subject_and_type_confused_signed_predicates_are_rejected(self):
        self.assertNotEqual(self.run_case(TEST_WRONG_SUBJECT="cyclonedx")[0].returncode, 0)
        self.assertNotEqual(self.run_case(TEST_TYPE_CONFUSION="cyclonedx")[0].returncode, 0)
        self.assertNotEqual(self.run_case(TEST_STATEMENT_TYPE="https://in-toto.io/Statement/v1")[0].returncode, 0)

    def test_cosign_structpb_integral_float_roundtrip_is_accepted(self):
        result, _ = self.run_case(TEST_INTEGRAL_FLOAT="cyclonedx")
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__": unittest.main()

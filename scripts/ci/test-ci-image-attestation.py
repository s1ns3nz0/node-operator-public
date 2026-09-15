#!/usr/bin/env python3
# Check objective: Verify image signature and attestation subject bindings with fixtures.
"""Mocked command tests for sign-ci-image-evidence; they prove no real cryptography."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/release/sign-ci-image-evidence.sh"
REVISION = "a" * 40
CONFIG = "sha256:" + "b" * 64
IMAGE = "ghcr.io/s1ns3nz0/node-operator/security-scanners"
ATTESTATION_HELPER = ROOT / "scripts/ci/ci_image_attestation.py"


class ImageAttestationTests(unittest.TestCase):
    def fixture(self, failure=""):
        temp = tempfile.TemporaryDirectory(); root = Path(temp.name)
        tools = root / "bin"; tools.mkdir(); log = root / "commands.log"
        sbom = root / "sbom.json"; sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {"version": "archive-not-manifest"}}}))
        receipt = root / "receipt.json"; receipt.write_text(json.dumps({"source_revision": REVISION, "image_config_digest": CONFIG, "sbom_sha256": hashlib.sha256(sbom.read_bytes()).hexdigest()}))
        docker = tools / "docker"
        docker.write_text("""#!/usr/bin/env python3
import json, os, sys
open(os.environ['MOCK_LOG'], 'a').write('docker ' + ' '.join(sys.argv[1:]) + '\\n')
manifest = json.dumps({'schemaVersion': 2, 'config': {'digest': os.environ['TEST_CONFIG']}, 'layers': []}, separators=(',', ':'))
if '@sha256:' in sys.argv[-1] and os.environ.get('MOCK_PIN_MISMATCH'):
    manifest = manifest[:-1] + ' }'
sys.stdout.write(manifest)
""")
        cosign = tools / "cosign"
        cosign.write_text("""#!/usr/bin/env python3
import base64, hashlib, json, os, sys
args = sys.argv[1:]
open(os.environ['MOCK_LOG'], 'a').write('cosign ' + ' '.join(args) + '\\n')
if os.environ.get('MOCK_FAIL') and args[0] == os.environ['MOCK_FAIL']:
    raise SystemExit(9)
subject = args[-1]; image, digest = subject.split('@', 1)
def env(predicate, kind):
    if os.environ.get('MOCK_BAD') == kind: predicate = {'bad': True}
    statement = {'_type': 'https://in-toto.io/Statement/v0.1', 'subject': [{'name': image, 'digest': {'sha256': digest.split(':', 1)[1]}}], 'predicateType': kind, 'predicate': predicate}
    return {'payloadType': 'application/vnd.in-toto+json', 'payload': base64.b64encode(json.dumps(statement, separators=(',', ':')).encode()).decode(), 'signatures': []}
if args[0] == 'verify':
    critical = {'type': 'https://sigstore.dev/cosign/sign/v1', 'identity': {'docker-reference': subject}, 'image': {'docker-manifest-digest': digest}}
    case = os.environ.get('MOCK_SIGNATURE_CASE')
    if case == 'bare': critical['identity']['docker-reference'] = image
    if case == 'wrong-reference': critical['identity']['docker-reference'] = image + '@sha256:' + '0' * 64
    if case == 'wrong-digest': critical['image']['docker-manifest-digest'] = 'sha256:' + '0' * 64
    if case == 'attestation-type': critical['type'] = 'https://cyclonedx.org/bom'
    if case == 'missing-type': del critical['type']
    print(json.dumps([{'critical': critical}]))
elif args[0] == 'verify-attestation':
    if os.environ.get('MOCK_MALFORMED') == 'verify-attestation':
        print('not-json')
        raise SystemExit(0)
    typ = args[args.index('--type') + 1]
    predicate = json.load(open(os.environ['TEST_SBOM'] if typ == 'cyclonedx' else os.environ['TEST_RECEIPT']))
    kind = 'https://cyclonedx.org/bom' if typ == 'cyclonedx' else typ
    print(json.dumps(env(predicate, kind)))
""")
        for path in (docker, cosign): path.chmod(0o755)
        env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"], MOCK_LOG=str(log), TEST_CONFIG=CONFIG, TEST_SBOM=str(sbom), TEST_RECEIPT=str(receipt), GITHUB_REPOSITORY="s1ns3nz0/node-operator", GITHUB_REF="refs/heads/main", GITHUB_SHA=REVISION, GITHUB_RUN_ID="123", MOCK_FAIL=failure)
        return temp, root, sbom, receipt, log, env

    def execute(self, failure="", mutate=None, **env_changes):
        temp, root, sbom, receipt, log, env = self.fixture(failure)
        with temp:
            if mutate: mutate(receipt)
            env.update(env_changes)
            output = root / "evidence"
            result = subprocess.run(["bash", str(SCRIPT), IMAGE, CONFIG, str(sbom), str(receipt), str(output)], text=True, capture_output=True, env=env, timeout=30)
            return result, output.exists(), ((output / "image-ref.txt").read_text() if (output / "image-ref.txt").exists() else ""), log.read_text() if log.exists() else ""

    def test_success_signs_and_verifies_before_evidence_output(self):
        result, exists, image_ref, log = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(exists)
        self.assertEqual(image_ref.strip().split("@")[0], IMAGE)
        self.assertIn("cosign attest --yes --type cyclonedx", log)
        self.assertIn("attestations/image-build-receipt/v1", log)
        self.assertLess(log.index("cosign sign"), log.index("cosign verify"))
        self.assertIn("--certificate-github-workflow-sha " + REVISION, log)
        self.assertNotIn("insecure-ignore", log)

    def test_rejects_unbound_or_non_signature_cosign_v3_records(self):
        for case in ('bare', 'wrong-reference', 'wrong-digest', 'attestation-type', 'missing-type'):
            with self.subTest(case=case):
                result, exists, _, _ = self.execute(MOCK_SIGNATURE_CASE=case)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(exists)

    def test_rejects_wrong_branch_before_registry_or_signing(self):
        result, exists, _, log = self.execute(GITHUB_REF="refs/heads/feature")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(exists)
        self.assertEqual(log, "")

    def test_rejects_foreign_repository_before_registry_or_signing(self):
        result, exists, _, log = self.execute(GITHUB_REPOSITORY="another-owner/node-operator")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(exists)
        self.assertEqual(log, "")

    def test_receipt_mismatch_stops_before_cosign(self):
        def mutate(receipt):
            item = json.loads(receipt.read_text()); item["sbom_sha256"] = "0" * 64; receipt.write_text(json.dumps(item))
        result, exists, _, log = self.execute(mutate=mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(exists)
        self.assertNotIn("cosign", log)

    def test_tampered_receipt_config_stops_before_cosign(self):
        def mutate(receipt):
            item = json.loads(receipt.read_text()); item["image_config_digest"] = "sha256:" + "0" * 64; receipt.write_text(json.dumps(item))
        result, exists, _, log = self.execute(mutate=mutate)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(exists)
        self.assertNotIn("cosign", log)

    def test_failed_verification_never_creates_image_ref(self):
        result, exists, _, log = self.execute("verify-attestation")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(exists)
        self.assertIn("cosign verify-attestation", log)

    def test_digest_pinned_refetch_mismatch_stops_before_cosign(self):
        result, exists, _, log = self.execute(MOCK_PIN_MISMATCH="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(exists)
        self.assertIn("docker buildx imagetools inspect --raw", log)
        self.assertNotIn("cosign", log)

    def test_tampered_attested_receipt_is_rejected_after_cosign_verification(self):
        result, exists, _, log = self.execute(MOCK_BAD="https://github.com/s1ns3nz0/node-operator/attestations/image-build-receipt/v1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(exists)
        self.assertIn("cosign verify-attestation", log)

    def test_malformed_verified_output_is_rejected(self):
        result, exists, _, log = self.execute(MOCK_MALFORMED="verify-attestation")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(exists)
        self.assertIn("cosign verify-attestation", log)

    def test_verified_dsse_cap_covers_a_maximum_size_sbom_after_base64_expansion(self):
        namespace = {}
        exec(ATTESTATION_HELPER.read_text(), namespace)
        self.assertGreaterEqual(namespace["MAX_VERIFY"], (namespace["MAX_SBOM"] * 4 + 2) // 3 + 1024 * 1024)


if __name__ == "__main__":
    unittest.main()

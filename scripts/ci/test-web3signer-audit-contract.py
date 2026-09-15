#!/usr/bin/env python3
# Check objective: Verify Web3Signer audit patch and hardened image build remain linked.
"""Offline patch/build linkage; full signer Java tests run inside image build."""
import hashlib
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE = ROOT / '.ci/web3signer-hardened'


class AuditBuildContract(unittest.TestCase):
    def test_both_patches_are_hash_bound(self):
        lock = json.loads((BASE / 'source.lock.json').read_text())
        dockerfile = (BASE / 'Dockerfile').read_text()
        ignore = (BASE / 'Dockerfile.dockerignore').read_text()
        for name, key in [('0001-security-dependencies.patch', 'patch_sha256'),
                          ('0002-signing-audit-metadata.patch', 'audit_patch_sha256')]:
            digest = hashlib.sha256((BASE / 'patches' / name).read_bytes()).hexdigest()
            self.assertEqual(lock[key], digest)
            self.assertIn(digest, dockerfile)
            self.assertIn(name, dockerfile)
            self.assertIn('!.ci/web3signer-hardened/patches/' + name, ignore)

    def test_build_runs_signer_tests(self):
        dockerfile = (BASE / 'Dockerfile').read_text()
        for task in (':core:test', ':signing:test', ':keystorage:test', ':slashing-protection:test'):
            self.assertIn(task, dockerfile)
        self.assertIn('USER 10001:10001', dockerfile)
        self.assertIn('USER 999:999', dockerfile)
        self.assertIn('git apply --check /tmp/signing-audit.patch', dockerfile)


if __name__ == '__main__':
    unittest.main()

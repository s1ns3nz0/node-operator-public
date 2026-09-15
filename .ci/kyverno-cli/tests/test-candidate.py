#!/usr/bin/env python3
"""Static candidate review only; it does not prove an upstream build compiles."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
class Candidate(unittest.TestCase):
 def test_pinned_source_patch_and_official_cli_target(self):
  source=(ROOT/'Dockerfile').read_text()
  helper=(ROOT/'scripts/update-etcd.sh').read_text(); self.assertIn('KYVERNO_COMMIT=40ec788d48bb28d83dbf85538e962a59db9d45c6',source); self.assertIn('make build-cli VERSION=v1.19.1',source); self.assertIn('GOARCH=amd64',source); self.assertIn('update-etcd /src > /artifacts/metadata/resolved-modules.json',source); self.assertIn('go get go.etcd.io/etcd/client/pkg/v3@v3.6.14',helper); self.assertIn('--check-only',helper); self.assertNotIn('build-all',source); self.assertIn('unbuilt', (ROOT/'README.md').read_text())
if __name__=='__main__': unittest.main()

#!/usr/bin/env python3
"""Offline contracts for portable installer registry credentials."""
import base64, json, os, tempfile, unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
from installer_registry_auth import RegistryAuthError, write_ecr_auth
from unittest import mock

REGISTRY="123456789012.dkr.ecr.ap-northeast-2.amazonaws.com"
SECOND="999999999999.dkr.ecr.ap-southeast-1.amazonaws.com"

class RegistryAuthTests(unittest.TestCase):
 def test_auths_only_merges_tokens_and_preserves_private_modes(self):
  with tempfile.TemporaryDirectory() as raw:
   directory=Path(raw)/"auth";directory.mkdir(mode=0o700);known=set()
   write_ecr_auth(directory,REGISTRY,"token with spaces \n",known)
   write_ecr_auth(directory,SECOND,"next\r\n",known)
   config=directory/"config.json";value=json.loads(config.read_text())
   self.assertEqual(value,{"auths":{REGISTRY:{"auth":base64.b64encode(b"AWS:token with spaces ").decode()},SECOND:{"auth":base64.b64encode(b"AWS:next").decode()}}})
   self.assertEqual(config.stat().st_mode & 0o777,0o600);self.assertEqual(directory.stat().st_mode & 0o777,0o700)
 def test_foreign_or_unsafe_config_is_not_overwritten(self):
  with tempfile.TemporaryDirectory() as raw:
   directory=Path(raw)/"auth";directory.mkdir(mode=0o700);config=directory/"config.json";config.write_text('{"auths":{}}');os.chmod(config,0o600)
   with self.assertRaises(RegistryAuthError):write_ecr_auth(directory,REGISTRY,"token",set())
   config.unlink();config.symlink_to("elsewhere")
   with self.assertRaises(RegistryAuthError):write_ecr_auth(directory,REGISTRY,"token",set())
 def test_write_failure_does_not_mask_cleanup_or_publish_config(self):
  with tempfile.TemporaryDirectory() as raw:
   directory=Path(raw)/"auth";directory.mkdir(mode=0o700)
   with mock.patch("installer_registry_auth.os.fsync",side_effect=OSError("fixture")):
    with self.assertRaises(RegistryAuthError):write_ecr_auth(directory,REGISTRY,"token",set())
   self.assertFalse((directory/"config.json").exists());self.assertFalse(any(directory.iterdir()))

if __name__=="__main__": unittest.main()

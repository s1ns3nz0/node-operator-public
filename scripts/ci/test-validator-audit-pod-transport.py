#!/usr/bin/env python3
# Check objective: Verify validator audit Pod remote-shell argument handling.
"""Exercise actual remote shell argument handling using synthetic local tools."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("transport", ROOT / "scripts/release/validator_audit_pod_transport.py")
transport = importlib.util.module_from_spec(spec); spec.loader.exec_module(transport)

class TransportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.calls = []
        self.reader = transport.PodAWSTransport("validator-observability", "validator-audit-reader-test", "uid-1", "bucket-test", "validator/", "ap-northeast-2", self.call)
        self.response = b"{}"

    def tearDown(self):
        self.temp.cleanup()

    def call(self, args):
        self.calls.append(args)
        return b"uid-1" if args[3] == "get" else self.response

    def request(self, op, *extra):
        return ["s3api", op, "--bucket", "bucket-test", "--region", "ap-northeast-2", "--no-cli-pager", *extra]

    def test_metadata_reads_are_scoped_and_uid_checked(self):
        for request in (
            self.request("list-objects-v2", "--prefix", "validator/", "--max-keys", "64", "--no-paginate"),
            self.request("head-object", "--key", "validator/log.gz"),
        ):
            self.assertEqual(self.reader(request), b"{}")
        self.assertEqual(len(self.calls), 6)
        self.assertTrue(all(command[0] == "kubectl" for command in self.calls))

    def test_scope_and_uid_fail_before_exec(self):
        for request in (
            self.request("delete-object", "--key", "validator/a"),
            self.request("head-object", "--key", "other/a"),
            self.request("head-object", "--key", "validator/a", "--endpoint-url", "https://other"),
            self.request("list-objects-v2", "--prefix", "validator/", "--max-keys", "64"),
        ):
            with self.assertRaises(transport.TransportError): self.reader(request)
        self.assertEqual(self.calls, [])
        self.reader.call = lambda args: b"different-uid"
        with self.assertRaises(transport.TransportError): self.reader(self.request("head-object", "--key", "validator/a"))

    def test_malformed_arguments_and_unversioned_download_are_rejected(self):
        for request in (
            None, ["s3api", 1],
            self.request("head-object", "--key", "validator/a\x00b"),
            self.request("list-objects-v2", "--prefix", "validator/", "--max-keys", "64", "--no-paginate", "--continuation-token", "a" * 4097),
            self.request("get-object", "--key", "validator/a", "--version-id", "null", str(self.base / "unused")),
        ):
            with self.assertRaises(transport.TransportError): self.reader(request)
        self.assertEqual(self.calls, [])
        with self.assertRaises(transport.TransportError):
            transport.PodAWSTransport("validator-observability", "validator-audit-reader-test", "uid-1", "bucket-test", "validator/foo", "ap-northeast-2")

    def test_versioned_get_uses_real_shell_without_identifier_interpolation(self):
        binary = self.base / "aws"
        arguments = self.base / "arguments.json"
        binary.write_text("#!" + sys.executable + "\nimport json, os, pathlib, sys\npathlib.Path(os.environ['ARGUMENTS']).write_text(json.dumps(sys.argv[1:]))\npathlib.Path(sys.argv[-1]).write_bytes(b'archive-bytes')\n")
        binary.chmod(0o700)
        output = self.base / "object"; output.write_bytes(b""); output.chmod(0o600)
        marker = self.base / "injected"
        key = "validator/a'; touch " + str(marker) + "; #"
        version = "version'with;quotes"
        def actual(args):
            if args[3] == "get": return b"uid-1"
            remote = args[args.index("--") + 1:]
            return subprocess.run(remote, env={**os.environ, "PATH": str(self.base) + os.pathsep + os.environ["PATH"], "ARGUMENTS": str(arguments)}, check=True, capture_output=True, timeout=5).stdout
        self.reader.call = actual
        self.reader(self.request("get-object", "--key", key, "--version-id", version, str(output)))
        argv = json.loads(arguments.read_text())
        self.assertEqual(argv[argv.index("--key") + 1], key)
        self.assertEqual(argv[argv.index("--version-id") + 1], version)
        self.assertEqual(argv[argv.index("--range") + 1], "bytes=0-8388608")
        self.assertFalse(marker.exists())
        self.assertFalse(Path(argv[-1]).exists(), "owned remote scratch was not removed")
        self.assertEqual(output.read_bytes(), b"archive-bytes")

    def test_unsafe_target_oversize_and_remote_cleanup_failure_do_not_publish(self):
        output = self.base / "object"; output.write_bytes(b"original"); output.chmod(0o600)
        request = self.request("get-object", "--key", "validator/a", "--version-id", "v", str(output))
        self.response = b"x" * (transport.MAX_BYTES + 1)
        with self.assertRaises(transport.TransportError): self.reader(request)
        self.assertEqual(output.read_bytes(), b"original")
        def failed(args):
            if args[3] == "get": return b"uid-1"
            raise subprocess.CalledProcessError(70, args)
        self.reader.call = failed
        with self.assertRaises(transport.TransportError): self.reader(request)
        self.assertEqual(output.read_bytes(), b"original")
        output.unlink(); output.symlink_to(self.base / "absent")
        with self.assertRaises(transport.TransportError): self.reader(request)

    def test_replaced_pod_after_exec_does_not_publish(self):
        output = self.base / "object"; output.write_bytes(b"original"); output.chmod(0o600)
        reads = 0
        def replaced(args):
            nonlocal reads
            if args[3] == "get":
                reads += 1
                return b"uid-1" if reads == 1 else b"replacement"
            return b"untrusted"
        self.reader.call = replaced
        with self.assertRaises(transport.TransportError):
            self.reader(self.request("get-object", "--key", "validator/a", "--version-id", "v", str(output)))
        self.assertEqual(output.read_bytes(), b"original")

if __name__ == "__main__":
    unittest.main()

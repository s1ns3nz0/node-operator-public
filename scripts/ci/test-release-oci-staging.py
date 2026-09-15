#!/usr/bin/env python3
"""Check objective: stage only version-pinned, complete OCI payload bytes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
import release_oci_staging as staging

spec = importlib.util.spec_from_file_location("payload_fixture", Path(__file__).with_name("test-installer-oci-payload.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class FakeS3:
    def __init__(self, objects):
        self.objects = objects
        self.calls = []
        self.head_lengths = {}

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        key = command[command.index("--key") + 1]
        version = command[command.index("--version-id") + 1]
        payload = self.objects[(key, version)]
        if command[2] == "head-object":
            response = {"VersionId": version, "ContentLength": self.head_lengths.get((key, version), len(payload))}
        else:
            Path(command[-1]).write_bytes(payload)
            response = {"VersionId": version}
        return subprocess.CompletedProcess(command, 0, json.dumps(response), "")


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.payload_fixture = fixture.TestPayload()
        self.payload_fixture.setUp()
        self.addCleanup(self.payload_fixture.tearDown)
        self.root = self.payload_fixture.tmp
        self.payload_fixture.prepare()
        payload = self.root / "payload"
        manifest = (payload / "payload-manifest.json").read_bytes()
        source_chunks = []
        objects = {("manifest", "manifest-v1"): manifest}
        for number, row in enumerate(json.loads(manifest)["chunks"]):
            data = (payload / row["name"]).read_bytes()
            source_chunks.append({"key": f"chunk-{number}", "version_id": f"chunk-v{number}", "sha256": hashlib.sha256(data).hexdigest(), "name": row["name"], "size": len(data)})
            objects[(f"chunk-{number}", f"chunk-v{number}")] = data
        self.config = {"schema_version": 1, "region": "ap-northeast-2", "bucket": "private-release-assets", "manifest": {"key": "manifest", "version_id": "manifest-v1", "sha256": hashlib.sha256(manifest).hexdigest()}, "chunks": source_chunks}
        self.source = self.root / "source.json"
        self.source.write_text(json.dumps(self.config))
        self.runner = FakeS3(objects)
        self.parent = self.root / "private"
        self.parent.mkdir(mode=0o700)

    def test_fetches_real_fixture_and_blocks_endpoint_overrides(self):
        previous = os.environ.get("AWS_ENDPOINT_URL")
        previous_token = os.environ.get("GITHUB_TOKEN")
        os.environ["AWS_ENDPOINT_URL"] = "http://hostile.invalid"
        os.environ["GITHUB_TOKEN"] = "preserve-this-token"
        try:
            manifest = staging.fetch(self.source, (self.parent / "staged").absolute(), runner=self.runner)
        finally:
            if previous is None:
                os.environ.pop("AWS_ENDPOINT_URL", None)
            else:
                os.environ["AWS_ENDPOINT_URL"] = previous
            if previous_token is None:
                os.environ.pop("GITHUB_TOKEN", None)
            else:
                os.environ["GITHUB_TOKEN"] = previous_token
        self.assertEqual(manifest["schema_version"], 1)
        self.assertTrue((self.parent / "staged/chunks").is_dir())
        self.assertTrue(all("--version-id" in command for command, _ in self.runner.calls))
        self.assertTrue(all("AWS_ENDPOINT_URL" not in kwargs["env"] and kwargs["env"]["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] == "true" for _, kwargs in self.runner.calls))
        self.assertTrue(all(kwargs["env"]["GITHUB_TOKEN"] == "preserve-this-token" for _, kwargs in self.runner.calls))
        self.assertEqual(self.runner.calls[0][0][2], "head-object")
        self.assertEqual(self.runner.calls[0][1]["timeout"], 60)
        self.assertTrue(all(kwargs["timeout"] == 900 for command, kwargs in self.runner.calls if command[2] == "get-object"))

    def test_manifest_mismatch_leaves_no_output(self):
        self.config["manifest"]["sha256"] = "0" * 64
        self.source.write_text(json.dumps(self.config))
        target = (self.parent / "rejected").absolute()
        with self.assertRaises(staging.StagingError):
            staging.fetch(self.source, target, runner=self.runner)
        self.assertFalse(target.exists())

    def test_rejects_unversioned_null_without_aws_calls(self):
        self.config["chunks"][0]["version_id"] = "null"
        self.source.write_text(json.dumps(self.config))
        with self.assertRaises(staging.StagingError):
            staging.fetch(self.source, (self.parent / "bad").absolute(), runner=self.runner)
        self.assertEqual(self.runner.calls, [])

    def test_rejects_nonprivate_parent(self):
        public = self.root / "public"
        public.mkdir(mode=0o755)
        with self.assertRaises(staging.StagingError):
            staging.fetch(self.source, (public / "bad").absolute(), runner=self.runner)

    def test_oversized_manifest_head_leaves_no_output_and_does_not_get(self):
        self.runner.head_lengths[("manifest", "manifest-v1")] = staging.MAX_METADATA_BYTES + 1
        target = (self.parent / "oversized").absolute()
        with self.assertRaises(staging.StagingError):
            staging.fetch(self.source, target, runner=self.runner)
        self.assertFalse(target.exists())
        self.assertEqual([command[2] for command, _ in self.runner.calls], ["head-object"])


if __name__ == "__main__":
    unittest.main()

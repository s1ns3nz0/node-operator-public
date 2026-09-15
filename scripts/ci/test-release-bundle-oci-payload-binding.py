#!/usr/bin/env python3
# Check objective: Bind OCI payload manifests to exact candidate inventory roots and release bundle hashes.
"""Check objective: an OCI payload manifest is bundle-bound to candidate authority."""
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class PayloadBindingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        with subprocess.Popen(["git", "-C", str(ROOT), "archive", "HEAD"], stdout=subprocess.PIPE) as archive:
            subprocess.run(["tar", "-xf", "-", "-C", str(self.repo)], stdin=archive.stdout, check=True)
        for name in ("prysm", "fence", "client-chart", "signer-probe"):
            (self.repo / f"release/{name}-publication-authorization.json").unlink(missing_ok=True)
        for relative in ("scripts/ci/build-release-bundle.sh", "scripts/release/installer_oci_payload.py", "scripts/release/installer_oci_selection.py"):
            target = self.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        # This focused bundle-binding fixture supplies a complete offline
        # authority projection; inventory semantics have their own CI suite.
        (self.repo / "scripts/release/installer_artifact_inventory.py").write_text(
            "class InventoryError(ValueError): pass\n"
            "def build_inventory(bundle_root, release_sha, account, region, deployment_name, require_signer_probe=False):\n"
            " return {'schema_version':1,'complete':True,'unresolved_authority':[],'artifacts':[{'component':'fixture-image','required':True,'status':'source-approved','authority':'fixture','source':'example.invalid/fixture@sha256:' + 'a'*64,'destination':'000000000000.dkr.ecr.ap-northeast-2.amazonaws.com/release-check@sha256:' + 'a'*64}]}\n"
        )
        subprocess.run(["git", "init", "-q"], cwd=self.repo, check=True)
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "OCI payload fixture"], cwd=self.repo, check=True)
        self.bin = self.tmp / "bin"; self.bin.mkdir()
        (self.bin / "kubectl").write_text("#!/usr/bin/env bash\nset -eu\n[ \"$1\" = kustomize ]\nprintf 'apiVersion: v1\\nkind: ConfigMap\\nmetadata: {name: fixture}\\n'\n")
        (self.bin / "syft").write_text("#!/usr/bin/env bash\nset -eu\nfor arg in \"$@\"; do case $arg in cyclonedx-json=*) output=${arg#cyclonedx-json=};; esac; done\nprintf '{\"bomFormat\":\"CycloneDX\",\"components\":[]}' > \"$output\"\n")
        for command in self.bin.iterdir(): command.chmod(0o700)
        self.manifest = self.tmp / "payload-manifest.json"
        self.write_manifest()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write_manifest(self):
        sys.path.insert(0, str(self.repo / "scripts/release"))
        spec = importlib.util.spec_from_file_location("inventory", self.repo / "scripts/release/installer_artifact_inventory.py")
        module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
        selection_spec = importlib.util.spec_from_file_location("selection", self.repo / "scripts/release/installer_oci_selection.py")
        selection = importlib.util.module_from_spec(selection_spec); sys.modules[selection_spec.name] = selection; selection_spec.loader.exec_module(selection)
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        inventory = module.build_inventory(self.repo, revision, "000000000000", "ap-northeast-2", "release-check", require_signer_probe=True)
        roots = {name: {"root_digest": digest, "root_media_type": "application/vnd.oci.image.manifest.v1+json", "root_annotations": {}} for name, digest in selection.approved_roots(inventory).items()}
        self.manifest.write_text(json.dumps({"schema_version": 1, "roots": roots, "entries": [], "chunks": [{"name": "chunks/oci-payload-00000.tar", "sha256": "a" * 64, "size": 10240, "entries": []}]}, sort_keys=True))

    def build(self, output, *arguments):
        return subprocess.run([str(self.repo / "scripts/ci/build-release-bundle.sh"), *arguments, str(output)], cwd=self.repo, env={**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}"}, text=True, capture_output=True, timeout=90)

    def test_absent_option_preserves_legacy_bundle(self):
        output = self.tmp / "legacy"
        result = self.build(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(output / "node-operator-release-bundle.tar") as archive:
            self.assertNotIn("rendered/installer-oci-payload-manifest.json", archive.getnames())

    def test_mismatched_root_is_rejected(self):
        value = json.loads(self.manifest.read_text())
        value["roots"][next(iter(value["roots"]))]["root_digest"] = "sha256:" + "f" * 64
        self.manifest.write_text(json.dumps(value))
        result = self.build(self.tmp / "bad", "--oci-payload-manifest", str(self.manifest))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("payload roots differ", result.stderr)

    def test_manifest_member_is_hashed_by_bundle_manifest(self):
        output = self.tmp / "bound"
        result = self.build(output, "--oci-payload-manifest", str(self.manifest))
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(output / "node-operator-release-bundle.tar") as archive:
            data = archive.extractfile("rendered/installer-oci-payload-manifest.json").read()
        manifest = json.loads((output / "manifest.json").read_text())
        hashes = {entry["path"]: entry["sha256"] for entry in manifest["entries"]}
        self.assertEqual(hashes["rendered/installer-oci-payload-manifest.json"], hashlib.sha256(data).hexdigest())

    def test_single_backslash_member_is_rejected(self):
        value = json.loads(self.manifest.read_text())
        name = "oci/fixture-image/bad\\member"
        value["entries"] = [{"path": name, "size": 1, "sha256": "b" * 64}]
        value["chunks"][0]["entries"] = [name]
        self.manifest.write_text(json.dumps(value))
        result = self.build(self.tmp / "unsafe", "--oci-payload-manifest", str(self.manifest))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("member path is invalid", result.stderr)


if __name__ == "__main__":
    unittest.main()

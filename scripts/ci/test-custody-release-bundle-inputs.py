#!/usr/bin/env python3
# Check objective: Verify custody helper inclusion from a committed release revision.
"""Exercise custody helper inclusion from a committed release-tree revision."""
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BUILDER = "scripts/ci/build-release-bundle.sh"
KEY_GUARD = "scripts/ops/verify-custody-validator-key.py"
TLS_GUARD = "scripts/ops/verify-hoodi-vault-v2-transport-records.sh"
CRYPTO_GUARD = "scripts/ops/verify-custody-keystore-secret.py"
CRYPTO_LOCK = ".ci/custody-verifier/source-lock.json"
RUNTIME_HELPER = "scripts/release/custody_verifier_runtime.py"


class CustodyReleaseBundleInputsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.fixture = base / "fixture"
        self.bin = base / "bin"; self.bin.mkdir()
        self.output = base / "output"
        subprocess.run(["git", "clone", "--quiet", "--no-local", str(ROOT), str(self.fixture)], check=True)
        subprocess.run(["python3", str(ROOT / "scripts/ci/reset-release-authorization-fixture.py"), str(self.fixture)], check=True)
        subprocess.run(["git", "-C", str(self.fixture), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.fixture), "config", "user.name", "release test"], check=True)
        for relative in (BUILDER, KEY_GUARD, TLS_GUARD, CRYPTO_GUARD, CRYPTO_LOCK, RUNTIME_HELPER):
            source = ROOT / relative
            self.assertTrue(source.is_file(), relative)
            target = self.fixture / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o755)
        subprocess.run(["git", "-C", str(self.fixture), "add", BUILDER, KEY_GUARD, TLS_GUARD, CRYPTO_GUARD, CRYPTO_LOCK, RUNTIME_HELPER], check=True)
        subprocess.run(["git", "-C", str(self.fixture), "commit", "--quiet", "-m", "add reviewed custody bundle inputs"], check=True)
        self.committed_guard = (self.fixture / KEY_GUARD).read_bytes()
        self._fake("kubectl", "#!/usr/bin/env sh\nset -eu\n[ \"$1\" = kustomize ] || exit 64\nprintf '%s\\n' 'apiVersion: v1' 'kind: ConfigMap' 'metadata:' '  name: rendered'\n")
        self._fake("syft", "#!/usr/bin/env sh\nset -eu\nout=''; name=''; version=''\nwhile [ \"$#\" -gt 0 ]; do case \"$1\" in --output) out=\"${2#cyclonedx-json=}\"; shift 2;; --source-name) name=$2; shift 2;; --source-version) version=$2; shift 2;; *) shift;; esac; done\nprintf '{\"bomFormat\":\"CycloneDX\",\"metadata\":{\"component\":{\"name\":\"%s\",\"version\":\"%s\"},\"tools\":{\"components\":[{\"name\":\"syft\"}]}},\"components\":[]}\\n' \"$name\" \"$version\" > \"$out\"\n")

    def tearDown(self):
        self.temporary.cleanup()

    def _fake(self, name, contents):
        path = self.bin / name
        path.write_text(contents)
        path.chmod(0o755)

    def _run(self):
        environment = os.environ | {"PATH": f"{self.bin}:{os.environ['PATH']}"}
        return subprocess.run([str(self.fixture / BUILDER), str(self.output)], cwd=self.fixture,
                              env=environment, text=True, capture_output=True, timeout=90)

    def _archive(self):
        destination = Path(self.temporary.name) / "extract"; destination.mkdir()
        with tarfile.open(self.output / "node-operator-release-bundle.tar") as archive:
            archive.extractall(destination, filter="data")
        return destination

    def test_committed_custody_runtime_inputs_are_included(self):
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        extracted = self._archive()
        self.assertEqual((extracted / "source" / KEY_GUARD).read_bytes(), self.committed_guard)
        self.assertTrue((extracted / "source" / TLS_GUARD).is_file())
        self.assertTrue((extracted / "source" / CRYPTO_GUARD).is_file(), list((extracted / "source/scripts/ops").iterdir()))
        self.assertTrue((extracted / "source" / CRYPTO_LOCK).is_file())

    def test_operator_files_and_historical_identity_tools_are_not_released(self):
        forbidden = ("release/keystore-fixture.json", "release/deposit_data-fixture.json",
                     "release/oci-payload-source.json",
                     "infra/terraform/terraform.tfvars.json", "infra/terraform/terraform.tfstate.json")
        for relative in forbidden:
            path = self.fixture / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"synthetic_operator_input":true}\n')
        subprocess.run(["git", "-C", str(self.fixture), "add", "-f", *forbidden], check=True)
        subprocess.run(["git", "-C", str(self.fixture), "commit", "--quiet", "-m", "synthetic accidentally tracked operator inputs"], check=True)
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        extracted = self._archive()
        for relative in (*forbidden, "scripts/ops/verify-hoodi-example-signer-tls-rejection.sh",
                         "scripts/ops/with-private-vault-operator.sh", "scripts/ops/publish-reviewed-vault-grpc-candidates.sh"):
            self.assertFalse((extracted / "source" / relative).exists(), relative)
        example = extracted / "source/release/env.example"
        self.assertTrue(example.is_file())
        self.assertIn("VALIDATOR_PUBLIC_KEY=\n", example.read_text())
        self.assertIn("WITHDRAWAL_ADDRESS=\n", example.read_text())
        self.assertIn("EXISTING_KEYSTORE_DIR=\n", example.read_text())
        self.assertTrue((extracted / "source" / RUNTIME_HELPER).is_file())

    def test_dirty_and_untracked_worktree_inputs_are_not_materialized(self):
        (self.fixture / KEY_GUARD).write_text("dirty helper must not be bundled\n")
        for relative in ("scripts/ops/untracked-custody-secret.py", ".ci/custody-verifier/cache.py", "cache/custody-secret.txt"):
            path = self.fixture / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("untracked fixture material\n")
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        extracted = self._archive()
        self.assertEqual((extracted / "source" / KEY_GUARD).read_bytes(), self.committed_guard)
        for relative in ("source/scripts/ops/untracked-custody-secret.py", "source/.ci/custody-verifier/cache.py", "source/cache/custody-secret.txt"):
            self.assertFalse((extracted / relative).exists(), relative)


if __name__ == "__main__":
    unittest.main()

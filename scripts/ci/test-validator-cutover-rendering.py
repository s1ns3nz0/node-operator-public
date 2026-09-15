#!/usr/bin/env python3
# Check objective: Verify validator cutover renderers reject unsafe manifest modifications.
"""Exercise the actual shell renderers, then reject modified manifests."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("verifier", ROOT / "scripts/ops/verify-validator-cutover-rendering.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class Rendering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Test legacy manifest shape in an isolated source fixture. The separate
        # authorized-client suite tests bundle-bound publication authorization.
        fixture = tempfile.TemporaryDirectory()
        cls.addClassCleanup(fixture.cleanup)
        cls.render_root = Path(fixture.name) / "source"
        for relative in ("scripts/ops/render-hoodi-validator-runtime.sh", "scripts/ops/render-hoodi-validator-client.sh",
                         "deploy/validator/runtime-template.yaml", "deploy/validator/client-template.yaml",
                         "deploy/validator/client-lease-fence-template.yaml", ".ci/validator/approved-client-images.json"):
            target = cls.render_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        approved = json.loads((ROOT / ".ci/validator/approved-client-images.json").read_text())
        image = next(item["private_image"] for item in approved["images"]
                     if item.get("stage_approved") and item.get("release_channel") in
                     ("upstream-mirror", "manual-native-mtls"))
        registry = image.split("/")[0]
        account, _, _, region, *_ = registry.split(".")
        cls.key = "0x" + "ab" * 48
        cls.images = {"WEB3SIGNER_IMAGE": registry + "/signer@sha256:" + "a" * 64,
                      "POSTGRES_IMAGE": registry + "/postgres@sha256:" + "b" * 64,
                      "SIGNING_FENCE_IMAGE": registry + "/node-operator-baseline-validator-fence@sha256:" + "c" * 64}
        base = ["--validator-set", "hoodi-example", "--aws-account-id", account, "--aws-region", region]
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime.yaml"
            client = Path(directory) / "client.yaml"
            subprocess.run(["bash", str(cls.render_root / "scripts/ops/render-hoodi-validator-runtime.sh"),
                            *base, "--web3signer-image", registry + "/signer@sha256:" + "a" * 64,
                            "--postgres-image", registry + "/postgres@sha256:" + "b" * 64,
                            "--output", str(runtime)], check=True, capture_output=True)
            subprocess.run(["bash", str(cls.render_root / "scripts/ops/render-hoodi-validator-client.sh"),
                            *base, "--validator-public-key", cls.key, "--prysm-validator-image", image,
                            "--signing-fence-image", registry + "/node-operator-baseline-validator-fence@sha256:" + "c" * 64,
                            "--kubernetes-api-cidr", "172.20.0.1/32", "--output", str(client)],
                           check=True, capture_output=True)
            cls.runtime, cls.client = runtime.read_text(), client.read_text()

    def test_actual_renderer_output(self):
        verifier.validate(self.runtime, self.client, "hoodi-example", self.key, self.images)

    def test_runtime_changes_rejected(self):
        for old, new in [("replicas: 0", "replicas: 1"), ("port: 5432", "port: 9999"),
                         ("mountPath: /var/lib/postgresql/data", "mountPath: /lost-history"),
                         ("serviceAccountName:", "otherServiceAccountName:")]:
            with self.subTest(old=old):
                modified = self.runtime.replace(old, new)
                self.assertNotEqual(modified, self.runtime)
                with self.assertRaises(ValueError):
                    verifier.validate(modified, self.client, "hoodi-example", self.key, self.images)

    def test_fence_or_client_changes_rejected(self):
        for old, new in [("replicas: 0", "replicas: 1"), ("port: 9000", "port: 9001"),
                         ("172.20.0.1/32", "0.0.0.0/0")]:
            with self.subTest(old=old):
                modified = self.client.replace(old, new)
                self.assertNotEqual(modified, self.client)
                with self.assertRaises(ValueError):
                    verifier.validate(self.runtime, modified, "hoodi-example", self.key, self.images)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            verifier.validate(self.runtime, self.client, "hoodi-example", "0x" + "cd" * 48, self.images)

    def test_runtime_image_changes_rejected(self):
        for key, original in self.images.items():
            with self.subTest(image=key), self.assertRaises(ValueError):
                changed = original.rsplit(":", 1)[0] + ":" + "d" * 64
                verifier.validate(self.runtime.replace(original, changed), self.client.replace(original, changed),
                                  "hoodi-example", self.key, self.images)

    def test_deployment_identity_must_match_protected_fence_prefix(self):
        approved = json.loads((ROOT / ".ci/validator/approved-client-images.json").read_text())
        image = next(item["private_image"] for item in approved["images"]
                     if item.get("stage_approved") and item.get("release_channel") in
                     ("upstream-mirror", "manual-native-mtls"))
        registry = image.split("/")[0]
        account, _, _, region, *_ = registry.split(".")
        deployment = self.images["SIGNING_FENCE_IMAGE"].split("/")[1].split("-baseline-validator-fence@")[0]
        revision = "d" * 40
        base = ["--validator-set", "hoodi-example", "--aws-account-id", account, "--aws-region", region,
                "--deployment-name", deployment, "--release-revision", revision]
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime.yaml"
            client = Path(directory) / "client.yaml"
            subprocess.run(["bash", str(self.render_root / "scripts/ops/render-hoodi-validator-runtime.sh"), *base,
                            "--web3signer-image", self.images["WEB3SIGNER_IMAGE"],
                            "--postgres-image", self.images["POSTGRES_IMAGE"], "--output", str(runtime)],
                           check=True, capture_output=True)
            subprocess.run(["bash", str(self.render_root / "scripts/ops/render-hoodi-validator-client.sh"), *base,
                            "--validator-public-key", self.key, "--prysm-validator-image", image,
                            "--signing-fence-image", self.images["SIGNING_FENCE_IMAGE"],
                            "--kubernetes-api-cidr", "172.20.0.1/32", "--output", str(client)],
                           check=True, capture_output=True)
            verifier.validate(runtime.read_text(), client.read_text(), "hoodi-example", self.key, self.images)
            with self.assertRaises(ValueError):
                verifier.validate(runtime.read_text().replace(deployment, "other-deployment"), client.read_text(),
                                  "hoodi-example", self.key, self.images)
            alternate_deployment = "alternate-operator"
            alternate_fence = self.images["SIGNING_FENCE_IMAGE"].replace(
                deployment + "-baseline-validator-fence", alternate_deployment + "-baseline-validator-fence")
            alternate_images = {**self.images, "SIGNING_FENCE_IMAGE": alternate_fence}
            alternate_runtime = runtime.read_text().replace(
                "node-operator.io/deployment-name: " + deployment,
                "node-operator.io/deployment-name: " + alternate_deployment)
            alternate_client = client.read_text().replace(
                "node-operator.io/deployment-name: " + deployment,
                "node-operator.io/deployment-name: " + alternate_deployment).replace(
                self.images["SIGNING_FENCE_IMAGE"], alternate_fence)
            verifier.validate(alternate_runtime, alternate_client, "hoodi-example", self.key, alternate_images)
            with self.assertRaises(ValueError):
                verifier.validate(runtime.read_text(), client.read_text().replace(revision, "e" * 40),
                                  "hoodi-example", self.key, self.images)
            with self.assertRaises(ValueError):
                verifier.validate(runtime.read_text().replace(
                    '        node-operator.io/release-revision: "' + revision + '"\n', ""), client.read_text(),
                                  "hoodi-example", self.key, self.images)

    def test_unknown_template_placeholder_is_rejected_explicitly(self):
        original_root = verifier.ROOT
        with tempfile.TemporaryDirectory() as directory:
            template_root = Path(directory) / "deploy" / "validator"
            template_root.mkdir(parents=True)
            for name in ("runtime-template.yaml", "client-lease-fence-template.yaml", "client-template.yaml"):
                shutil.copy(ROOT / "deploy" / "validator" / name, template_root / name)
            path = template_root / "runtime-template.yaml"
            path.write_text(path.read_text().replace("REPLACE_WITH_VALIDATOR_SET", "REPLACE_WITH_UNKNOWN", 1))
            verifier.ROOT = Path(directory)
            try:
                with self.assertRaisesRegex(ValueError, "unknown template placeholder: UNKNOWN"):
                    verifier.validate(self.runtime, self.client, "hoodi-example", self.key, self.images)
            finally:
                verifier.ROOT = original_root


if __name__ == "__main__":
    unittest.main()

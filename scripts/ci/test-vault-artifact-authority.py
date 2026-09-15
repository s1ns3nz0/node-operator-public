#!/usr/bin/env python3
# Check objective: Vault image overrides use only the approved catalog's exact private digests.
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import stat
import tempfile
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[2]
RENDERER = ROOT / "scripts/release/render-private-vault-values.py"
SPEC = importlib.util.spec_from_file_location("vault_values_renderer", RENDERER)
assert SPEC and SPEC.loader
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)

ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
REPOSITORY = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/node-operator-baseline-gitops-vault"
SERVER = "sha256:268bb80aa9c6d13d65fcfa05c0c268caca068952240a8087291a6ce0b66e3a10"
INJECTOR = "sha256:8c18ccc87fd72930fd0c3f12ea444e9e57e83f119b93c546ed047aba29a05c5f"


class VaultArtifactAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp())
        self.work.chmod(0o700)
        self.catalog = self.work / "approved.json"
        shutil.copy2(ROOT / ".ci/gitops/approved-oci-artifacts.json", self.catalog)

    def tearDown(self) -> None:
        shutil.rmtree(self.work)

    def render(self, **changes: str) -> dict:
        values = {
            "catalog_path": self.catalog,
            "account": ACCOUNT,
            "region": REGION,
            "vault_repository": REPOSITORY,
            "server_image": f"{REPOSITORY}@{SERVER}",
            "agent_image": f"{REPOSITORY}@{SERVER}",
            "injector_image": f"{REPOSITORY}@{INJECTOR}",
        }
        values.update(changes)
        return renderer.render(**values)

    def test_actual_overlay_is_catalog_bound_and_json_yaml(self) -> None:
        overlay_path = self.work / "vault-image-overrides.json"
        overlay = self.render()
        renderer._publish(overlay_path, overlay)
        rendered = json.loads(overlay_path.read_text())
        self.assertEqual(0o600, stat.S_IMODE(overlay_path.stat().st_mode))
        self.assertEqual(rendered["server"]["image"], {"repository": REPOSITORY, "tag": f"{SERVER[7:]}@{SERVER}"})
        self.assertEqual(rendered["injector"]["agentImage"], rendered["server"]["image"])
        self.assertEqual(rendered["injector"]["image"], {"repository": REPOSITORY, "tag": f"{INJECTOR[7:]}@{INJECTOR}"})
        template = (ROOT / "docs/gitops/vault-values.example.yaml").read_text()
        for placeholder in (
            "REPLACE_WITH_PRIVATE_VAULT_SERVER_REPOSITORY",
            "REPLACE_WITH_PRIVATE_VAULT_SERVER_TAG",
            "REPLACE_WITH_PRIVATE_VAULT_AGENT_REPOSITORY",
            "REPLACE_WITH_PRIVATE_VAULT_AGENT_TAG",
            "REPLACE_WITH_PRIVATE_VAULT_INJECTOR_REPOSITORY",
            "REPLACE_WITH_PRIVATE_VAULT_INJECTOR_TAG",
        ):
            self.assertIn(placeholder, template)
        self.assertNotIn("5d3802fde4b13b1a7a459cc9a1d1bfab48de3ff88a8c23ed8b89ce6fd6b5ef0d", template)
        self.assertNotIn("41496b509345246f4cb29d7c83c4e99e6eeb891ef756e327617adb458b5c4b8d", template)

    def test_wrong_private_digest_is_rejected(self) -> None:
        with self.assertRaises(renderer.RenderError):
            self.render(server_image=f"{REPOSITORY}@sha256:{'0' * 64}")

    def test_missing_or_changed_catalog_source_is_rejected(self) -> None:
        catalog = json.loads(self.catalog.read_text())
        catalog["artifacts"] = [item for item in catalog["artifacts"] if not item["source"].startswith("docker.io/hashicorp/vault-k8s@")]
        self.catalog.write_text(json.dumps(catalog))
        with self.assertRaises(renderer.RenderError):
            self.render()

    def test_output_never_overwrites(self) -> None:
        output = self.work / "vault-image-overrides.json"
        output.write_text("existing")
        with self.assertRaises(renderer.RenderError):
            renderer._publish(output, self.render())

    def test_explicit_reuse_retains_identical_existing_bytes_and_inode(self) -> None:
        output = self.work / "vault-image-overrides.json"
        expected = self.render()
        # Formatting is not authority: the existing JSON must be structurally
        # exact, while successful reuse deliberately leaves its bytes intact.
        output.write_text(json.dumps(expected, indent=2) + "\n")
        output.chmod(0o600)
        before = output.stat()
        before_bytes = output.read_bytes()
        renderer._publish(output, expected, reuse_identical=True)
        after = output.stat()
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertEqual(before_bytes, output.read_bytes())

    def test_reuse_rejects_mismatch_without_mutating_existing_file(self) -> None:
        output = self.work / "vault-image-overrides.json"
        output.write_text('{"server":{}}\n')
        output.chmod(0o600)
        before = output.stat()
        before_bytes = output.read_bytes()
        with self.assertRaises(renderer.RenderError):
            renderer._publish(output, self.render(), reuse_identical=True)
        after = output.stat()
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertEqual(before_bytes, output.read_bytes())

    def test_reuse_rejects_unsafe_and_duplicate_key_existing_output(self) -> None:
        output = self.work / "vault-image-overrides.json"
        output.write_text(json.dumps(self.render()))
        output.chmod(0o644)
        with self.assertRaises(renderer.RenderError):
            renderer._publish(output, self.render(), reuse_identical=True)
        output.chmod(0o600)
        output.write_text('{"server":{},"server":{}}\n')
        with self.assertRaises(renderer.RenderError):
            renderer._publish(output, self.render(), reuse_identical=True)

    def test_reuse_rejects_symlink_output_and_parent(self) -> None:
        target = self.work / "target.json"
        target.write_text(json.dumps(self.render()))
        target.chmod(0o600)
        output = self.work / "vault-image-overrides.json"
        output.symlink_to(target)
        with self.assertRaises(renderer.RenderError):
            renderer._publish(output, self.render(), reuse_identical=True)
        output.unlink()
        real_parent = self.work / "real-parent"
        real_parent.mkdir(mode=0o700)
        linked_parent = self.work / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaises(renderer.RenderError):
            renderer._publish(linked_parent / "vault-image-overrides.json", self.render())

    def test_verified_macos_system_alias_is_not_a_user_controlled_ancestor(self) -> None:
        def fake_lstat(path: Path):
            mode = stat.S_IFLNK | 0o777 if path == Path("/var") else stat.S_IFDIR | 0o700
            return SimpleNamespace(st_mode=mode)

        alias_path = Path("/var/folders/example/private/vault-image-overrides.json")
        self.assertFalse(
            renderer._has_symlink_ancestor(
                alias_path, lstat=fake_lstat,
                readlink=lambda path: "/private/var" if path == Path("/var") else "",
            )
        )
        self.assertTrue(
            renderer._has_symlink_ancestor(
                alias_path, lstat=fake_lstat,
                readlink=lambda path: "/not-private/var",
            )
        )


if __name__ == "__main__":
    unittest.main()

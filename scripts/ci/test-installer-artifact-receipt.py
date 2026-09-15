#!/usr/bin/env python3
# Check objective: Verify mirror receipts bind the approved installer artifact index.
"""Check mirror receipts bind the complete approved installer artifact index."""
import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "release"))
import installer_artifact_receipt as receipt
import interactive_deploy as deploy


DISCOVERY = {"aws_account_id": "123456789012", "aws_region": "ap-northeast-1", "deployment_name": "node"}
DIGEST = "sha256:" + "a" * 64


def authority():
    repositories = {
        "vault": "123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/vault",
        "vault_chart": "123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/vault-chart",
        "cert_manager": "123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/cert-manager",
        "cert_manager_chart": "123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/cert-manager-chart",
    }
    baseline = {
        "private_gitops_ecr_repository_urls": {"sensitive": False, "value": repositories},
        "vault_audit_relay_ecr_repository_url": {"sensitive": False, "value": "123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/audit-relay"},
    }
    first_party = {"kind": "image", "build_revision": "b" * 40, "third_party_source_revision": None, "image_ref": "ghcr.io/example/tool@" + DIGEST, "manifest_digest": DIGEST, "input_sha256": "c" * 64, "publication": {"workflow": "image-publish.yml", "run_id": "1", "invocation": "main"}, "verification": {"method": "input-hash-and-registry-digest", "status": "passed"}}
    image = {"kind": "image", "image_ref": "docker.io/example/tool@" + DIGEST, "manifest_digest": DIGEST, "destination": "ignored-by-receipt", "tag": "1.2.3"}
    chart = {"kind": "helm-chart", "approved_url": "https://example.invalid/chart.tgz", "archive_sha256": "d" * 64, "expected_oci_manifest_digest": DIGEST, "version": "1.2.3", "destination": "ignored-by-receipt", "tag": "1.2.3"}
    components = {name: copy.deepcopy(first_party if name in {"vault-bootstrap", "vault-audit-relay", "gitops-oci-mirror"} else chart if name in receipt.CHART_COMPONENTS else image) for name in receipt.NAMES}
    components["vault-audit-relay"]["verification"] = {"method": "cosign-and-slsa", "status": "passed"}
    index = {"schema_version": 1, "release_revision": "e" * 40, "components": components}
    destinations = {
        "vault-bootstrap": repositories["vault"], "vault-server": repositories["vault"], "vault-injector": repositories["vault"],
        "cert-manager-controller": repositories["cert_manager"], "cert-manager-webhook": repositories["cert_manager"], "cert-manager-cainjector": repositories["cert_manager"], "cert-manager-startupapicheck": repositories["cert_manager"],
        "vault-audit-relay": baseline["vault_audit_relay_ecr_repository_url"]["value"], "vault-chart": repositories["vault_chart"], "cert-manager-chart": repositories["cert_manager_chart"],
    }
    raw = json.dumps(index, sort_keys=True, separators=(",", ":")).encode()
    artifacts = {name: {"image_ref": destination + "@" + DIGEST, "manifest_digest": DIGEST, **({"version": "1.2.3"} if name in receipt.CHART_COMPONENTS else {})} for name, destination in destinations.items()}
    mirror = {"schema_version": 1, "status": "verified", **DISCOVERY, "release_revision": index["release_revision"], "index_sha256": hashlib.sha256(raw).hexdigest(), "artifacts": artifacts}
    return index, mirror, baseline, raw


class ReceiptTests(unittest.TestCase):
    def test_cert_manager_v_prefix_is_preserved_and_bound(self):
        index, mirror, baseline, _ = authority()
        index["components"]["cert-manager-chart"].update(version="v1.21.1", tag="v1.21.1")
        mirror["artifacts"]["cert-manager-chart"]["version"] = "v1.21.1"
        raw = json.dumps(index, sort_keys=True).encode()
        mirror["index_sha256"] = hashlib.sha256(raw).hexdigest()
        artifacts, _ = receipt.validate(index, mirror, baseline, DISCOVERY, raw)
        self.assertEqual(artifacts["cert-manager-chart"]["version"], "v1.21.1")
        mirror["artifacts"]["cert-manager-chart"]["version"] = "1.21.1"
        with self.assertRaises(receipt.ReceiptError):
            receipt.validate(index, mirror, baseline, DISCOVERY, raw)

    def test_chart_version_acceptance_remains_bounded(self):
        for component, versions in (
            ("cert-manager-chart", ("vv1.2.3", "1.2", "v1.2.3/other", "latest", "v1.2.3\n")),
            ("vault-chart", ("v1.2.3", "latest")),
        ):
            for version in versions:
                with self.subTest(component=component, version=version):
                    index, _, _, _ = authority()
                    index["components"][component]["version"] = version
                    with self.assertRaises(receipt.ReceiptError):
                        receipt._validate_index(index)

    def test_full_real_shape_is_accepted(self):
        index, mirror, baseline, raw = authority()
        artifacts, digest = receipt.validate(index, mirror, baseline, DISCOVERY, raw)
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
        self.assertEqual(artifacts["vault-chart"]["version"], "1.2.3")

    def test_tampered_receipt_index_and_destination_are_rejected(self):
        cases = (
            ("missing artifact", lambda i, m, b, r: m["artifacts"].pop("vault-server")),
            ("wrong digest", lambda i, m, b, r: m["artifacts"]["vault-server"].update(manifest_digest="sha256:" + "b" * 64)),
            ("wrong ref", lambda i, m, b, r: m["artifacts"]["vault-server"].update(image_ref="123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/other@" + DIGEST)),
            ("wrong registry", lambda i, m, b, r: b["private_gitops_ecr_repository_urls"]["value"].update(vault="999999999999.dkr.ecr.ap-northeast-1.amazonaws.com/vault")),
            ("missing repository", lambda i, m, b, r: b["private_gitops_ecr_repository_urls"]["value"].pop("vault_chart")),
            ("chart version", lambda i, m, b, r: m["artifacts"]["vault-chart"].update(version="9.9.9")),
            ("bad index component type", lambda i, m, b, r: i["components"].update(**{"vault-server": "not-an-object"})),
            ("bad nested publication", lambda i, m, b, r: i["components"]["vault-bootstrap"].update(publication=[])),
            ("wrong nested verification", lambda i, m, b, r: i["components"]["vault-audit-relay"].update(verification={"method": "input-hash-and-registry-digest", "status": "passed"})),
            ("non-string revision", lambda i, m, b, r: i.update(release_revision=None)),
            ("boolean schema", lambda i, m, b, r: i.update(schema_version=True)),
            ("raw object mismatch", lambda i, m, b, r: i.update(release_revision="f" * 40)),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                index, mirror, baseline, raw = authority()
                mutate(index, mirror, baseline, raw)
                with self.assertRaises(receipt.ReceiptError):
                    receipt.validate(index, mirror, baseline, DISCOVERY, raw)

    def test_duplicate_raw_json_is_not_accepted(self):
        index, mirror, baseline, raw = authority()
        duplicate = raw[:-1] + b',"schema_version":1}'
        mirror["index_sha256"] = hashlib.sha256(duplicate).hexdigest()
        with self.assertRaises(receipt.ReceiptError):
            receipt.validate(index, mirror, baseline, DISCOVERY, duplicate)

    def test_nested_schema_is_checked_after_raw_binding(self):
        index, mirror, baseline, _ = authority()
        index["components"]["vault-bootstrap"]["publication"] = []
        raw = json.dumps(index, sort_keys=True, separators=(",", ":")).encode()
        mirror["index_sha256"] = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(receipt.ReceiptError):
            receipt.validate(index, mirror, baseline, DISCOVERY, raw)

    def test_type_errors_are_fail_closed_after_raw_binding(self):
        cases = (
            ("index revision", lambda index, mirror: index.update(release_revision=None)),
            ("index schema", lambda index, mirror: index.update(schema_version=True)),
            ("receipt schema", lambda index, mirror: mirror.update(schema_version=True)),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                index, mirror, baseline, _ = authority()
                mutate(index, mirror)
                raw = json.dumps(index, sort_keys=True, separators=(",", ":")).encode()
                mirror["index_sha256"] = hashlib.sha256(raw).hexdigest()
                with self.assertRaises(receipt.ReceiptError):
                    receipt.validate(index, mirror, baseline, DISCOVERY, raw)

    def test_interactive_gate_uses_same_authority_validation(self):
        index, mirror, baseline, raw = authority()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"; bundle = root / "bundle"
            (state / "terraform-work").mkdir(parents=True)
            (bundle / "rendered").mkdir(parents=True)
            paths = ((state / "terraform-work" / "baseline-output.json", baseline), (state / "vault-artifact-mirror-receipt.json", mirror))
            for path, value in paths:
                path.write_text(json.dumps(value)); os.chmod(path, 0o600)
            index_path = bundle / "rendered" / "installer-artifact-index.json"
            index_path.write_bytes(raw); os.chmod(index_path, 0o600)
            self.assertTrue(deploy._guided_mirror_ready(state, bundle, DISCOVERY, index["release_revision"]))
            mirror["artifacts"]["vault-server"]["image_ref"] = "123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/other@" + DIGEST
            (state / "vault-artifact-mirror-receipt.json").write_text(json.dumps(mirror))
            os.chmod(state / "vault-artifact-mirror-receipt.json", 0o600)
            with self.assertRaises(deploy.StateError):
                deploy._guided_mirror_ready(state, bundle, DISCOVERY, index["release_revision"])


if __name__ == "__main__":
    unittest.main()

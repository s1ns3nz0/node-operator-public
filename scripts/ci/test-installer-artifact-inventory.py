#!/usr/bin/env python3
# Check objective: Validate the all-artifact authority inventory.
"""Offline contract tests for the all-artifact authority inventory."""
from __future__ import annotations
import importlib.util
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/release/installer_artifact_inventory.py"
sys.path.insert(0, str(ROOT / "scripts/release"))
SPEC = importlib.util.spec_from_file_location("inventory", SCRIPT)
assert SPEC and SPEC.loader
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)
import prysm_publication_record as prysm_record
import fence_build_inputs
import fence_release_authorization as fence_authorization
import client_chart_release_authorization as chart_authorization
import signer_probe_build_inputs as signer_probe_inputs
import signer_probe_publication_record as signer_probe_record
import signer_probe_release_authorization as signer_probe_authorization
SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64


def vault_index() -> dict:
    components = {}
    for component in inventory.VAULT_COMPONENTS:
        if component in {"vault-chart", "cert-manager-chart"}:
            components[component] = {
                "kind": "helm-chart", "approved_url": "https://example.invalid/chart.tgz",
                "archive_sha256": "c" * 64, "expected_oci_manifest_digest": DIGEST,
                "version": "1.2.3", "destination": "ignored", "tag": "1.2.3",
            }
        elif component in {"vault-bootstrap", "vault-audit-relay", "gitops-oci-mirror"}:
            method = "cosign-and-slsa" if component == "vault-audit-relay" else "input-hash-and-registry-digest"
            components[component] = {
                "kind": "image", "build_revision": "d" * 40,
                "third_party_source_revision": None,
                "image_ref": f"example.invalid/{component}@{DIGEST}", "manifest_digest": DIGEST,
                "input_sha256": "e" * 64,
                "publication": {"workflow": "image-publish.yml", "run_id": "1", "invocation": "main"},
                "verification": {"method": method, "status": "passed"},
            }
        else:
            components[component] = {
                "kind": "image", "image_ref": f"example.invalid/{component}@{DIGEST}",
                "manifest_digest": DIGEST, "destination": "ignored", "tag": "1.2.3",
            }
    return {"schema_version": 1, "release_revision": SHA, "components": components}


class ArtifactInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.tmp.name) / "bundle"
        self.source = self.bundle / "source"
        (self.source / ".ci/gitops").mkdir(parents=True)
        (self.source / ".ci/validator").mkdir(parents=True)
        (self.source / "release").mkdir()
        (self.bundle / "rendered").mkdir()
        for source in (".ci/gitops/approved-oci-artifacts.json", ".ci/validator/approved-runtime-images.json", ".ci/validator/approved-client-images.json"):
            shutil.copyfile(ROOT / source, self.source / source)
        (self.bundle / "rendered/installer-artifact-index.json").write_text(json.dumps(vault_index()))

    def test_reviewed_private_cli_maps_to_deployment_repository(self):
        path = self.source / ".ci/gitops/approved-oci-artifacts.json"
        catalog = json.loads(path.read_text())
        source = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-nodes@" + DIGEST
        catalog["artifacts"] = [entry for entry in catalog["artifacts"] if not entry["source"].startswith(source.split("@")[0] + "@")]
        row = {"source": source, "destination": "nodes", "ecrTag": DIGEST[7:], "purpose": "Reviewed Kyverno CLI"}
        catalog["artifacts"].append(row)
        path.write_text(json.dumps(catalog))
        result = self.invoke()
        self.assertEqual(result.returncode, 1, result.stderr)  # Other fixture authorities remain unresolved.
        value = json.loads(result.stdout)
        entries = value["artifacts"]
        item = next(entry for entry in entries if entry["component"] == "kyverno-cli")
        self.assertEqual(item["source"], source)
        self.assertEqual(item["destination"], "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-nodes@" + DIGEST)
        catalog["artifacts"].append(row)
        path.write_text(json.dumps(catalog))
        duplicate = self.invoke()
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn("kyverno-cli", duplicate.stderr)

    def tearDown(self):
        self.tmp.cleanup()

    def invoke(self, root: Path | None = None, *extra: str):
        return subprocess.run([str(SCRIPT), "--bundle-root", str(root or self.bundle), "--release-sha", SHA, "--aws-account-id", "123456789012", "--aws-region", "ap-northeast-2", "--deployment-name", "node-operator", *extra], text=True, capture_output=True)

    def test_valid_sources_map_actual_mirror_routes_but_report_real_missing_authority(self):
        result = self.invoke(None, "--require-signer-probe")
        self.assertEqual(result.returncode, 1, result.stderr)
        value = json.loads(result.stdout)
        self.assertFalse(value["complete"])
        items = {item["component"]: item for item in value["artifacts"]}
        self.assertEqual(items["argo-cd-chart"]["destination"], "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-argocd/argo-cd@sha256:8ff18ee7a22670305555167ea31f24a88e2f912cf0a872f852e1880886d4c308")
        self.assertEqual(items["argo-cd-chart"]["destination_tag"], "10.4.0")
        self.assertEqual(items["argo-cd"]["destination"], f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-argocd@{items['argo-cd']['source'].split('@', 1)[1]}")
        self.assertEqual(items["kyverno-chart"]["destination_tag"], "3.8.1")
        self.assertNotIn("destination_tag", items["validator-log-collector"])
        self.assertEqual(items["vault-bootstrap"]["authority"], "installer-artifact-index")
        self.assertEqual(items["vault-bootstrap"]["source"], f"example.invalid/vault-bootstrap@{DIGEST}")
        self.assertEqual(items["argocd-bootstrap"]["destination"],
                         f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-argocd@{items['argocd-bootstrap']['source'].split('@', 1)[1]}")
        self.assertEqual(items["argocd-bootstrap"]["authority"], "approved-gitops-catalog")
        self.assertTrue(items["argocd-bootstrap"]["source"].startswith("ghcr.io/s1ns3nz0/node-operator/argocd-bootstrap@sha256:"))
        self.assertIsNone(items["prysm-validator"]["source"])
        collector = items["validator-log-collector"]
        self.assertEqual(collector["source"], "cr.fluentbit.io/fluent/fluent-bit@sha256:a5761fa961cb22dd0875883a4d446b1acd99d4935d77358aa9f50ee177e44fe2")
        self.assertEqual(collector["destination"], "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-fluent-bit@sha256:a5761fa961cb22dd0875883a4d446b1acd99d4935d77358aa9f50ee177e44fe2")
        self.assertEqual(collector["authority"], "approved-validator-runtime-catalog")
        self.assertEqual({entry["component"] for entry in value["unresolved_authority"]}, {"node-operator-client-chart", "prysm-validator", "validator-signing-fence", "validator-signer-identity-probe"})

    def test_local_authority_only_resolves_matching_unresolved_component(self):
        baseline = json.loads(self.invoke(None, "--require-signer-probe").stdout)
        prysm = next(item for item in baseline["artifacts"] if item["component"] == "prysm-validator")
        digest = "sha256:" + "f" * 64
        authority = self.bundle / "local-artifact-authority.json"
        authority.write_text(json.dumps({"schema_version": 1, "release_revision": SHA,
            "deployment": {"aws_account_id": "123456789012", "aws_region": "ap-northeast-2", "deployment_name": "node-operator"},
            "artifacts": [{"component": "prysm-validator", "source": "local.example/prysm@" + digest,
                           "destination": prysm["destination"].rsplit("@", 1)[0] + "@" + digest,
                           "authority": "local-build-sign-publish"}]}))
        # A release index is already signed authority. Local output is never a
        # replacement path when it exists, even for an otherwise unresolved item.
        result = self.invoke(None, "--require-signer-probe", "--local-artifact-authority", str(authority))
        self.assertEqual(result.returncode, 2, result.stderr)
        authority.write_text(json.dumps({"schema_version": 1, "release_revision": SHA,
            "deployment": {"aws_account_id": "123456789012", "aws_region": "ap-northeast-2", "deployment_name": "node-operator"},
            "artifacts": [{"component": "argo-cd", "source": "local.example/argo@" + digest,
                           "destination": "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-argocd@" + digest,
                           "authority": "local-build-sign-publish"}]}))
        self.assertEqual(self.invoke(None, "--local-artifact-authority", str(authority)).returncode, 2)

    def test_client_chart_authorization_selects_destination_and_orphans_reject(self):
        digest="sha256:"+"f"*64; archive="sha256:"+"e"*64; revision="c"*40
        predicate={"buildDefinition":{"buildType":"https://node-operator.example/gitops-chart/v1","resolvedDependencies":[{"uri":"git+https://github.com/s1ns3nz0/node-operator-gitops","digest":{"gitCommit":revision}}]},"runDetails":{"builder":{"id":chart_authorization.BUILDER}}}
        statement={"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-client/node-operator-client","digest":{"sha256":digest[7:]}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":predicate}
        records={"gitops-chart-subject.json":{"schema_version":"v1","oci_digest":digest,"chart_archive_digest":archive,"chart_version":"0.1.37"},"gitops-chart-sbom.json":{"bomFormat":"CycloneDX","metadata":{"component":{"name":"node-operator-client-0.1.37.tgz","version":archive},"tools":{"components":[{"name":"syft"}]}}},"gitops-chart-grype.json":{"matches":[],"descriptor":{"name":"grype","version":"1","db":{"status":{"valid":True}},"configuration":{"ignore":[],"exclude":[],"only-fixed":False,"only-notfixed":False,"show-suppressed":True}},"source":{"type":"file","target":"node-operator-client-0.1.37.tgz"}},"gitops-chart-provenance-predicate.json":predicate,"gitops-chart-provenance-verified.json":{"payloadType":"application/vnd.in-toto+json","payload":__import__('base64').b64encode(json.dumps(statement).encode()).decode(),"signatures":[{"sig":"x"}]}}
        directory=self.bundle/"rendered/client-chart-publication-records";directory.mkdir()
        raw={name:json.dumps(value).encode() for name,value in records.items()}
        for name,value in raw.items():(directory/name).write_bytes(value)
        image=f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-client/node-operator-client@{digest}"
        auth={"schema_version":1,"source_revision":revision,"publication":{"repository":"s1ns3nz0/node-operator-gitops","workflow":"publish-oci.yml","run_id":"1","artifact_id":"2","artifact_name":"gitops-chart-evidence-x","run_number":"37"},"target":{"image_ref":image,"manifest_digest":digest,"chart_archive_digest":archive,"chart_version":"0.1.37"},"evidence_sha256":{n:hashlib.sha256(v).hexdigest() for n,v in raw.items()},"approvals":{"stage_approved":True,"activation_approved":False}}
        auth_path=self.source/"release/client-chart-publication-authorization.json";auth_path.write_text(json.dumps(auth)); entries=[]
        for path in (chart_authorization.AUTH_PATH,*[f"{chart_authorization.RECORD_DIR}/{n}" for n in chart_authorization.NAMES]):
            value=(self.bundle/path).read_bytes();entries.append({"path":path,"sha256":hashlib.sha256(value).hexdigest(),"size":len(value)})
        (self.bundle/"bundle-manifest.json").write_text(json.dumps({"schema_version":"v1","artifact":{},"source_revision":SHA,"entries":entries}))
        result=self.invoke();self.assertEqual(result.returncode,1,result.stderr);item=next(x for x in json.loads(result.stdout)["artifacts"] if x["component"]=="node-operator-client-chart")
        self.assertEqual(item["destination"],f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-gitops-client/node-operator-client@{digest}");self.assertEqual(item["destination_tag"],"0.1.37")
        auth_path.unlink();self.assertEqual(self.invoke().returncode,2)
        auth_path.write_text(json.dumps(auth));(directory/chart_authorization.NAMES[0]).unlink();self.assertEqual(self.invoke().returncode,2)

    def test_missing_vault_index_never_falls_back_to_historical_catalog(self):
        (self.bundle / "rendered/installer-artifact-index.json").unlink()
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        value = json.loads(result.stdout)
        vault = next(item for item in value["artifacts"] if item["component"] == "vault-bootstrap")
        self.assertIsNone(vault["source"])
        self.assertIn("historical Vault catalog", vault["unresolved_authority"])
        self.assertIn("vault-bootstrap", {entry["component"] for entry in value["unresolved_authority"]})

    def test_signed_local_vault_authority_is_accepted_only_without_bundle_index(self):
        (self.bundle / "rendered/installer-artifact-index.json").unlink()
        baseline = inventory.build_inventory(self.bundle, SHA, "123456789012", "ap-northeast-2", "node-operator")
        digest = "sha256:" + "f" * 64
        rows = []
        for entry in baseline["artifacts"]:
            if entry["component"] not in inventory.VAULT_COMPONENTS:
                continue
            destination = entry["destination"]
            if destination is not None:
                destination = destination.replace("<local-digest>", digest)
            rows.append({"component": entry["component"], "source": "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/local/" + entry["component"] + "@" + digest, "destination": destination, "authority": "local-build-sign-publish"})
        authority = self.bundle / "local-artifact-authority.json"
        authority.write_text(json.dumps({"schema_version": 1, "release_revision": SHA, "deployment": {"aws_account_id": "123456789012", "aws_region": "ap-northeast-2", "deployment_name": "node-operator"}, "artifacts": rows}))
        authority.with_suffix(".pub").write_text("public")
        authority.with_suffix(".sigstore.json").write_text("signature")
        original = inventory.subprocess.run
        calls = []
        inventory.subprocess.run = lambda command, **kwargs: calls.append(command)
        try:
            result = inventory.build_inventory(self.bundle, SHA, "123456789012", "ap-northeast-2", "node-operator", local_artifact_authority=authority)
        finally:
            inventory.subprocess.run = original
        resolved = {item["component"] for item in result["artifacts"] if item.get("authority") == "local-build-sign-publish"}
        self.assertEqual(resolved, set(inventory.VAULT_COMPONENTS))
        self.assertEqual(calls[0][0:2], ["cosign", "verify-blob"])
        self.assertFalse(any(command[0] == "aws" for command in calls))

    def test_missing_gitops_catalog_is_structured_incomplete_not_a_schema_error(self):
        (self.source / ".ci/gitops/approved-oci-artifacts.json").unlink()
        result = self.invoke()
        self.assertEqual(result.returncode, 1, result.stderr)
        value = json.loads(result.stdout)
        argo = next(item for item in value["artifacts"] if item["component"] == "argo-cd-chart")
        self.assertIsNone(argo["source"])
        self.assertIn("absent from the verified bundle", argo["unresolved_authority"])

    def test_collector_runtime_authority_is_remapped_and_old_or_malformed_records_fail_closed(self):
        remapped = self.invoke(None, "--deployment-name", "other-node")
        self.assertEqual(remapped.returncode, 1, remapped.stderr)
        collector = next(item for item in json.loads(remapped.stdout)["artifacts"] if item["component"] == "validator-log-collector")
        self.assertEqual(collector["destination"], "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/other-node-baseline-validator-fluent-bit@sha256:a5761fa961cb22dd0875883a4d446b1acd99d4935d77358aa9f50ee177e44fe2")
        runtime_path = self.source / ".ci/validator/approved-runtime-images.json"
        runtime = json.loads(runtime_path.read_text())
        self.assertEqual(set(runtime["images"]), {"web3signer", "postgres", "fluent-bit"})
        self.assertIn("web3signer@sha256:", runtime["images"]["web3signer"]["source"])
        self.assertIn("postgres@sha256:", runtime["images"]["postgres"]["source"])
        runtime["images"].pop("fluent-bit")
        runtime_path.write_text(json.dumps(runtime))
        old = self.invoke()
        self.assertEqual(old.returncode, 1, old.stderr)
        old_collector = next(item for item in json.loads(old.stdout)["artifacts"] if item["component"] == "validator-log-collector")
        self.assertIsNone(old_collector["source"])
        self.assertIn("retained collector digest approval is absent", old_collector["unresolved_authority"])
        runtime["images"]["fluent-bit"] = None
        runtime_path.write_text(json.dumps(runtime))
        self.assertEqual(self.invoke().returncode, 2)
        runtime["images"]["fluent-bit"] = {"source": "docker.io/fluent/fluent-bit@sha256:" + "a" * 64,
                                             "reference": "v0.1.20 retained collector digest"}
        runtime_path.write_text(json.dumps(runtime))
        self.assertEqual(self.invoke().returncode, 2)
        runtime["images"]["fluent-bit"] = {"source": "cr.fluentbit.io/fluent/fluent-bit:latest",
                                             "reference": "v0.1.20 retained collector digest"}
        runtime_path.write_text(json.dumps(runtime))
        self.assertEqual(self.invoke().returncode, 2)

    def test_task_scoped_live_prysm_approval_is_not_a_fresh_deployment_source(self):
        catalog_path = self.source / ".ci/validator/approved-client-images.json"
        catalog = json.loads(catalog_path.read_text())
        global_manual = next(item for item in catalog["images"] if item.get("component") == "prysm-validator" and item.get("release_channel") == "manual-native-mtls")
        scoped = json.loads(json.dumps(global_manual))
        scoped["private_image"] = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-op-live-baseline-validator-prysm@sha256:" + "c" * 64
        scoped["approval_basis"] = {"task_scoped_activation_approval": True}
        catalog["images"].append(scoped)
        catalog_path.write_text(json.dumps(catalog))

        result = self.invoke(None, "--deployment-name", "fresh-node")
        self.assertEqual(result.returncode, 1, result.stderr)
        prysm = next(item for item in json.loads(result.stdout)["artifacts"] if item["component"] == "prysm-validator")
        self.assertIsNone(prysm["source"])
        self.assertEqual(prysm["destination"], "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/fresh-node-baseline-validator-prysm@" + global_manual["private_image"].rsplit("@", 1)[1])

        duplicate = json.loads(json.dumps(global_manual))
        catalog["images"].append(duplicate)
        catalog_path.write_text(json.dumps(catalog))
        self.assertEqual(self.invoke().returncode, 2)

    def test_malformed_sources_and_identity_are_rejected(self):
        catalog_path = self.source / ".ci/gitops/approved-oci-artifacts.json"
        catalog = json.loads(catalog_path.read_text())
        catalog["artifacts"] = [item for item in catalog["artifacts"] if not item["source"].startswith("quay.io/argoproj/argocd@")]
        catalog_path.write_text(json.dumps(catalog))
        self.assertEqual(self.invoke().returncode, 2)
        self.assertEqual(self.invoke(None, "--aws-account-id", "bad").returncode, 2)

    def test_vault_index_uses_shared_strict_schema_and_argo_suffix_is_fixed(self):
        index_path = self.bundle / "rendered/installer-artifact-index.json"
        index = json.loads(index_path.read_text())
        index["components"]["vault-bootstrap"].pop("verification")
        index_path.write_text(json.dumps(index))
        self.assertEqual(self.invoke().returncode, 2)
        index = vault_index()
        index["components"]["vault-chart"]["approved_url"] = "http://not-approved.invalid/chart.tgz"
        index_path.write_text(json.dumps(index))
        self.assertEqual(self.invoke().returncode, 2)
        index_path.write_text(json.dumps(vault_index()))
        catalog_path = self.source / ".ci/gitops/approved-oci-artifacts.json"
        catalog = json.loads(catalog_path.read_text())
        catalog["artifacts"] = [item for item in catalog["artifacts"]
                                if not item["source"].startswith("ghcr.io/s1ns3nz0/node-operator/argocd-bootstrap@")]
        catalog_path.write_text(json.dumps(catalog))
        self.assertEqual(self.invoke().returncode, 2)

    def test_actual_repository_is_incomplete_until_release_records_exist(self):
        result = self.invoke(ROOT)
        self.assertEqual(result.returncode, 1, result.stderr)
        value = json.loads(result.stdout)
        self.assertFalse(value["complete"])
        self.assertIn("vault-bootstrap", {entry["component"] for entry in value["unresolved_authority"]})

    def test_stage_authorization_uses_candidate_source_without_activation(self):
        candidate="c"*40; release="d"*40
        for relative in prysm_record.BUILD_INPUTS:
            destination = self.source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        self.bundle.joinpath("rendered/installer-artifact-index.json").write_text(json.dumps({**vault_index(),"release_revision":release}))
        image=f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-prysm@{DIGEST}"
        record=prysm_record.create_record(self.source,release_revision=candidate,build_revision=candidate,input_sha256=prysm_record.build_input_sha256(self.source),aws_account_id="123456789012",aws_region="ap-northeast-2",deployment_name="node-operator",repository="node-operator-baseline-validator-prysm",image_ref=image,manifest_digest=DIGEST,run_id="42")
        record_path=self.bundle/"rendered/prysm-mtls-publication-record.json"; record_path.write_text(json.dumps(record))
        auth={"schema_version":1,"candidate_revision":candidate,"record_sha256":hashlib.sha256(record_path.read_bytes()).hexdigest(),"publication":{"repository":"s1ns3nz0/node-operator","workflow":"image-publish.yml","run_id":"42","artifact_id":"123"},"target":{"image_ref":image,"manifest_digest":DIGEST,"input_sha256":record["input_sha256"]},"approvals":{"stage_approved":True,"activation_approved":False}}
        auth_path=self.source/"release/prysm-publication-authorization.json"; auth_path.write_text(json.dumps(auth))
        entries=[]
        for path in ("source/release/prysm-publication-authorization.json","rendered/prysm-mtls-publication-record.json"):
            data=(self.bundle/path).read_bytes(); entries.append({"path":path,"sha256":hashlib.sha256(data).hexdigest(),"size":len(data)})
        (self.bundle/"bundle-manifest.json").write_text(json.dumps({"schema_version":"v1","artifact":{"name":"node-operator-release-bundle.tar","media_type":"application/x-tar"},"source_revision":release,"entries":entries}))
        result=self.invoke(None,"--release-sha",release); self.assertEqual(result.returncode,1,result.stderr)
        prysm=next(item for item in json.loads(result.stdout)["artifacts"] if item["component"]=="prysm-validator"); self.assertEqual(prysm["authority"],"prysm-release-authorization"); self.assertEqual(prysm["source"],image)
        remapped=self.invoke(None,"--release-sha",release,"--deployment-name","other-node"); remapped_prysm=next(item for item in json.loads(remapped.stdout)["artifacts"] if item["component"]=="prysm-validator"); self.assertEqual(remapped_prysm["destination"],f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/other-node-baseline-validator-prysm@{DIGEST}")
        selected=self.invoke(None,"--release-sha",release,"--aws-account-id","222222222222","--aws-region","ap-northeast-1","--deployment-name","dated-node"); self.assertEqual(selected.returncode,1,selected.stderr); selected_prysm=next(item for item in json.loads(selected.stdout)["artifacts"] if item["component"]=="prysm-validator"); self.assertEqual(selected_prysm["source"],image); self.assertEqual(selected_prysm["destination"],f"222222222222.dkr.ecr.ap-northeast-1.amazonaws.com/dated-node-baseline-validator-prysm@{DIGEST}")

    def _write_signer_probe_authorization(self) -> tuple[str, str]:
        candidate = "c" * 40
        release = "d" * 40
        source_account = "111111111111"
        source_region = "ap-northeast-1"
        source_deployment = "source-node"
        digest = "sha256:" + "f" * 64
        repository = f"{source_deployment}-baseline-validator-signer-identity-probe"
        image = f"{source_account}.dkr.ecr.{source_region}.amazonaws.com/{repository}@{digest}"
        for relative in signer_probe_inputs.INPUT_PATHS:
            target = self.source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        record = signer_probe_record.create_record(
            self.source, release_revision=candidate, build_revision=candidate,
            input_sha256=signer_probe_inputs.signer_probe_input_sha256(self.source),
            aws_account_id=source_account, aws_region=source_region,
            deployment_name=source_deployment, repository=repository,
            image_ref=image, manifest_digest=digest, run_id="42",
        )
        record_path = self.bundle / signer_probe_authorization.RECORD_PATH
        record_raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        record_path.write_bytes(record_raw)
        auth = {
            "schema_version": 1, "candidate_revision": candidate,
            "record_sha256": hashlib.sha256(record_raw).hexdigest(),
            "publication": {"repository": "s1ns3nz0/node-operator", "workflow": "image-publish.yml", "run_id": "42", "artifact_id": "123"},
            "target": {"image_ref": image, "manifest_digest": digest, "input_sha256": record["input_sha256"]},
            "approvals": {"stage_approved": True},
        }
        auth_path = self.bundle / signer_probe_authorization.AUTH_PATH
        auth_raw = json.dumps(auth, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        auth_path.write_bytes(auth_raw)
        entries = [
            {"path": signer_probe_authorization.AUTH_PATH, "sha256": hashlib.sha256(auth_raw).hexdigest(), "size": len(auth_raw)},
            {"path": signer_probe_authorization.RECORD_PATH, "sha256": hashlib.sha256(record_raw).hexdigest(), "size": len(record_raw)},
        ]
        for relative in signer_probe_inputs.INPUT_PATHS:
            raw = (self.source / relative).read_bytes()
            entries.append({"path": f"source/{relative}", "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)})
        (self.bundle / "bundle-manifest.json").write_text(json.dumps({
            "schema_version": "v1", "artifact": {"name": "bundle", "media_type": "application/x-tar"},
            "source_revision": release, "entries": entries,
        }))
        self.bundle.joinpath("rendered/installer-artifact-index.json").write_text(json.dumps({**vault_index(), "release_revision": release}))
        return release, image

    def test_signer_probe_stage_authorization_maps_source_to_selected_target_without_running_probe(self):
        release, source = self._write_signer_probe_authorization()
        result = self.invoke(None, "--release-sha", release, "--aws-account-id", "222222222222",
                             "--aws-region", "ap-northeast-2", "--deployment-name", "target-node")
        self.assertEqual(result.returncode, 1, result.stderr)
        entry = next(item for item in json.loads(result.stdout)["artifacts"]
                     if item["component"] == "validator-signer-identity-probe")
        self.assertEqual(entry["authority"], "signer-probe-release-authorization")
        self.assertEqual(entry["source"], source)
        self.assertEqual(entry["destination"], "222222222222.dkr.ecr.ap-northeast-2.amazonaws.com/target-node-baseline-validator-signer-identity-probe@sha256:" + "f" * 64)
        self.assertEqual(entry["consumer"], "signer identity evidence")

    def test_signer_probe_missing_is_only_unresolved_when_required(self):
        without_requirement = json.loads(self.invoke().stdout)
        self.assertNotIn("validator-signer-identity-probe", {item["component"] for item in without_requirement["artifacts"]})
        required = json.loads(self.invoke(None, "--require-signer-probe").stdout)
        entry = next(item for item in required["artifacts"] if item["component"] == "validator-signer-identity-probe")
        self.assertEqual(entry["status"], "unresolved")

    def test_signer_probe_tampered_record_fails_closed_even_when_not_required(self):
        release, _ = self._write_signer_probe_authorization()
        record_path = self.bundle / signer_probe_authorization.RECORD_PATH
        record_path.write_bytes(record_path.read_bytes() + b" ")
        self.assertEqual(self.invoke(None, "--release-sha", release).returncode, 2)

    def test_signer_probe_malformed_authorization_fails_closed_even_when_not_required(self):
        release, _ = self._write_signer_probe_authorization()
        auth_path = self.bundle / signer_probe_authorization.AUTH_PATH
        auth_path.write_text("{}")
        self.assertEqual(self.invoke(None, "--release-sha", release).returncode, 2)

    def test_signer_probe_orphaned_record_fails_closed_even_when_not_required(self):
        release, _ = self._write_signer_probe_authorization()
        auth_path = self.bundle / signer_probe_authorization.AUTH_PATH
        auth_path.unlink()
        self.assertEqual(self.invoke(None, "--release-sha", release).returncode, 2)

    def test_signer_probe_symlinked_authorization_fails_closed_even_when_not_required(self):
        release, _ = self._write_signer_probe_authorization()
        auth_path = self.bundle / signer_probe_authorization.AUTH_PATH
        auth_path.unlink(); auth_path.symlink_to("missing.json")
        self.assertEqual(self.invoke(None, "--release-sha", release).returncode, 2)

    def test_signer_probe_symlinked_record_is_an_orphan_and_fails_closed(self):
        release, _ = self._write_signer_probe_authorization()
        auth_path = self.bundle / signer_probe_authorization.AUTH_PATH
        record_path = self.bundle / signer_probe_authorization.RECORD_PATH
        auth_path.unlink()
        record_path.unlink(); record_path.symlink_to("missing.json")
        self.assertEqual(self.invoke(None, "--release-sha", release).returncode, 2)

    def test_signer_probe_internal_parent_symlinks_reject(self):
        for relative in ("source/release", "rendered"):
            with self.subTest(relative=relative):
                release, _ = self._write_signer_probe_authorization()
                path = self.bundle / relative
                replacement = self.bundle.parent / (relative.replace("/", "-") + "-target")
                path.rename(replacement)
                path.symlink_to(replacement, target_is_directory=True)
                self.assertEqual(self.invoke(None, "--release-sha", release).returncode, 2)
                path.unlink()
                replacement.rename(path)

    def test_rehashed_authorization_tampering_still_rejects(self):
        self.test_stage_authorization_uses_candidate_source_without_activation()
        auth_path=self.source/"release/prysm-publication-authorization.json"
        for field, value in (("candidate_revision","e"*40),("record_sha256","f"*64)):
            auth=json.loads(auth_path.read_text()); auth[field]=value; auth_path.write_text(json.dumps(auth))
            manifest=json.loads((self.bundle/"bundle-manifest.json").read_text()); data=auth_path.read_bytes(); manifest["entries"][0]={"path":"source/release/prysm-publication-authorization.json","sha256":hashlib.sha256(data).hexdigest(),"size":len(data)}; (self.bundle/"bundle-manifest.json").write_text(json.dumps(manifest))
            self.assertEqual(self.invoke(None,"--release-sha","d"*40).returncode,2)

    def test_orphan_or_malformed_authorization_rejects(self):
        record = self.bundle / "rendered/prysm-mtls-publication-record.json"; record.write_text("{}")
        self.assertEqual(self.invoke().returncode, 2)
        record.unlink(); (self.source / "release/prysm-publication-authorization.json").write_text("{}")
        self.assertEqual(self.invoke().returncode, 2)

    def test_fence_stage_authorization_selects_exact_destination_and_orphans_fail(self):
        candidate = "c" * 40; release = "d" * 40
        for relative in fence_build_inputs.INPUT_PATHS:
            target = self.source / relative; target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(ROOT / relative, target)
        self.bundle.joinpath("rendered/installer-artifact-index.json").write_text(json.dumps({**vault_index(), "release_revision": release}))
        digest = "sha256:" + "f" * 64
        image = f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-fence@{digest}"
        input_sha = fence_build_inputs.fence_input_sha256(self.source); sbom_sha = "e" * 64
        record = {"schema_version": 1, "event_type": "validator-signing-fence-release-verification", "collected_at_utc": "2026-09-13T00:00:00Z", "image": image, "artifact_digest": digest, "source_revision": candidate, "input_sha256": input_sha, "result": "PASS", "cryptographic_verification": {"tool": "cosign", "signature_count": 1, "identity": fence_authorization.IDENTITY, "issuer": fence_authorization.ISSUER, "slsa_provenance": True, "transparency_log_verified": True}, "sbom": {"tool": "syft", "format": "cyclonedx-json", "component_count": 1, "sha256": sbom_sha}, "vulnerability_scan": {"schema_version": "v1", "tool": "grype", "scanner": {"version": "1", "database_built": "2026-09-13T00:00:00Z", "database_schema_version": "6"}, "artifact_digest": digest, "sbom_sha256": sbom_sha, "scanned_at": "2026-09-13T00:00:00Z", "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}, "status": "passed"}}
        record_path = self.bundle / "rendered/fence-release-verification.json"; raw = json.dumps(record, sort_keys=True).encode(); record_path.write_bytes(raw)
        auth = {"schema_version": 1, "candidate_revision": candidate, "record_sha256": hashlib.sha256(raw).hexdigest(), "publication": {"repository": "s1ns3nz0/node-operator", "workflow": "image-publish.yml", "run_id": "42", "artifact_id": "123"}, "target": {"image_ref": image, "manifest_digest": digest, "input_sha256": input_sha}, "approvals": {"stage_approved": True, "activation_approved": False}}
        auth_path = self.source / "release/fence-publication-authorization.json"; auth_path.write_text(json.dumps(auth))
        entries = []
        for path in (fence_authorization.AUTH_PATH, fence_authorization.RECORD_PATH):
            data = (self.bundle / path).read_bytes(); entries.append({"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
        (self.bundle / "bundle-manifest.json").write_text(json.dumps({"schema_version": "v1", "artifact": {"name": "bundle", "media_type": "application/x-tar"}, "source_revision": release, "entries": entries}))
        result = self.invoke(None, "--release-sha", release); self.assertEqual(result.returncode, 1, result.stderr)
        entry = next(item for item in json.loads(result.stdout)["artifacts"] if item["component"] == "validator-signing-fence")
        self.assertEqual(entry["authority"], "fence-release-authorization"); self.assertEqual(entry["source"], image); self.assertEqual(entry["destination"], f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-fence@{digest}")
        auth_path.unlink()
        self.assertEqual(self.invoke(None, "--release-sha", release).returncode, 2)

    def complete_inventory(self) -> dict:
        registry = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com"
        return {
            "schema_version": 1, "release_revision": SHA,
            "deployment": {"aws_account_id": "123456789012", "aws_region": "ap-northeast-2", "deployment_name": "node-operator"},
            "complete": True, "unresolved_authority": [],
            "artifacts": [
                {"component": "argo-cd-chart", "required": True, "destination": f"{registry}/node-operator-baseline-gitops-argocd/argo-cd@{DIGEST}", "destination_tag": "10.4.0"},
                {"component": "beta", "required": True, "destination": f"{registry}/node-operator-baseline-nested/beta@{DIGEST}"},
                {"component": "gitops-oci-mirror", "required": True, "destination": None},
            ],
        }

    def verifier(self, mode: str = "ok"):
        calls = []
        def execute(command, **kwargs):
            calls.append((command, kwargs))
            if command[:2] == ["aws", "sts"]:
                account = "000000000000" if mode == "wrong-account" else "123456789012"
                return subprocess.CompletedProcess(command, 0, json.dumps({"Account": account}), "")
            if mode == "timeout":
                raise subprocess.TimeoutExpired(command, 30)
            if mode == "malformed":
                return subprocess.CompletedProcess(command, 0, "{", "")
            repository = command[command.index("--repository-name") + 1]
            digest = command[command.index("--image-ids") + 1].split("=", 1)[1]
            if mode == "partial":
                body = {"imageDetails": []}
            else:
                tags = [] if mode == "missing-tag" else ["wrong-tag"] if mode == "wrong-tag" else ["10.4.0", "10.4.0"] if mode == "ambiguous-tag" else ["10.4.0"]
                body = {"imageDetails": [{"registryId": "999999999999" if mode == "wrong-registry" else "123456789012",
                                          "repositoryName": "unexpected-repository" if mode == "wrong-repository" else repository,
                                          "imageDigest": None if mode == "missing-digest" else digest,
                                          "imageTags": tags}]}
            return subprocess.CompletedProcess(command, 0, json.dumps(body), "")
        return calls, execute

    def test_destination_verification_checks_every_required_destination_with_exact_identity(self):
        calls, execute = self.verifier()
        original = inventory.build_inventory
        inventory.build_inventory = lambda *args, **kwargs: self.complete_inventory()
        try:
            result = inventory.verify_destinations(self.bundle, SHA, "123456789012", "ap-northeast-2", "node-operator", "fixture", executor=execute)
        finally:
            inventory.build_inventory = original
        self.assertEqual(result["scope"], "destination presence only")
        self.assertEqual(result["release_revision"], SHA)
        self.assertEqual(result["exclusions"], [{"component": "gitops-oci-mirror", "reason": "local transport tool exclusion"}])
        self.assertEqual({item["component"] for item in result["artifacts"]}, {"argo-cd-chart", "beta"})
        chart = next(item for item in result["artifacts"] if item["component"] == "argo-cd-chart")
        self.assertEqual(chart["destination_tag"], "10.4.0")
        self.assertEqual(len(calls), 3)
        for command, kwargs in calls[1:]:
            self.assertEqual(command[:3], ["aws", "ecr", "describe-images"])
            self.assertEqual(command[command.index("--registry-id") + 1], "123456789012")
            self.assertEqual(command[command.index("--region") + 1], "ap-northeast-2")
            self.assertTrue(command[command.index("--image-ids") + 1].startswith("imageDigest=sha256:"))
            self.assertEqual(kwargs["timeout"], inventory.AWS_TIMEOUT)
            self.assertEqual(kwargs["env"]["AWS_PROFILE"], "fixture")

    def test_destination_verification_rejects_identity_and_ecr_response_failures(self):
        original = inventory.build_inventory
        inventory.build_inventory = lambda *args, **kwargs: self.complete_inventory()
        try:
            for mode in ("wrong-account", "missing-digest", "wrong-registry", "wrong-repository", "missing-tag", "wrong-tag", "ambiguous-tag", "malformed", "timeout", "partial"):
                with self.subTest(mode=mode):
                    _, execute = self.verifier(mode)
                    with self.assertRaises(inventory.DestinationVerificationError):
                        inventory.verify_destinations(self.bundle, SHA, "123456789012", "ap-northeast-2", "node-operator", "fixture", executor=execute)
        finally:
            inventory.build_inventory = original

    def test_incomplete_canonical_inventory_fails_before_any_external_call(self):
        calls = []
        def execute(*args, **kwargs):
            calls.append(args)
            raise AssertionError("incomplete authority must never call AWS")
        with self.assertRaises(inventory.DestinationVerificationError):
            inventory.verify_destinations(self.bundle, SHA, "123456789012", "ap-northeast-2", "node-operator", "fixture", executor=execute)
        self.assertEqual(calls, [])

    def test_required_null_destination_is_not_an_implicit_exclusion(self):
        value = self.complete_inventory()
        value["artifacts"].append({"component": "unmapped", "required": True, "destination": None})
        calls, execute = self.verifier()
        original = inventory.build_inventory
        inventory.build_inventory = lambda *args, **kwargs: value
        try:
            with self.assertRaises(inventory.DestinationVerificationError):
                inventory.verify_destinations(self.bundle, SHA, "123456789012", "ap-northeast-2", "node-operator", "fixture", executor=execute)
        finally:
            inventory.build_inventory = original
        self.assertEqual(calls, [])
        value = self.complete_inventory()
        value["artifacts"][-1]["destination"] = f"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/transport@{DIGEST}"
        calls, execute = self.verifier()
        inventory.build_inventory = lambda *args, **kwargs: value
        try:
            with self.assertRaises(inventory.DestinationVerificationError):
                inventory.verify_destinations(self.bundle, SHA, "123456789012", "ap-northeast-2", "node-operator", "fixture", executor=execute)
        finally:
            inventory.build_inventory = original
        self.assertEqual(calls, [])

    def test_verify_cli_requires_explicit_profile(self):
        result = self.invoke(None, "--verify-destinations")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--profile is required", result.stderr)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# Check objective: Verify validator quiescence detection against synthetic Kubernetes fixtures.
"""Synthetic Kubernetes fixtures; no cluster access or secret material."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "ops/assert-hoodi-validator-quiesced.sh"


class Quiescence(unittest.TestCase):
    def test_cutover_preserves_claim_ownership_and_lease(self):
        claim = {"metadata": {"name": "data"}, "spec": {"accessModes": ["ReadWriteOnce"],
                 "storageClassName": "validator-hoodi-gp3-kms", "resources": {"requests": {"storage": "50Gi"}}}}
        db = {"kind": "StatefulSet", "metadata": {"name": "validator-hoodi-example-slashing-db"},
              "spec": {"replicas": 1, "volumeClaimTemplates": [claim],
                       "persistentVolumeClaimRetentionPolicy": {"whenDeleted": "Retain", "whenScaled": "Retain"}}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            documents = root / "documents.json"
            database = root / "database.json"
            documents.write_text(json.dumps({"kind": "List", "items": [db, {"kind": "Lease"}]}))

            def run(live):
                database.write_text(json.dumps(live))
                return subprocess.run(["jq", "-ne", "--arg", "set", "hoodi-example", "--slurpfile",
                                       "documents", str(documents), "--slurpfile", "database", str(database),
                                       "-f", str(SCRIPT.parent / "lib/preserve-validator-cutover-state.jq")],
                                      capture_output=True, text=True)

            db["spec"]["volumeClaimTemplates"][0]["spec"]["volumeMode"] = "Filesystem"
            result = run(db)
            self.assertEqual(result.returncode, 0, result.stderr)
            items = json.loads(result.stdout)["items"]
            self.assertEqual(len(items), 1)
            self.assertNotIn("volumeClaimTemplates", items[0]["spec"])
            self.assertEqual(items[0]["spec"]["replicas"], 1)
            db["spec"]["volumeClaimTemplates"][0]["spec"]["resources"]["requests"]["storage"] = "100Gi"
            self.assertNotEqual(run(db).returncode, 0)
            db["spec"]["volumeClaimTemplates"][0]["spec"]["resources"]["requests"]["storage"] = "50Gi"
            db["spec"]["persistentVolumeClaimRetentionPolicy"]["whenDeleted"] = "Delete"
            self.assertNotEqual(run(db).returncode, 0)

    def test_manifest_allowlist_and_replica_gate(self):
        entries = [
            ("Service", "slashing-db"), ("StatefulSet", "slashing-db"),
            ("Service", "remote-signer-direct"), ("Deployment", "remote-signer"),
            ("Lease", "primary"), ("NetworkPolicy", "signer-dependencies"),
            ("NetworkPolicy", "db-dependencies"), ("NetworkPolicy", "signer-ingress"),
            ("NetworkPolicy", "db-ingress"), ("Service", "client-headless"),
            ("StatefulSet", "client"), ("NetworkPolicy", "client-egress"),
            ("NetworkPolicy", "beacon-ingress"), ("ConfigMap", "client-lease-fence"),
            ("ServiceAccount", "client-fence"), ("Role", "client-lease-fence"),
            ("RoleBinding", "client-lease-fence"), ("Deployment", "signing-fence"),
            ("Service", "remote-signer"), ("NetworkPolicy", "signing-fence-ingress"),
            ("NetworkPolicy", "signing-fence-egress")]
        items = [{"kind": kind, "metadata": {
            "name": "validator-hoodi-example-" + suffix,
            "namespace": "node-operator" if suffix == "beacon-ingress" else "validator-operations"},
            "spec": {"replicas": 1 if suffix == "slashing-db" else 0}}
            for kind, suffix in entries]

        def check(objects):
            return subprocess.run(["jq", "-ne", "--arg", "set", "hoodi-example",
                                   "--slurpfile", "documents", "/dev/stdin", "-f",
                                   str(SCRIPT.parent / "lib/validator-cutover-manifests.jq")],
                                  input=json.dumps({"kind": "List", "items": objects}),
                                  capture_output=True, text=True).returncode

        self.assertEqual(check(items), 0)
        items[3]["spec"]["replicas"] = 1
        self.assertNotEqual(check(items), 0)
        items[3]["spec"]["replicas"] = 0
        self.assertNotEqual(check(items + [{"kind": "Secret", "metadata": {"name": "extra"}}]), 0)
        self.assertNotEqual(check(items[:-1]), 0)
        items[0]["metadata"]["namespace"] = "other"
        self.assertNotEqual(check(items), 0)

    def invoke(self, replicas=0, observed=2, pods=None, desired=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            controller = {"metadata": {"generation": 2},
                          "spec": {"replicas": desired},
                          "status": {"replicas": replicas, "observedGeneration": observed}}
            (root / "controller.json").write_text(json.dumps(controller))
            (root / "pods.json").write_text(json.dumps({"items": pods or []}))
            kubectl = root / "kubectl"
            kubectl.write_text('#!/bin/bash\ncase "$*" in\n'
                               '*"get pods"*) cat "$FIXTURES/pods.json";;\n'
                               '*) cat "$FIXTURES/controller.json";;\nesac\n')
            kubectl.chmod(0o700)
            return subprocess.run(["bash", str(SCRIPT), "--validator-set", "hoodi-example"],
                                  capture_output=True, text=True,
                                  env={**os.environ, "FIXTURES": directory,
                                       "PATH": f"{directory}:{os.environ['PATH']}"})

    def test_stopped(self):
        self.assertEqual(self.invoke().returncode, 0)

    def test_desired_running(self):
        self.assertNotEqual(self.invoke(desired=1).returncode, 0)

    def test_observed_running(self):
        self.assertNotEqual(self.invoke(replicas=1).returncode, 0)

    def test_stale_controller_status(self):
        self.assertNotEqual(self.invoke(observed=1).returncode, 0)

    def test_terminating_client_is_not_stopped(self):
        pod = {"metadata": {"name": "validator-hoodi-example-client-0",
                            "deletionTimestamp": "2026-09-10T00:00:00Z"}}
        self.assertNotEqual(self.invoke(pods=[pod]).returncode, 0)

    def test_fence_pod_blocks(self):
        pod = {"metadata": {"name": "validator-hoodi-example-signing-fence-abc-123"}}
        self.assertNotEqual(self.invoke(pods=[pod]).returncode, 0)

    def test_labelled_nonstandard_pod_blocks(self):
        pod = {"metadata": {"name": "custom-client-pod", "labels": {
            "node-operator.io/validator-set": "hoodi-example",
            "app.kubernetes.io/component": "validator-client"}}}
        self.assertNotEqual(self.invoke(pods=[pod]).returncode, 0)

    def test_other_validator_does_not_block(self):
        pod = {"metadata": {"name": "validator-hoodi-002-client-0"}}
        self.assertEqual(self.invoke(pods=[pod]).returncode, 0)


if __name__ == "__main__":
    unittest.main()

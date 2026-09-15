#!/usr/bin/env python3
# Check objective: Verify validator runtime probe rendering with a synthetic public identity.
import importlib.util, json, pathlib, subprocess, sys, unittest

ROOT = pathlib.Path(__file__).parents[2]
R = ROOT / "scripts/ops/render-validator-runtime-probes.py"
# Renderer tests need only a valid public-key shape, never a live identity.
KEY = "0x" + "ab" * 48
IMG = (
    "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-signer-identity-probe@sha256:"
    + "a" * 64
)


class T(unittest.TestCase):
    def test_network_negative_has_no_engine_identity_or_credentials(self):
        spec = importlib.util.spec_from_file_location("renderer", R)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        p = module.engine_network_deny("hoodi-example", KEY, IMG, "test1")
        self.assertNotIn("app.kubernetes.io/name", p["metadata"]["labels"])
        self.assertFalse(p["spec"]["volumes"])
        self.assertFalse(p["spec"]["containers"][0]["volumeMounts"])
        self.assertEqual(p["spec"]["containers"][0]["args"], ["--mode", "engine-network-deny", "--validator-set", "hoodi-example"])
    def test_engine_auth_secret_isolation(self):
        spec = importlib.util.spec_from_file_location("renderer", R)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for case in ("prepositive", "postpositive", "missing", "wrong"):
            p = module.engine_auth(case, "hoodi-example", KEY, IMG, "test1")
            a = p["metadata"]["annotations"]
            c = p["spec"]["containers"][0]
            self.assertEqual(c["args"][:2], ["--mode", "engine-auth"])
            self.assertEqual(c["volumeMounts"], [])
            self.assertTrue(p["spec"]["readinessGates"])
            self.assertNotIn("ports", c)
            if case in ("missing", "wrong"):
                self.assertFalse(any(k.startswith("vault.hashicorp.com/") for k in a))
                self.assertEqual(p["spec"]["volumes"], [])
            else:
                self.assertEqual(a["vault.hashicorp.com/role"], "hoodi-engine-prysm")
                self.assertEqual(a["vault.hashicorp.com/secret-volume-path"], "/engine")
                self.assertEqual(a["vault.hashicorp.com/agent-pre-populate-only"], "true")

    def test_engine_never_ready_placement(self):
        spec = importlib.util.spec_from_file_location("renderer", R)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for role, sa, app in (("nethermind", "nethermind-execution", "nethermind"), ("prysm", "prysm-beacon", "prysm-beacon")):
            pod = module.engine_vault(role, "hoodi-example", KEY, IMG, "test1")
            self.assertEqual(pod["metadata"]["namespace"], "node-operator")
            self.assertEqual(pod["spec"]["serviceAccountName"], sa)
            self.assertEqual(pod["metadata"]["labels"]["app.kubernetes.io/name"], app)
            self.assertTrue(pod["spec"]["readinessGates"])
            container = pod["spec"]["containers"][0]
            self.assertNotIn("ports", container)
            self.assertEqual(container["readinessProbe"]["exec"]["command"], ["/validator-runtime-probe", "--mode", "never-ready"])
            self.assertTrue(container["securityContext"]["runAsNonRoot"])

    def doc(self):
        return json.loads(
            subprocess.check_output(
                [
                    sys.executable,
                    R,
                    "--validator-set",
                    "hoodi-example",
                    "--expected-public-key",
                    KEY,
                    "--image",
                    IMG,
                    "--run-id",
                    "abc-1",
                ],
                text=True,
            )
        )

    def test_layout(self):
        xs = self.doc()["items"]
        self.assertEqual(len(xs), 8)
        self.assertEqual(len({x["metadata"]["name"] for x in xs}), 8)
        tls = [x for x in xs if "runtime-tls-" in x["metadata"]["name"]]
        self.assertEqual(len(tls), 5)
        for x in tls:
            a = x["metadata"]["annotations"]
            self.assertEqual(
                x["metadata"]["labels"]["app.kubernetes.io/component"],
                "validator-signing-fence",
            )
            self.assertEqual(
                x["spec"]["readinessGates"][0]["conditionType"],
                "node-operator.io/never-ready-runtime-diagnostic",
            )
            self.assertEqual(a["vault.hashicorp.com/tls-secret"], "vault-agent-ca")
            self.assertEqual(a["vault.hashicorp.com/ca-cert"], "/vault/tls/ca.crt")
            self.assertEqual(
                a["vault.hashicorp.com/tls-server-name"], "vault.vault.svc"
            )
            self.assertEqual(x["spec"]["containers"][0]["args"][0:2], ["--mode", "tls"])
        for x in tls:
            if any(
                r in x["metadata"]["name"] for r in ("no-client", "untrusted-client")
            ):
                self.assertNotIn(
                    "vault.hashicorp.com/agent-inject-template-tls.key",
                    x["metadata"]["annotations"],
                )
                self.assertNotIn(
                    "vault.hashicorp.com/agent-inject-template-tls.crt",
                    x["metadata"]["annotations"],
                )
        self.assertNotIn("validator-hoodi-example-client-tls", json.dumps(tls))

    def test_vault_roles(self):
        xs = [
            x for x in self.doc()["items"] if "runtime-vault-" in x["metadata"]["name"]
        ]
        self.assertEqual(
            {x["spec"]["serviceAccountName"] for x in xs},
            {"validator-client", "validator-slashing-db", "validator-remote-signer"},
        )
        for x in xs:
            self.assertNotIn(
                "vault.hashicorp.com/agent-inject", x["metadata"]["annotations"]
            )
            self.assertEqual(
                x["spec"]["containers"][0]["securityContext"]["readOnlyRootFilesystem"],
                True,
            )
            self.assertEqual(x["spec"]["activeDeadlineSeconds"], 120)

    def test_bad_image_and_run_id_rejected(self):
        for image, run in (
            (IMG.replace("identity-probe", "wrong"), "abc-"),
            (IMG, "A"),
        ):
            self.assertNotEqual(
                subprocess.run(
                    [
                        sys.executable,
                        R,
                        "--validator-set",
                        "hoodi-example",
                        "--expected-public-key",
                        KEY,
                        "--image",
                        image,
                        "--run-id",
                        run,
                    ],
                    capture_output=True,
                ).returncode,
                0,
            )


if __name__ == "__main__":
    unittest.main()

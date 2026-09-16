#!/usr/bin/env python3
"""Offline contract for complete local installer artifact publication."""
from __future__ import annotations
import hashlib, json, os, subprocess, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PUBLISHER = ROOT / "scripts/release/local-installer-artifact-publisher.sh"
REVISION = "a" * 40
FIRST_PARTY = {"vault-bootstrap", "gitops-oci-mirror", "vault-audit-relay", "prysm-validator", "validator-signing-fence", "validator-signer-identity-probe"}
MIRRORED = {"vault-server", "vault-injector", "cert-manager-controller", "cert-manager-webhook", "cert-manager-cainjector", "cert-manager-startupapicheck"}
CHARTS = {"vault-chart", "cert-manager-chart"}

class LocalPublisher(unittest.TestCase):
    def test_populates_every_indexless_gap_from_reviewed_bundle_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); bundle = root / "bundle"; source = bundle / "source"; work = root / "work"; work.mkdir()
            dockerfiles = {"vault-bootstrap": ".ci/toolchains/vault-bootstrap.Dockerfile", "gitops-oci-mirror": ".ci/toolchains/gitops-oci-mirror.Dockerfile", "vault-audit-relay": ".ci/vault-audit-relay/Dockerfile", "prysm-validator": ".ci/prysm-mtls/Dockerfile", "validator-signing-fence": ".ci/validator-signing-fence/Dockerfile", "validator-signer-identity-probe": ".ci/validator-signer-identity-probe/Dockerfile"}
            for relative in dockerfiles.values():
                path = source / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("FROM scratch\n")
            vault_archive = b"vault archive"; cert_archive = b"cert archive"; client_archive = b"client archive"
            catalog = {"version": 1, "helm_archives": [
                {"name":"vault","version":"0.31.0","source":"https://example.invalid/vault","sha256":hashlib.sha256(vault_archive).hexdigest(),"ecrManifestDigest":"sha256:"+"e"*64,"destination":"vault","ecrTag":"0.31.0"},
                {"name":"cert-manager","version":"v1.21.1","source":"https://example.invalid/cert","sha256":hashlib.sha256(cert_archive).hexdigest(),"ecrManifestDigest":"sha256:"+"f"*64,"destination":"cert-manager","ecrTag":"v1.21.1"}], "artifacts": []}
            for component, prefix, digit in (("vault-server","docker.io/hashicorp/vault@","1"),("vault-injector","docker.io/hashicorp/vault-k8s@","2"),("cert-manager-controller","quay.io/jetstack/cert-manager-controller@","3"),("cert-manager-webhook","quay.io/jetstack/cert-manager-webhook@","4"),("cert-manager-cainjector","quay.io/jetstack/cert-manager-cainjector@","5"),("cert-manager-startupapicheck","quay.io/jetstack/cert-manager-startupapicheck@","6")):
                catalog["artifacts"].append({"source":prefix+"sha256:"+digit*64})
            catalog_path = source / ".ci/gitops/approved-oci-artifacts.json"; catalog_path.parent.mkdir(parents=True); catalog_path.write_text(json.dumps(catalog))
            client = source / "release/node-operator-client-chart.tgz"; client.parent.mkdir(); client.write_bytes(client_archive)
            (source / "release/node-operator-client-chart.json").write_text(json.dumps({"version":"0.1.99","archive_sha256":hashlib.sha256(client_archive).hexdigest()}))
            (bundle / "bundle-manifest.json").write_text("{}")
            bin_dir = root / "bin"; bin_dir.mkdir(); log = root / "log"
            (bin_dir / "docker").write_text("#!/bin/sh\nprintf 'docker:%s\\n' \"$1\" >> \"$LOG\"\nexit 0\n")
            (bin_dir / "helm").write_text("#!/bin/sh\nprintf 'helm:%s\\n' \"$1\" >> \"$LOG\"\nexit 0\n")
            (bin_dir / "curl").write_text("#!/bin/sh\nout=''; url=''; while [ \"$#\" -gt 0 ]; do [ \"$1\" = --output ] && { out=$2; shift; }; url=$1; shift; done\ncase \"$url\" in *vault*) printf 'vault archive' > \"$out\";; *cert*) printf 'cert archive' > \"$out\";; *) exit 64;; esac\n")
            (bin_dir / "aws").write_text("#!/bin/sh\nprintf 'aws:%s\\n' \"$1\" >> \"$LOG\"\ncase \"$*\" in *get-login-password*) printf token;; *vault-chart*|*0.31.0*) printf 'sha256:%064d\\n' 0 | tr 0 e;; *cert-manager-chart*|*v1.21.1*) printf 'sha256:%064d\\n' 0 | tr 0 f;; *vault-server*) printf 'sha256:%064d\\n' 0 | tr 0 1;; *vault-injector*) printf 'sha256:%064d\\n' 0 | tr 0 2;; *cert-manager-controller*) printf 'sha256:%064d\\n' 0 | tr 0 3;; *cert-manager-webhook*) printf 'sha256:%064d\\n' 0 | tr 0 4;; *cert-manager-cainjector*) printf 'sha256:%064d\\n' 0 | tr 0 5;; *cert-manager-startupapicheck*) printf 'sha256:%064d\\n' 0 | tr 0 6;; *node-operator-client*) printf 'sha256:%064d\\n' 0 | tr 0 9;; *vault-bootstrap*) printf 'sha256:%064d\\n' 0 | tr 0 b;; *gitops-oci-mirror*) printf 'sha256:%064d\\n' 0 | tr 0 c;; *vault-audit-relay*) printf 'sha256:%064d\\n' 0 | tr 0 d;; *prysm-validator*) printf 'sha256:%064d\\n' 0 | tr 0 a;; *validator-signing-fence*) printf 'sha256:%064d\\n' 0 | tr 0 7;; *validator-signer-identity-probe*) printf 'sha256:%064d\\n' 0 | tr 0 8;; *) exit 64;; esac\n")
            (bin_dir / "cosign").write_text("#!/bin/sh\nprintf 'cosign:%s\\n' \"$1\" >> \"$LOG\"\nif [ \"$1\" = generate-key-pair ]; then while [ \"$#\" -gt 0 ]; do [ \"$1\" = --output-key-prefix ] && p=$2; shift; done; : > \"$p.key\"; : > \"$p.pub\"; elif [ \"$1\" = sign-blob ]; then while [ \"$#\" -gt 0 ]; do [ \"$1\" = --bundle ] && b=$2; shift; done; : > \"$b\"; fi\n")
            for path in bin_dir.iterdir(): path.chmod(0o755)
            output = work / "local-artifact-authority.json"
            env = os.environ | {"PATH": f"{bin_dir}:{os.environ['PATH']}", "LOG": str(log), "AWS_ACCESS_KEY_ID": "blocked", "AWS_SECRET_ACCESS_KEY": "blocked", "AWS_SESSION_TOKEN": "blocked"}
            result = subprocess.run([str(PUBLISHER), "--bundle-root", str(bundle), "--work-dir", str(work), "--account", "123456789012", "--region", "ap-northeast-2", "--deployment-name", "node-operator", "--release-sha", REVISION, "--output", str(output)], text=True, capture_output=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            authority = json.loads(output.read_text()); components = {item["component"] for item in authority["artifacts"]}
            self.assertEqual(components, FIRST_PARTY | MIRRORED | CHARTS | {"node-operator-client-chart"})
            self.assertTrue(all("@sha256:" in item["source"] for item in authority["artifacts"]))
            self.assertIn("docker:buildx", log.read_text()); self.assertIn("helm:push", log.read_text()); self.assertIn("cosign:sign-blob", log.read_text())
            self.assertNotIn("aws:sts", log.read_text())

if __name__ == "__main__": unittest.main()

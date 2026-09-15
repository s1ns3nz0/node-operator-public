#!/usr/bin/env python3
"""Explicit-env, local integration of onboarding with real crypto and TLS helpers.

Vault is faked; no cloud, custody key, or deployment is used.
"""
import base64, json, os, shutil, subprocess, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UPSTREAM = os.environ.get("CUSTODY_VERIFIER_UPSTREAM_ROOT")
PYTHON = os.environ.get("CUSTODY_VERIFIER_PYTHON")
SET = "hoodi-example"
SERVER = f"validator-{SET}-remote-signer.validator-operations.svc"
CLIENT = f"validator-{SET}-client.validator-operations.svc"
PASSWORD = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"

class OnboardingIntegration(unittest.TestCase):
    def setUp(self):
        if not UPSTREAM or not PYTHON:
            self.fail("CUSTODY_VERIFIER_UPSTREAM_ROOT and CUSTODY_VERIFIER_PYTHON are required")
        self.upstream, self.python = Path(UPSTREAM), Path(PYTHON)
        if not self.upstream.is_dir() or not self.python.is_file(): self.fail("explicit verifier environment is unavailable")
        self.temp = tempfile.TemporaryDirectory(); self.base = Path(self.temp.name)
        self.bundle = self.base / "bundle/source"; ops = self.bundle / "scripts/ops"; (ops / "lib").mkdir(parents=True)
        for name in ("recover-and-onboard-hoodi-validator-keystore.sh", "verify-custody-keystore-secret.py", "verify-hoodi-vault-v2-transport-records.sh"):
            shutil.copy2(ROOT / "scripts/ops" / name, ops / name); (ops / name).chmod(0o700)
        lock = self.bundle / ".ci/custody-verifier"; lock.mkdir(parents=True)
        shutil.copy2(ROOT / ".ci/custody-verifier/source-lock.json", lock / "source-lock.json")
        (ops / "lib/vault-recovery-auth.sh").write_text("vault_recovery_auth_preflight(){ :; }\nvault_recovery_decode_generated_root(){ printf root; }\n")
        (ops / "configure-hoodi-vault-kubernetes-auth.sh").write_text("#!/usr/bin/env bash\nexit 0\n"); (ops / "configure-hoodi-vault-kubernetes-auth.sh").chmod(0o700)
        # The partial-record path calls these after the stored candidate has
        # already passed the real crypto and TLS checks.  Keep their behavior
        # inert here: this fixture is exercising record convergence, not the
        # separately tested Vault bootstrap helpers.
        for name in ("bootstrap-node-operator-vault-v2.sh", "bootstrap-hoodi-validator-runtime-vault.sh"):
            helper = ops / name
            helper.write_text("#!/usr/bin/env bash\nset -eu\nprintf 'bootstrap %s\\n' \"${0##*/}\" >> \"$TRACE\"\n")
            helper.chmod(0o700)
        self.records = self.base / "records"; self.records.mkdir(); self.trace = self.base / "trace"; self.keys = self.base / "keys"; self.keys.mkdir()
        shutil.copy2(self.upstream / "tests/test_key_handling/keystore_test_vectors/test0.json", self.keys / "keystore-test.json")
        self.public_key = "0x" + json.loads((self.keys / "keystore-test.json").read_text())["pubkey"]
        self._certificates(); self._records(); self._vault()

    def tearDown(self): self.temp.cleanup()
    def openssl(self,*args): return subprocess.run(["openssl",*args],check=True,capture_output=True,text=True).stdout
    def _certificates(self):
        self.ca_key=self.base/"ca.key"; self.ca=self.base/"ca.crt"; self.openssl("genrsa","-out",str(self.ca_key),"2048"); self.openssl("req","-x509","-new","-key",str(self.ca_key),"-days","2","-subj","/CN=test-ca","-out",str(self.ca))
        def leaf(stem, cn, eku, san=None):
            key=self.base/f"{stem}.key"; csr=self.base/f"{stem}.csr"; cert=self.base/f"{stem}.crt"; ext=self.base/f"{stem}.ext"; self.openssl("genrsa","-out",str(key),"2048"); self.openssl("req","-new","-key",str(key),"-subj",f"/CN={cn}","-out",str(csr)); ext.write_text(f"subjectAltName=DNS:{san or cn}\nextendedKeyUsage={eku}\n"); self.openssl("x509","-req","-in",str(csr),"-CA",str(self.ca),"-CAkey",str(self.ca_key),"-CAcreateserial","-days","2","-out",str(cert),"-extfile",str(ext)); return key,cert
        self.server_key,self.server=leaf("server",SERVER,"serverAuth"); self.client_key,self.client=leaf("client",CLIENT,"clientAuth",CLIENT+".cluster.local")
    def _records(self):
        p12=self.base/"server.p12"; pw=self.base/"p12-password"; pw.write_text("fixture-password"); pw.chmod(0o600); self.openssl("pkcs12","-export","-inkey",str(self.server_key),"-in",str(self.server),"-certfile",str(self.ca),"-out",str(p12),"-passout",f"file:{pw}")
        b64=lambda p:base64.b64encode(p.read_bytes()).decode()
        values={"keystore":{"keystore":(self.keys/"keystore-test.json").read_text()},"password":{"password":PASSWORD},"slashing-db-password":{"password":"synthetic-slashing"},"signer-tls":{"pkcs12_b64":b64(p12),"password":"fixture-password"},"client-tls":{"tls_crt_b64":b64(self.client),"tls_key_b64":b64(self.client_key),"ca_crt_b64":b64(self.ca)}}
        for name,value in values.items():(self.records/f"{name}.json").write_text(json.dumps(value))
    def _vault(self):
        bindir=self.base/"bin"; bindir.mkdir(); vault=bindir/"vault"
        vault.write_text("#!/usr/bin/env bash\nset -eu\nprintf '%s\\n' \"$*\" >> \"$TRACE\"\ncase \"$1:$2\" in operator:generate-root) case \" $* \" in *' -status '*) echo '{\"started\":false}' ;; *' -init '*) echo '{\"nonce\":\"n\",\"otp\":\"o\",\"required\":1}' ;; *' -nonce=n '*) cat >/dev/null; echo '{\"complete\":true,\"encoded_token\":\"e\"}' ;; *) exit 64;; esac ;; kv:get) name=${!#}; name=${name##*/}; if [ -f \"$RECORDS/$name.json\" ]; then printf '{\"data\":{\"data\":'; cat \"$RECORDS/$name.json\"; printf '}}\\n'; else printf 'No value found at node-operator-runtime/data/validators/hoodi/hoodi-example/runtime/%s\\n' \"$name\" >&2; exit 2; fi ;; kv:put) name=${4##*/}; [ \"${ALLOW_PUT_RECORD:-}\" = \"$name\" ] && [ ! -e \"$RECORDS/$name.json\" ] || exit 64; if [ \"${CAS_RACE_RECORD:-}\" = \"$name\" ]; then printf '{\"password\":\"\"}' > \"$RECORDS/$name.json\"; exit 9; fi; cp \"${5#@}\" \"$RECORDS/$name.json\" ;; token:create) printf child ;; token:revoke) : ;; *) exit 64;; esac\n")
        vault.chmod(0o700); self.bin=bindir
    def invoke(self, **extra):
        env=os.environ.copy(); env.update({"PATH":f"{self.bin}:{env['PATH']}","PRIVATE_VAULT_SESSION":"1","VAULT_TOKEN":"synthetic","TRACE":str(self.trace),"RECORDS":str(self.records),"TMPDIR":str(self.base),"CUSTODY_VERIFIER_PYTHON":str(self.python),"CUSTODY_VERIFIER_UPSTREAM_ROOT":str(self.upstream)})
        env.update({key:str(value) for key,value in extra.items()})
        return subprocess.run(["bash",str(self.bundle/"scripts/ops/recover-and-onboard-hoodi-validator-keystore.sh"),"--validator-set",SET,"--keystore-dir",str(self.keys),"--signer-ca-output",str(self.base/"out/ca.crt"),"--known-clients-output",str(self.base/"out/known"),"--expected-public-key",self.public_key],input="share\n",text=True,capture_output=True,env=env,timeout=30)
    def test_all_present_real_crypto_tls_reconstructs_without_write_or_password_prompt(self):
        result=self.invoke(); self.assertEqual(result.returncode,0,result.stderr); self.assertEqual((self.base/"out/ca.crt").read_bytes(),self.ca.read_bytes()); self.assertIn("coherently verified",result.stdout); calls=self.trace.read_text(); self.assertNotIn("kv put",calls); self.assertNotIn("token create",calls); self.assertNotIn("Keystore password",result.stderr)
    def test_incoherent_stored_password_rejects_before_write(self):
        (self.records/"password.json").write_text(json.dumps({"password":"wrong"})); result=self.invoke(); self.assertEqual(result.returncode,65); self.assertNotIn("kv put",self.trace.read_text()); self.assertFalse((self.base/"out").exists())

    def test_missing_slashing_record_is_the_only_cas_write_and_winner_is_revalidated(self):
        preserved={name:(self.records/f"{name}.json").read_bytes() for name in ("keystore","password","signer-tls","client-tls")}
        (self.records/"slashing-db-password.json").unlink()
        result=self.invoke(ALLOW_PUT_RECORD="slashing-db-password")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.records/"slashing-db-password.json").is_file())
        for name,value in preserved.items(): self.assertEqual((self.records/f"{name}.json").read_bytes(),value)
        writes=[line for line in self.trace.read_text().splitlines() if line.startswith("kv put")]
        self.assertEqual(len(writes),1); self.assertIn("/slashing-db-password ",writes[0])
        self.assertEqual((self.base/"out/ca.crt").read_bytes(),self.ca.read_bytes())

    def test_cas_race_with_incoherent_winner_is_rejected_before_public_output(self):
        (self.records/"slashing-db-password.json").unlink()
        result=self.invoke(ALLOW_PUT_RECORD="slashing-db-password", CAS_RACE_RECORD="slashing-db-password")
        self.assertEqual(result.returncode,65,result.stderr)
        self.assertEqual(json.loads((self.records/"slashing-db-password.json").read_text()), {"password":""})
        self.assertEqual(len([line for line in self.trace.read_text().splitlines() if line.startswith("kv put")]),1)
        self.assertFalse((self.base/"out").exists())

if __name__ == "__main__": unittest.main()

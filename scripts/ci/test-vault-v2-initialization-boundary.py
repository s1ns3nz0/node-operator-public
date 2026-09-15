#!/usr/bin/env python3
# Check objective: Validate fresh Vault initialization boundaries with synthetic tools.
"""Exercise fresh Vault initialization boundaries with synthetic local CLIs only."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InitializationBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.ops = self.base / "checkout/scripts/ops"; (self.ops / "lib").mkdir(parents=True)
        self.script = self.ops / "recover-and-bootstrap-hoodi-vault-v2.sh"
        shutil.copy2(ROOT / "scripts/ops" / self.script.name, self.script)
        shutil.copy2(ROOT / "scripts/ops/configure-hoodi-vault-kubernetes-auth.sh", self.ops / "configure-hoodi-vault-kubernetes-auth.sh")
        (self.ops / "lib/vault-recovery-auth.sh").write_text("vault_recovery_auth_preflight() { :; }\nvault_recovery_decode_generated_root() { printf root-sentinel; }\n")
        for name in ("bootstrap-node-operator-vault-v2.sh", "bootstrap-hoodi-validator-runtime-vault.sh"):
            path = self.ops / name; path.write_text("#!/bin/bash\necho bootstrap >> \"$EVENTS\"\n"); path.chmod(0o700)
        engine = self.ops / "bootstrap-hoodi-engine-api-vault.sh"
        engine.write_text("#!/bin/bash\n[ -f \"$AUTH_CONFIGURED\" ] || { echo engine-without-kubernetes-auth >> \"$EVENTS\"; exit 78; }\necho bootstrap >> \"$EVENTS\"\n"); engine.chmod(0o700)
        self.bin = self.base / "bin"; self.bin.mkdir(); self.state = self.base / "state"; self.events = self.base / "events"; self.calls = self.base / "calls"; self.auth_enabled = self.base / "auth-enabled"; self.auth_configured = self.base / "auth-configured"; self.auth_ready = self.base / "auth-ready"
        vault = self.bin / "vault"
        vault.write_text('''#!/bin/bash
case "$1 $2" in
  "status -format=json") if [ -e "$STATE" ]; then printf '{"initialized":true,"sealed":%s,"cluster_id":"cluster-a"}\n' "${SEALED:-false}"; else echo '{"initialized":false}'; fi ;;
  "operator init") echo "$*" >> "$CALLS"; : > "$STATE"; if [ "${MALFORMED:-0}" = 1 ]; then echo '{}'; else echo '{"root_token":"root-sentinel","recovery_keys_b64":["share-1","share-2","share-3","share-4","share-5"]}'; fi ;;
  "token revoke") echo revoke >> "$EVENTS"; exit "${REVOKE_RC:-0}" ;;
  "auth list")
    if [ "${AUTH_SLEEP:-0}" = 1 ]; then : > "$AUTH_READY"; sleep 30; fi
    [ "${AUTH_MODE:-missing}" != list-error ] || { printf '%s\n' 'transport failure' >&2; exit 2; }
    if [ "${AUTH_MODE:-missing}" = wrong-type ]; then echo '{"kubernetes/":{"type":"jwt"}}'
    elif [ "${AUTH_MODE:-missing}" = missing ] && [ ! -e "$AUTH_ENABLED" ]; then echo '{}'
    else echo '{"kubernetes/":{"type":"kubernetes"}}'; fi ;;
  "auth enable") : > "$AUTH_ENABLED" ;;
  "read -format=json")
    [ "${AUTH_MODE:-missing}" != read-error ] || { printf '%s\n' 'permission denied' >&2; exit 2; }
    if [ "${AUTH_MODE:-missing}" = wrong-host ]; then echo '{"data":{"kubernetes_host":"https://another.cluster:443","disable_local_ca_jwt":false,"token_reviewer_jwt_set":false,"kubernetes_ca_cert":""}}'
    elif [ "${AUTH_MODE:-missing}" = matching ] || [ -e "$AUTH_CONFIGURED" ]; then : > "$AUTH_CONFIGURED"; echo '{"data":{"kubernetes_host":"https://kubernetes.default.svc:443","disable_local_ca_jwt":false,"token_reviewer_jwt_set":false,"kubernetes_ca_cert":""}}'
    else printf '%s\n' 'No value found at auth/kubernetes/config' >&2; exit 2; fi ;;
  "write auth/kubernetes/config")
    [ "${AUTH_CONFIG_FAIL:-0}" != 1 ] || exit 2
    [[ "$*" == *'kubernetes_host=https://kubernetes.default.svc:443'* ]] && [[ "$*" == *'disable_local_ca_jwt=false'* ]] || exit 64
    : > "$AUTH_CONFIGURED" ;;
  *) echo "$*" >> "$CALLS"; if [[ "$*" == *"generate-root -status"* ]]; then if [ "${ROOT_STARTED:-0}" = 1 ]; then echo '{"started":true,"progress":1,"required":3}'; else echo '{"started":false}'; fi; elif [[ "$*" == *"generate-root -init"* ]]; then echo '{"nonce":"n","otp":"o","required":1}'; elif [[ "$*" == *"generate-root -nonce"* ]]; then echo '{"complete":true,"encoded_token":"e"}'; elif [[ "$*" == *"generate-root -cancel"* ]]; then exit 0; else exit 64; fi ;;
esac
'''); vault.chmod(0o700)
        self.real_rm = shutil.which("rm")
        remover = self.bin / "rm"
        remover.write_text('''#!/bin/bash
for argument in "$@"; do case "$argument" in *vault-init-response.*) [ "${FAIL_RAW_RM:-0}" = 1 ] && exit 1 ;; esac; done
exec "$REAL_RM" "$@"
'''); remover.chmod(0o700)

    def tearDown(self): self.temp.cleanup()

    def invoke(self, data, directory, extra_args=(), **extra):
        return subprocess.run(["bash", str(self.script), "--validator-set", "hoodi-example", "--recovery-output-dir", str(directory), *extra_args], input=data, text=True, capture_output=True, env={**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}", "REAL_RM":self.real_rm, "PRIVATE_VAULT_SESSION":"1", "VAULT_ADDR":"https://vault.test", "STATE":str(self.state), "EVENTS":str(self.events), "CALLS":str(self.calls), "AUTH_ENABLED":str(self.auth_enabled), "AUTH_CONFIGURED":str(self.auth_configured), **extra})

    def test_completion_verification_never_replays_administrator_ceremony(self):
        output = self.base / "completed"; output.mkdir(mode=0o700); self.state.touch()
        checkpoint = output / "vault-initialization-checkpoint.json"
        checkpoint.write_text('{"schema_version":1,"status":"configured","cluster_id":"cluster-a","validator_set":"hoodi-example","shares":5,"threshold":3,"root_revoked":true}')
        checkpoint.chmod(0o600)
        before = checkpoint.read_bytes()
        result = self.invoke("", output, extra_args=("--verify-initialization-completion",))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no administrator ceremony was replayed", result.stdout)
        self.assertFalse(self.calls.exists()); self.assertFalse(self.events.exists())
        self.assertEqual(checkpoint.read_bytes(), before)

    def test_completion_verification_rejects_pending_or_mismatched_state_without_recovery(self):
        import json
        self.state.touch()
        for case in ("missing", "backup-pending", "cluster", "revocation", "sealed"):
            output = self.base / case; output.mkdir(mode=0o700)
            value = {"schema_version":1,"status":"configured","cluster_id":"cluster-a","validator_set":"hoodi-example","shares":5,"threshold":3,"root_revoked":True}
            if case == "backup-pending": value["status"] = case
            if case == "cluster": value["cluster_id"] = "another-cluster"
            if case == "revocation": value["root_revoked"] = False
            if case != "missing":
                checkpoint = output / "vault-initialization-checkpoint.json"
                checkpoint.write_text(json.dumps(value)); checkpoint.chmod(0o600)
            result = self.invoke("", output, extra_args=("--verify-initialization-completion",), SEALED="true" if case == "sealed" else "false")
            self.assertNotEqual(result.returncode, 0, case)
            self.assertFalse(self.calls.exists()); self.assertFalse(self.events.exists())

    def test_fresh_initialization_uses_explicit_policy_and_private_paths_only(self):
        output = self.base / "recovery"
        result = self.invoke("INIT\nBACKED_UP\n", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("-recovery-shares=5 -recovery-threshold=3", self.calls.read_text())
        self.assertNotIn("share-1", result.stdout + result.stderr); self.assertNotIn("root-sentinel", result.stdout + result.stderr)
        for number in range(1, 6): self.assertEqual((output / f"recovery-share-{number:02}.txt").stat().st_mode & 0o777, 0o600)
        self.assertFalse(any(output.glob("vault-init-response.*")))
        self.assertEqual(self.events.read_text(), "bootstrap\nbootstrap\nbootstrap\nrevoke\n")
        self.assertTrue(self.auth_configured.is_file())

    def test_gnu_stat_does_not_treat_bsd_format_as_a_successful_mode_check(self):
        stat = self.bin / "stat"
        stat.write_text('''#!/bin/bash
if [ "$1" = -c ]; then
  case "$(basename "$3")" in
    vault-init-response.*|vault-initialization-checkpoint.json|recovery-share-*.txt) echo 600 ;;
    *) echo 700 ;;
  esac
else
  printf '%s\\n' 'synthetic GNU filesystem status output'
fi
''')
        stat.chmod(0o700)
        output = self.base / "gnu-stat"
        result = self.invoke("INIT\nBACKED_UP\n", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events.read_text(), "bootstrap\nbootstrap\nbootstrap\nrevoke\n")

    def test_kubernetes_auth_failures_short_circuit_engine_and_still_revoke_root(self):
        for name, extra in (
            ("list-error", {"AUTH_MODE":"list-error"}),
            ("wrong-type", {"AUTH_MODE":"wrong-type"}),
            ("wrong-host", {"AUTH_MODE":"wrong-host"}),
            ("read-error", {"AUTH_MODE":"read-error"}),
            ("write-error", {"AUTH_CONFIG_FAIL":"1"}),
        ):
            with self.subTest(name=name):
                for path in (self.state, self.events, self.calls, self.auth_enabled, self.auth_configured):
                    path.unlink(missing_ok=True)
                output = self.base / f"auth-{name}"
                result = self.invoke("INIT\nBACKED_UP\n", output, **extra)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("engine-without-kubernetes-auth", self.events.read_text() if self.events.exists() else "")
                self.assertEqual(self.events.read_text() if self.events.exists() else "", "bootstrap\nrevoke\n")

    def test_existing_matching_kubernetes_auth_is_verified_before_engine(self):
        output = self.base / "auth-matching"
        result = self.invoke("INIT\nBACKED_UP\n", output, AUTH_MODE="matching")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events.read_text(), "bootstrap\nbootstrap\nbootstrap\nrevoke\n")

    def test_kubernetes_auth_interrupt_exits_without_success_or_configuration_write(self):
        process = subprocess.Popen(
            ["bash", str(self.ops / "configure-hoodi-vault-kubernetes-auth.sh")],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
            env={**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}", "REAL_RM":self.real_rm, "VAULT_ADDR":"https://vault.test", "VAULT_TOKEN":"root-sentinel", "STATE":str(self.state), "EVENTS":str(self.events), "CALLS":str(self.calls), "AUTH_ENABLED":str(self.auth_enabled), "AUTH_CONFIGURED":str(self.auth_configured), "AUTH_READY":str(self.auth_ready), "AUTH_MODE":"matching", "AUTH_SLEEP":"1"},
        )
        try:
            deadline = time.monotonic() + 3
            while not self.auth_ready.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(self.auth_ready.exists(), "fake auth-list command did not become ready")
            os.killpg(process.pid, signal.SIGINT)
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 130, stdout + stderr)
            self.assertNotIn("PASS", stdout + stderr)
            self.assertFalse(self.auth_configured.exists())
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)

    def test_backup_exit_is_pending_nonzero_and_preserves_private_material(self):
        output = self.base / "pending"
        result = self.invoke("INIT\nEXIT\n", output)
        self.assertEqual(result.returncode, 75)
        self.assertTrue(any(output.glob("vault-init-response.*")))
        self.assertTrue((output / "vault-initialization-checkpoint.json").is_file())
        self.assertFalse(self.events.read_text().startswith("bootstrap"))
        self.assertEqual(self.events.read_text(), "revoke\n")

    def test_backup_acknowledgement_raw_deletion_failure_stays_pending(self):
        output = self.base / "delete-failure"
        result = self.invoke("INIT\nBACKED_UP\n", output, FAIL_RAW_RM="1")
        self.assertEqual(result.returncode, 70)
        self.assertTrue(any(output.glob("vault-init-response.*")))
        self.assertEqual(__import__("json").loads((output / "vault-initialization-checkpoint.json").read_text())["status"], "backup-pending")
        self.assertNotIn("PASS", result.stdout + result.stderr)

    def test_checkpoint_cluster_mismatch_rejects_without_recovery_ceremony(self):
        output = self.base / "mismatch"; output.mkdir(mode=0o700); self.state.touch()
        (output / "vault-initialization-checkpoint.json").write_text('{"schema_version":1,"status":"backup-pending","cluster_id":"other","validator_set":"hoodi-example","shares":5,"threshold":3}')
        result = self.invoke("BACKED_UP\n", output)
        self.assertEqual(result.returncode, 65)
        self.assertFalse(self.events.exists())

    def test_symlink_or_existing_share_is_rejected_before_init(self):
        target = self.base / "target"; target.mkdir(mode=0o700)
        link = self.base / "link"; link.symlink_to(target, target_is_directory=True)
        self.assertEqual(self.invoke("INIT\n", link).returncode, 65)
        output = self.base / "occupied"; output.mkdir(mode=0o700)
        (output / "recovery-share-01.txt").write_text("old")
        self.assertEqual(self.invoke("INIT\n", output).returncode, 65)
        self.assertFalse(self.state.exists())

    def test_symlinked_parent_is_rejected_before_init(self):
        target = self.base / "parent-target"; target.mkdir(mode=0o700)
        parent = self.base / "parent-link"; parent.symlink_to(target, target_is_directory=True)
        self.assertEqual(self.invoke("INIT\n", parent / "recovery").returncode, 65)
        self.assertFalse(self.state.exists())

    def test_automated_flag_cannot_bypass_init_or_backup_acknowledgement(self):
        output = self.base / "automated"
        self.assertEqual(self.invoke("", output, NODE_OPERATOR_AUTOMATED_CEREMONY="1").returncode, 75)
        self.assertFalse(self.state.exists())

    def test_revocation_failure_retains_response_and_has_no_success(self):
        output = self.base / "revoke-failure"
        result = self.invoke("INIT\nBACKED_UP\n", output, REVOKE_RC="1")
        self.assertEqual(result.returncode, 70)
        self.assertTrue(any(output.glob("vault-init-response.*")))
        self.assertNotIn("PASS", result.stdout)

    def test_malformed_init_response_is_private_manual_recovery_failure(self):
        output = self.base / "malformed"
        result = self.invoke("INIT\n", output, MALFORMED="1")
        self.assertEqual(result.returncode, 70)
        self.assertTrue(any(output.glob("vault-init-response.*")))
        self.assertIn("manual recovery", result.stderr)

    def test_matching_pending_resume_configures_without_second_init(self):
        output = self.base / "resume"; output.mkdir(mode=0o700); self.state.touch()
        checkpoint = output / "vault-initialization-checkpoint.json"; checkpoint.write_text('{"schema_version":1,"status":"backup-pending","cluster_id":"cluster-a","validator_set":"hoodi-example","shares":5,"threshold":3,"raw_response":"vault-init-response.fixture"}'); checkpoint.chmod(0o600)
        raw = output / "vault-init-response.fixture"; raw.write_text('{"recovery_keys_b64":["share","share","share","share","share"]}'); raw.chmod(0o600)
        for number in range(1, 6):
            share = output / f"recovery-share-{number:02}.txt"; share.write_text("share"); share.chmod(0o600)
        result = self.invoke("BACKED_UP\nsynthetic-share\n", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("operator init", self.calls.read_text() if self.calls.exists() else "")
        self.assertEqual(__import__("json").loads((output / "vault-initialization-checkpoint.json").read_text())["status"], "configured")

    def test_configured_checkpoint_reconfigures_with_fresh_authenticated_recovery_without_init(self):
        output = self.base / "configured"; output.mkdir(mode=0o700); self.state.touch()
        checkpoint = output / "vault-initialization-checkpoint.json"
        checkpoint.write_text('{"schema_version":1,"status":"configured","cluster_id":"cluster-a","validator_set":"hoodi-example","shares":5,"threshold":3,"root_revoked":true}')
        checkpoint.chmod(0o600)
        result = self.invoke("synthetic-share\n", output, AUTH_MODE="matching")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls.read_text()
        self.assertNotIn("operator init", calls)
        self.assertIn("generate-root -init", calls)
        self.assertEqual(self.events.read_text(), "bootstrap\nbootstrap\nbootstrap\nrevoke\n")
        self.assertEqual(__import__("json").loads(checkpoint.read_text())["status"], "configured")

    def test_configured_checkpoint_rejects_cluster_root_revocation_or_unsafe_metadata(self):
        for kind, value in (("cluster", "other"), ("root", "cluster-a"), ("mode", "cluster-a")):
            with self.subTest(kind=kind):
                output = self.base / f"configured-{kind}"; output.mkdir(mode=0o700); self.state.touch()
                checkpoint = output / "vault-initialization-checkpoint.json"
                revoked = "false" if kind == "root" else "true"
                checkpoint.write_text('{"schema_version":1,"status":"configured","cluster_id":"' + value + '","validator_set":"hoodi-example","shares":5,"threshold":3,"root_revoked":' + revoked + '}')
                checkpoint.chmod(0o644 if kind == "mode" else 0o600)
                result = self.invoke("synthetic-share\n", output)
                self.assertEqual(result.returncode, 65)
                self.assertFalse(self.calls.exists())

    def test_existing_root_ceremony_exit_and_eof_are_pending_not_success(self):
        for response in ("EXIT\n", ""):
            with self.subTest(response=response):
                output = self.base / ("root-exit" if response else "root-eof"); output.mkdir(mode=0o700); self.state.touch()
                result = self.invoke(response, output, ROOT_STARTED="1")
                self.assertEqual(result.returncode, 75)
                self.assertFalse(self.events.exists())
                self.assertNotIn("PASS", result.stdout + result.stderr)

    def test_pending_resume_rejects_missing_or_unsafe_shares(self):
        output = self.base / "unsafe-resume"; output.mkdir(mode=0o700); self.state.touch()
        checkpoint = output / "vault-initialization-checkpoint.json"; checkpoint.write_text('{"schema_version":1,"status":"backup-pending","cluster_id":"cluster-a","validator_set":"hoodi-example","shares":5,"threshold":3,"raw_response":"vault-init-response.fixture"}'); checkpoint.chmod(0o600)
        raw = output / "vault-init-response.fixture"; raw.write_text('{"recovery_keys_b64":["share","share","share","share","share"]}'); raw.chmod(0o600)
        self.assertEqual(self.invoke("BACKED_UP\n", output).returncode, 65)
        for number in range(1, 6):
            share = output / f"recovery-share-{number:02}.txt"; share.write_text("share"); share.chmod(0o600)
        (output / "recovery-share-03.txt").chmod(0o644)
        self.assertEqual(self.invoke("BACKED_UP\n", output).returncode, 65)

    def test_pending_resume_rejects_unsafe_checkpoint_boundaries_before_generate_root(self):
        for kind in ("directory-mode", "checkpoint-mode", "extra-share", "symlink-share"):
            with self.subTest(kind=kind):
                output = self.base / f"resume-{kind}"
                self.state.unlink(missing_ok=True)
                self.assertEqual(self.invoke("INIT\nEXIT\n", output).returncode, 75)
                if kind == "directory-mode": output.chmod(0o755)
                elif kind == "checkpoint-mode": (output / "vault-initialization-checkpoint.json").chmod(0o644)
                elif kind == "extra-share":
                    share = output / "recovery-share-06.txt"; share.write_text("synthetic"); share.chmod(0o600)
                else:
                    target = self.base / "share-target"; target.write_text("synthetic"); target.chmod(0o600)
                    (output / "recovery-share-01.txt").unlink()
                    (output / "recovery-share-01.txt").symlink_to(target)
                before = self.calls.read_text()
                result = self.invoke("BACKED_UP\nsynthetic-share\n", output)
                self.assertEqual(result.returncode, 65)
                self.assertEqual(before, self.calls.read_text())

    def test_pending_two_invocation_resume_uses_owned_raw_then_removes_it(self):
        output = self.base / "two-invocation"
        self.assertEqual(self.invoke("INIT\nEXIT\n", output).returncode, 75)
        raw = next(output.glob("vault-init-response.*"))
        self.assertEqual(self.invoke("BACKED_UP\nsynthetic-share\n", output).returncode, 0)
        self.assertEqual(self.calls.read_text().count("operator init"), 1)
        self.assertFalse(raw.exists())
        self.assertEqual(__import__("json").loads((output / "vault-initialization-checkpoint.json").read_text())["status"], "configured")

    def test_initialized_directory_does_not_delete_unrelated_raw_response(self):
        output = self.base / "external"; output.mkdir(mode=0o700); self.state.touch()
        unrelated = output / "vault-init-response.unrelated"; unrelated.write_text("unrelated")
        self.assertEqual(self.invoke("synthetic-share\n", output).returncode, 0)
        self.assertEqual(unrelated.read_text(), "unrelated")


if __name__ == "__main__": unittest.main()

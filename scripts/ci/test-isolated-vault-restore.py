#!/usr/bin/env python3
# Check objective: Verify interactive isolated Vault restoration guards with offline fixtures.
"""Offline contract tests for the interactive isolated recovery helper."""
import importlib.util
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import base64
import tempfile
import http.server
import threading
import subprocess
from types import SimpleNamespace

sys.dont_write_bytecode = True

SCRIPT = Path(__file__).parents[1] / "ops" / "rehearse-isolated-vault-restore.py"
spec = importlib.util.spec_from_file_location("restore", SCRIPT); restore = importlib.util.module_from_spec(spec); spec.loader.exec_module(restore)

class RestoreTests(unittest.TestCase):
    def test_lost_attempt_response_still_cancels(self):
        c = restore.Ceremony()
        api = unittest.mock.Mock()
        api.request.side_effect = TimeoutError("synthetic lost response")
        with self.assertRaises(TimeoutError): c.begin_root_attempt(api)
        self.assertTrue(c.ceremony_started)
        with patch.object(restore, "LocalVault") as factory:
            c.cleanup()
            factory.return_value.request.assert_called_once_with("DELETE", "/v1/sys/generate-root/attempt")

    def test_raw_base64_all_length_residues(self):
        for length in (24, 25, 26, 27, 28):
            token, otp = b"r" * length, b"A" * length
            encoded = base64.b64encode(bytes(a ^ b for a, b in zip(token, otp))).decode().rstrip("=")
            self.assertEqual(restore.xor_decode(encoded, otp.decode()), token.decode())

    def test_raw_base64_malformed_is_redacted(self):
        for encoded, otp in (("!", "A"), ("A", "A"), ("AA==", "A"), ("AB", "A"), ("AA\n", "A"), ("", "A"), (None, "A"), ("AA", "**"), ("AA", "é"), ("AA", "AA")):
            with self.subTest(encoded=encoded):
                with self.assertRaisesRegex(restore.CeremonyError, "^invalid generate-root OTP material$"):
                    restore.xor_decode(encoded, otp)

    def test_recovery_substages_are_static_and_safe(self):
        c = restore.Ceremony()
        for stage in ("recovery_begin", "recovery_prompt", "recovery_submit", "recovery_decode"):
            c.stage = stage
            result = restore.failure_summary(c, ValueError("SYNTHETIC_SECRET"))
            self.assertIn("stage=" + stage, result)
            self.assertNotIn("SYNTHETIC_SECRET", result)

    def test_prompt_uses_real_nonseekable_terminal(self):
        # Isolate PTY terminal ownership/SIGHUP behavior from the test runner.
        code = '''import os, signal, importlib.util
from unittest.mock import patch
signal.signal(signal.SIGHUP, signal.SIG_IGN)
s=importlib.util.spec_from_file_location("restore", SCRIPT)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
master,slave=os.openpty()
real_open=open
try:
 def terminal(path, mode, **kwargs):
  assert path=="/dev/tty" and mode=="w"
  return real_open(os.ttyname(slave), mode, **kwargs)
 with patch("builtins.open", side_effect=terminal), patch.object(m.getpass,"getpass",return_value="synthetic"):
  assert m.Ceremony().prompt_share()=="synthetic"
finally:
 os.close(slave);os.close(master)
'''.replace("SCRIPT", repr(str(SCRIPT)))
        result = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_prompt_refuses_echo_fallback(self):
        stream = unittest.mock.MagicMock()
        stream.__enter__.return_value.isatty.return_value = True
        with patch("builtins.open", return_value=stream), patch.object(restore.getpass, "getpass", side_effect=restore.getpass.GetPassWarning("synthetic")):
            with self.assertRaisesRegex(restore.CeremonyError, "echo fallback"):
                restore.Ceremony().prompt_share()

    def test_raft_path_exists_with_private_mode_and_vault_ownership(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(restore.os, "chown") as chown:
            scratch = Path(directory)
            restore.prepare_raft_directories(scratch)
            for name in ("data", "data/raft"):
                self.assertTrue((scratch / name).is_dir())
                self.assertEqual((scratch / name).stat().st_mode & 0o777, 0o700)
            self.assertEqual(chown.call_count, 2)
            chown.assert_any_call(scratch / "data", 65000, 65000)
            chown.assert_any_call(scratch / "data/raft", 65000, 65000)

    def test_real_http_response_is_consumed_once(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(403 if self.path.endswith("denied") else 200)
                self.end_headers()
                self.wfile.write(b'{"initialized":false}')
            def log_message(self, *args): pass
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            api = restore.LocalVault(server.server_port)
            self.assertEqual(api.request("GET", "/v1/sys/health"), {"initialized": False})
            with self.assertRaisesRegex(restore.CeremonyError, "HTTP 403"):
                api.request("GET", "/v1/denied")
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_failure_diagnostics_never_expose_dynamic_content(self):
        c = restore.Ceremony()
        c.stage = "initialize"
        c.cleanup_state = "passed"
        error = restore.CeremonyError("token=synthetic-sensitive-material")
        self.assertEqual(restore.failure_summary(c, error), "FAILED: stage=initialize error=CeremonyError cleanup=passed; details withheld")
        c.stage = "synthetic-sensitive-material"
        c.cleanup_state = "synthetic-sensitive-material"
        self.assertNotIn("synthetic-sensitive-material", restore.failure_summary(c, error))
        with patch.object(restore.Ceremony, "execute", side_effect=error), patch("sys.stderr", new_callable=io.StringIO) as err:
            self.assertEqual(restore.main(["--execute"]), 1)
        self.assertNotIn("synthetic-sensitive-material", err.getvalue())
    def test_default_is_a_no_write_plan(self):
        with patch.object(restore, "command", side_effect=AssertionError("write attempted")), patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(restore.main([]), 0)
        self.assertIn('"writes": false', out.getvalue())
        self.assertNotIn(restore.SHA256, out.getvalue())
    def test_otp_xor_is_decoded_in_process(self):
        raw, pad = b"root", b"AbC9"
        encoded = base64.b64encode(bytes(a ^ b for a,b in zip(raw,pad))).decode().rstrip("=")
        self.assertEqual(restore.xor_decode(encoded, pad.decode()), "root")
    def test_wrong_host_and_expiry_are_rejected_before_aws_or_docker(self):
        with patch.object(restore.os, "geteuid", return_value=0), patch.object(restore.sys, "platform", "linux"), patch.object(restore.Path, "read_text", return_value="Filename\tType\tSize\tUsed\tPriority\n"), patch.object(restore.os, "open", return_value=3), patch.object(restore.os, "close"), patch.object(restore, "imds", return_value='{"instanceId":"wrong"}'):
            with self.assertRaisesRegex(restore.CeremonyError, "approved"): restore.preflight()
    def test_expiry_guard_precedes_host_access(self):
        class Expired:
            @classmethod
            def now(cls, tz): return restore.DEADLINE
        with patch.object(restore.os, "geteuid", return_value=0), patch.object(restore.sys, "platform", "linux"), patch.object(restore, "datetime", Expired), patch.object(restore, "imds", side_effect=AssertionError("IMDS after expiry")):
            with self.assertRaisesRegex(restore.CeremonyError, "expired"): restore.preflight()
    def test_audit_contract_rejects_raw_or_wrong_destination(self):
        with self.assertRaises(restore.CeremonyError):
            restore.audited_configuration({"validator-file/": {"type":"file", "options":{"file_path":"/wrong", "log_raw":"true"}}})
    def test_raft_must_be_exact_isolated_singleton(self):
        with self.assertRaisesRegex(restore.CeremonyError, "singleton"):
            restore.singleton_raft({"data":{"config":{"servers":[]}}})
    def test_raft_fingerprint_ignores_request_envelope(self):
        data={"data":{"config":{"servers":[{"node_id":"isolated-rehearsal","address":"127.0.0.1:28201","leader":True,"voter":True}]}}}
        self.assertEqual(restore.raft_fingerprint({**data,"request_id":"one"}), restore.raft_fingerprint({**data,"request_id":"two"}))
    def test_candidate_metadata_mismatch_is_detectable(self):
        self.assertNotEqual(restore.metadata_fingerprint({"data":{"a/":{}}},{"data":{"keys":[]}}), restore.metadata_fingerprint({"data":{"b/":{}}},{"data":{"keys":[]}}))
    def test_wrong_snapshot_hash_blocks_restore(self):
        with tempfile.NamedTemporaryFile() as snapshot:
            snapshot.write(b"not the approved snapshot"); snapshot.flush()
            with self.assertRaisesRegex(restore.CeremonyError, "checksum"): restore.verify_snapshot(snapshot.name)
    def test_client_is_loopback_with_no_proxy_or_redirects(self):
        source = SCRIPT.read_text()
        self.assertIn('HTTPConnection("127.0.0.1"', source)
        self.assertIn('ProxyHandler({})', source)
        self.assertNotIn('allow_redirects', source)
    def test_no_secret_cli_or_environment(self):
        source = SCRIPT.read_text()
        self.assertIn('X-Vault-Token', source)
        self.assertIn('password-stdin', source)
        self.assertNotIn('VAULT_TOKEN=', source)
        self.assertNotIn('print(snap', source)
    def test_cleanup_failure_is_fatal(self):
        c = restore.Ceremony(); c.container = 'owned'; c.scratch = Path('/definitely/not/a-real-owned-dir')
        with patch.object(c, 'stop', side_effect=RuntimeError('no')), patch.object(restore.shutil, 'rmtree', side_effect=RuntimeError('no')):
            with self.assertRaisesRegex(restore.CeremonyError, 'cleanup failed'): c.cleanup()
    def test_execute_orders_egress_before_host_network_and_closes_after_stop(self):
        events = []
        class Guard:
            def __init__(self, **kw): pass
            def install(self): events.append("guard-install")
            def close(self): events.append("guard-close")
        class Audit:
            def __init__(self, *a): self.count = 1
            def start(self): pass
            def close(self): pass
        class API:
            def request(self, method, path, token=None, body=None, binary=False):
                if path == "/v1/sys/generate-root/attempt": return {"otp":"AbCd", "nonce":"n", "required":1}
                if path == "/v1/sys/generate-root/update": return {"complete":True, "encoded_token":base64.b64encode(bytes(a ^ b for a,b in zip(b"root",b"AbCd"))).decode().rstrip("=")}
                if path == "/v1/sys/audit": return {"validator-file/":{"type":"file","options":{"file_path":"/vault/audit/validator-audit.json","log_raw":"false"}},"validator-socket/":{"type":"socket","options":{"address":"/vault/audit/validator-audit.sock","socket_type":"unix","log_raw":"false"}}}
                if path == "/v1/sys/storage/raft/configuration": return {"data":{"config":{"servers":["one"]}}}
                if path == "/v1/sys/mounts": return {"data":{}}
                if path == "/v1/sys/policies/acl": return {"data":{"keys":[]}}
                if path == "/v1/auth/token/lookup-self" and events.count("revoke"):
                    raise restore.CeremonyError("local Vault request failed: HTTP 403")
                if path == "/v1/auth/token/revoke-self": events.append("revoke")
                return {}
        fake_spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda m: None))
        fake_module = SimpleNamespace(EgressGuard=Guard)
        c = restore.Ceremony()
        with patch.object(restore, "preflight"), patch.object(restore, "ports_are_free"), patch.object(restore.os, "chown"), patch.object(restore, "AuditSink", Audit), patch.object(restore, "LocalVault", API), patch.object(restore.Ceremony, "download", return_value=Path(__file__)), patch.object(restore.Ceremony, "prompt_share", return_value="share"), patch.object(restore.Ceremony, "wait", side_effect=[{"cluster_id":"fresh"},{"cluster_id":"restored"},{"cluster_id":"restored"}]), patch.object(restore.Ceremony, "start", side_effect=lambda image: events.append("start")), patch.object(restore.Ceremony, "stop", side_effect=lambda: events.append("stop")), patch.object(restore.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="password")), patch.object(restore.importlib.util, "spec_from_file_location", return_value=fake_spec), patch.object(restore.importlib.util, "module_from_spec", return_value=fake_module), patch.object(restore.resource, "setrlimit"), patch.object(restore.signal, "signal", return_value=None), patch.object(restore.http.client, "HTTPConnection", side_effect=OSError):
            # Bypass the raw fresh-listener probe: start is intentionally mocked.
            with patch.object(restore.time, "monotonic", side_effect=[0, 91]):
                with self.assertRaisesRegex(restore.CeremonyError, "fresh Vault"): c.execute()
        # This failure proves no guard is ever silently left open on early startup failure.
        self.assertIn("guard-close", events)
    def test_full_mocked_execute_only_prints_after_cleanup(self):
        events, holder = [], {}
        class Guard:
            def __init__(self, **kw): pass
            def install(self): events.append("install")
            def close(self): events.append("close")
        class Audit:
            def __init__(self, directory): self.directory=Path(directory); self.count=0; holder["audit"]=self
            def start(self): self.directory.mkdir(); (self.directory / "validator-audit.json").write_bytes(b"x")
            def close(self): events.append("audit-close")
        raft={"data":{"config":{"servers":[{"node_id":"isolated-rehearsal","address":"127.0.0.1:28201","leader":True,"voter":True}]}}}
        audits={"validator-file/":{"type":"file","options":{"file_path":"/vault/audit/validator-audit.json","log_raw":"false"}},"validator-socket/":{"type":"socket","options":{"address":"/vault/audit/validator-audit.sock","socket_type":"unix","log_raw":"false"}}}
        class API:
            def request(self, method, path, token=None, body=None, binary=False):
                if path == "/v1/sys/init": return {"root_token":"ephemeral","recovery_keys_b64":["never-output"]}
                if path.endswith("attempt"): return {"otp":"AbCd","nonce":"n","required":1}
                if path.endswith("update"): return {"complete":True,"encoded_token":base64.b64encode(bytes(a^b for a,b in zip(b"root",b"AbCd"))).decode().rstrip("=")}
                if path == "/v1/sys/audit": return audits
                if path.endswith("configuration"):
                    return {**raft, "request_id":"different-" + str(len(events))}
                if path.endswith("mounts"): return {"data":{}}
                if path.endswith("policies/acl"): return {"data":{"keys":[]}}
                if path.endswith("lookup-self"):
                    if "revoked" in events: raise restore.CeremonyError("local Vault request failed: HTTP 403")
                    holder["audit"].count += 1; return {}
                if path.endswith("revoke-self"): events.append("revoked"); return {}
                return {}
        fake_spec=SimpleNamespace(loader=SimpleNamespace(exec_module=lambda m:None)); fake_module=SimpleNamespace(EgressGuard=Guard)
        c=restore.Ceremony()
        def start(image): c.container="owned"; events.append("start")
        def stop(): c.container=None; events.append("stop")
        class Conn:
            def __init__(self,*a,**k): pass
            def request(self,*a): pass
            def getresponse(self): return SimpleNamespace(read=lambda:b"")
            def close(self): pass
        waits=[{"cluster_id":"fresh","version":"1.20.4"},{"cluster_id":"restored","version":"1.20.4"},{"cluster_id":"restored","version":"2.1.0"}]
        with patch.object(restore,"preflight"),patch.object(restore,"ports_are_free"),patch.object(restore.os,"chown"),patch.object(restore,"AuditSink",Audit),patch.object(restore,"LocalVault",API),patch.object(restore.Ceremony,"download",return_value=Path(__file__)),patch.object(restore.Ceremony,"prompt_share",return_value="share"),patch.object(restore.Ceremony,"wait",side_effect=waits),patch.object(restore.Ceremony,"start",side_effect=start),patch.object(restore.Ceremony,"stop",side_effect=stop),patch.object(restore.subprocess,"run",return_value=SimpleNamespace(returncode=0,stdout="pw")),patch.object(restore.importlib.util,"spec_from_file_location",return_value=fake_spec),patch.object(restore.importlib.util,"module_from_spec",return_value=fake_module),patch.object(restore.resource,"setrlimit"),patch.object(restore.signal,"signal",return_value=None),patch.object(restore.http.client,"HTTPConnection",Conn),patch.object(restore.time,"sleep"):
            with patch("sys.stdout",new_callable=io.StringIO) as out: c.execute(); self.assertIn('"result": "passed"',out.getvalue())
        self.assertLess(events.index("close"),events.index("audit-close"))
    def test_cleanup_failure_cannot_emit_pass(self):
        c=restore.Ceremony(); c.scratch=Path("/owned-scratch")
        with patch.object(c,"stop"),patch.object(restore.shutil,"rmtree",side_effect=OSError("fail")),patch("sys.stdout",new_callable=io.StringIO) as out:
            with self.assertRaisesRegex(restore.CeremonyError,"cleanup failed"): c.cleanup()
        self.assertNotIn('"result": "passed"',out.getvalue())

if __name__ == '__main__': unittest.main()

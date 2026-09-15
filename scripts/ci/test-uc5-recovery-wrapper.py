#!/usr/bin/env python3
# Check objective: Verify the UC5 recovery wrapper protocol with fake Vault and synthetic keys.
"""PTY recovery-wrapper protocol with synthetic keys and fake Vault only."""
import base64
import errno
import json
import os
import pathlib
import pty
import select
import shutil
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts/ops/recover-and-run-hoodi-uc5.sh"
TOKEN, SHARE = "hvs.syntheticOnlyNotARealCredential", "synthetic-recovery-share"

class WrapperTests(unittest.TestCase):
    def exercise(self, failure=False):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            evidence = root / "evidence"
            evidence.mkdir(mode=0o700)
            events = root / "events"
            otp = "A" * len(TOKEN)
            encoded = base64.b64encode(bytes(a ^ b for a, b in zip(TOKEN.encode(), otp.encode()))).decode().rstrip("=")
            vault = root / "vault"
            vault.write_text(f'''#!{sys.executable}
import json,os,sys
a=sys.argv[1:]
if a[0]=="status": result={{"initialized":True,"sealed":False,"version":"1.19.0"}}
elif "-status" in a: result={{"started":False}}
elif "-init" in a: result={{"nonce":"synthetic-nonce","otp":{otp!r},"required":1}}
elif "-cancel" in a: result={{}}
else:
 if sys.stdin.read()!={SHARE!r}: sys.exit(2)
 result={{"complete":True,"encoded_token":{encoded!r}}}
print(json.dumps(result))
''')
            python = root / "python3"
            python.write_text(f'''#!{sys.executable}
import json,os,sys
if len(sys.argv)>2 and sys.argv[1].endswith("run-hoodi-uc5-ceremony.py"):
 mode=sys.argv[2]
 with open(os.environ["SYNTHETIC_EVENTS"],"a") as f:
  f.write(json.dumps({{"mode":mode,"root_matches":os.environ.get("VAULT_TOKEN")=={TOKEN!r}}})+"\\n")
 sys.exit(1 if mode=="execute" and os.environ.get("SYNTHETIC_FAIL")=="1" else 0)
os.execv({sys.executable!r},[{sys.executable!r},*sys.argv[1:]])
''')
            for path in (vault, python): path.chmod(0o700)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       PRIVATE_VAULT_SESSION="1", VAULT_TOKEN="synthetic-operator",
                       SYNTHETIC_EVENTS=str(events), SYNTHETIC_FAIL="1" if failure else "0")
            pid, fd = pty.fork()
            if pid == 0:
                os.execve("/bin/bash", ["bash", str(WRAPPER), "--inside", "--evidence-dir", str(evidence)], env)
            transcript = bytearray()
            confirmed = entered = False
            deadline = time.monotonic() + 20
            status = None
            reaped = False
            try:
                while time.monotonic() < deadline:
                    if select.select([fd], [], [], .1)[0]:
                        try: chunk = os.read(fd, 4096)
                        except OSError as error:
                            if error.errno == errno.EIO: break
                            raise
                        if not chunk: break
                        transcript.extend(chunk)
                        if b"Type UC5 to continue:" in transcript and not confirmed:
                            os.write(fd, b"UC5\n"); confirmed = True
                        if b"Recovery key share 1 of 1:" in transcript and not entered:
                            os.write(fd, SHARE.encode() + b"\n"); entered = True
                    finished, observed_status = os.waitpid(pid, os.WNOHANG)
                    if finished:
                        status, reaped = observed_status, True
                        break
                else:
                    self.fail("synthetic wrapper timed out")
            finally:
                os.close(fd)
                if not reaped:
                    finished, status = os.waitpid(pid, os.WNOHANG)
                    if not finished:
                        # PTY EOF can precede the final wait status by a moment.
                        for _ in range(20):
                            time.sleep(.01)
                            finished, status = os.waitpid(pid, os.WNOHANG)
                            if finished: break
                    if not finished:
                        os.kill(pid, 15)
                        _, status = os.waitpid(pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 1 if failure else 0)
            self.assertNotIn(TOKEN.encode(), transcript)
            self.assertNotIn(SHARE.encode(), transcript)
            rows = [json.loads(line) for line in events.read_text().splitlines()]
            self.assertEqual([r["mode"] for r in rows], ["preflight", "execute", "cleanup-root"])
            self.assertFalse(rows[0]["root_matches"])
            self.assertTrue(all(r["root_matches"] for r in rows[1:]))
            if failure: self.assertNotIn(b"PASS: UC-5 role probe", transcript)
            else: self.assertIn(b"canonical duty evidence are still required", transcript)

    @unittest.skipUnless(shutil.which("jq"), "jq required")
    def test_success_protocol_keeps_synthetic_key_off_output(self): self.exercise()

    @unittest.skipUnless(shutil.which("jq"), "jq required")
    def test_failed_child_still_cleans_up_without_pass(self): self.exercise(True)

if __name__ == "__main__": unittest.main()

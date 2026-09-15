#!/usr/bin/env python3
# Check objective: Verify local Vault snapshot recovery cleans up without exposing credentials or shares.
"""Regression tests for the local-only Vault snapshot recovery wrapper.

All dependencies are copied or mocked inside a temporary directory.  The
tests deliberately record only operation names, never credentials or shares.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
WRAPPER = REPO_ROOT / "scripts/ops/recover-and-save-private-vault-raft-snapshot.sh"


class SnapshotRecoveryCleanupTests(unittest.TestCase):
    def run_wrapper(
        self,
        *,
        snapshot_rc: int = 0,
        revoke_results: str = "0",
        cancel_rc: int = 0,
        complete: bool = True,
        empty_decode: bool = False,
        interrupt: signal.Signals | None = None,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            ops = temporary_root / "ops"
            (ops / "lib").mkdir(parents=True)
            mock_bin = temporary_root / "bin"
            mock_bin.mkdir()
            events = temporary_root / "events"
            shutil.copy2(WRAPPER, ops / WRAPPER.name)
            (ops / WRAPPER.name).chmod(0o755)
            (ops / "lib/vault-recovery-auth.sh").write_text(
                "vault_recovery_auth_preflight() { :; }\n"
                "vault_recovery_decode_generated_root() { [ \"$MOCK_EMPTY_DECODE\" = 1 ] || printf x; }\n",
                encoding="utf-8",
            )
            (ops / "save-private-vault-raft-snapshot.sh").write_text(
                "#!/usr/bin/env bash\nprintf '%s\\n' snapshot >> \"$MOCK_EVENTS\"\nexit \"$MOCK_SNAPSHOT_RC\"\n",
                encoding="utf-8",
            )
            (ops / "save-private-vault-raft-snapshot.sh").chmod(0o755)
            (mock_bin / "vault").write_text(
                """#!/usr/bin/env bash
set -eu
case "$*" in
  *"generate-root -status"*) printf '%s\\n' '{"started":false}' ;;
  *"generate-root -init"*)
    printf '%s\\n' '{"nonce":"n","otp":"o","required":2}'
    [ -z "${MOCK_READY:-}" ] || : > "$MOCK_READY"
    ;;
  *"generate-root -decode"*) [ "$MOCK_EMPTY_DECODE" = 1 ] || printf x ;;
  *"generate-root -cancel"*) printf '%s\\n' cancel >> "$MOCK_EVENTS"; exit "$MOCK_CANCEL_RC" ;;
  *"token revoke -self"*)
    printf '%s\\n' revoke >> "$MOCK_EVENTS"
    attempt=0
    [ ! -f "$MOCK_REVOKE_COUNT" ] || attempt="$(cat "$MOCK_REVOKE_COUNT")"
    printf '%s' "$((attempt + 1))" > "$MOCK_REVOKE_COUNT"
    IFS=, read -r -a results <<< "$MOCK_REVOKE_RESULTS"
    exit "${results[$attempt]:-1}"
    ;;
  *"generate-root -nonce="*)
    if [ "$MOCK_COMPLETE" = 1 ]; then
      printf '%s\\n' '{"complete":true,"encoded_token":"e"}'
    else
      printf '%s\\n' '{"complete":false}'
    fi
    ;;
  *) exit 64 ;;
esac
""",
                encoding="utf-8",
            )
            (mock_bin / "vault").chmod(0o755)
            (mock_bin / "jq").write_text(
                """#!/usr/bin/env bash
set -eu
query="${!#}"
case "$query" in
  .started) printf false ;;
  .nonce) printf n ;;
  .otp) printf o ;;
  .required) printf 2 ;;
  .complete) if [ "$MOCK_COMPLETE" = 1 ]; then printf true; else printf false; fi ;;
  .encoded_token) printf e ;;
  *) exit 64 ;;
esac
""",
                encoding="utf-8",
            )
            (mock_bin / "jq").chmod(0o755)
            environment = {
                **os.environ,
                "PATH": f"{mock_bin}:{os.environ['PATH']}",
                "PRIVATE_VAULT_SESSION": "1",
                "MOCK_EVENTS": str(events),
                "MOCK_SNAPSHOT_RC": str(snapshot_rc),
                "MOCK_REVOKE_RESULTS": revoke_results,
                "MOCK_REVOKE_COUNT": str(temporary_root / "revoke-count"),
                "MOCK_CANCEL_RC": str(cancel_rc),
                "MOCK_COMPLETE": "1" if complete else "0",
                "MOCK_EMPTY_DECODE": "1" if empty_decode else "0",
            }
            command = [str(ops / WRAPPER.name), "--bucket", "test-bucket"]
            if interrupt is None:
                result = subprocess.run(
                    command,
                    input="\n" if complete else "\n\n",
                    text=True,
                    capture_output=True,
                    env=environment,
                    check=False,
                )
            else:
                ready = temporary_root / "ready"
                environment["MOCK_READY"] = str(ready)
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=environment,
                )
                deadline = time.monotonic() + 3
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists(), "ceremony did not reach the interrupt point")
                # The mock marks the instant its init response is written;
                # allow the shell to set `started=true` before delivering the
                # signal, matching a real completed init response.
                time.sleep(0.05)
                process.send_signal(interrupt)
                stdout, stderr = process.communicate(timeout=3)
                result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
            result.events = events.read_text(encoding="utf-8").splitlines() if events.exists() else []  # type: ignore[attr-defined]
            return result

    def test_success_reports_pass_only_after_revoke(self) -> None:
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.events, ["snapshot", "revoke"])
        self.assertIn("PASS: generated root token was revoked", result.stdout)
        self.assertNotIn("x", result.stdout + result.stderr)

    def test_snapshot_failure_still_revokes_and_preserves_failure(self) -> None:
        result = self.run_wrapper(snapshot_rc=42)
        self.assertEqual(result.returncode, 42)
        self.assertEqual(result.events, ["snapshot", "revoke"])
        self.assertNotIn("PASS:", result.stdout)

    def test_revoke_failure_is_nonzero_and_never_reports_pass(self) -> None:
        result = self.run_wrapper(revoke_results="23,23")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.events, ["snapshot", "revoke", "revoke"])
        self.assertNotIn("PASS:", result.stdout)

    def test_transient_revoke_failure_is_retried_by_exit_cleanup(self) -> None:
        result = self.run_wrapper(revoke_results="23,0")
        self.assertEqual(result.returncode, 23)
        self.assertEqual(result.events, ["snapshot", "revoke", "revoke"])
        self.assertNotIn("PASS:", result.stdout)

    def test_partial_ceremony_is_cancelled(self) -> None:
        result = self.run_wrapper(complete=False)
        self.assertEqual(result.returncode, 77)
        self.assertEqual(result.events, ["cancel"])
        self.assertNotIn("PASS:", result.stdout)

    def test_cancel_failure_is_reported_without_masking_partial_ceremony(self) -> None:
        result = self.run_wrapper(complete=False, cancel_rc=25)
        self.assertEqual(result.returncode, 77)
        self.assertEqual(result.events, ["cancel"])
        self.assertIn("failed to cancel", result.stderr)

    def test_empty_decoded_token_fails_closed(self) -> None:
        result = self.run_wrapper(empty_decode=True)
        self.assertEqual(result.returncode, 78)
        self.assertEqual(result.events, [])
        self.assertNotIn("PASS:", result.stdout)

    def test_term_cancels_active_ceremony_with_bounded_cleanup(self) -> None:
        result = self.run_wrapper(interrupt=signal.SIGTERM)
        self.assertEqual(result.returncode, 143)
        self.assertEqual(result.events, ["cancel"])

    def test_int_cancels_active_ceremony_with_bounded_cleanup(self) -> None:
        result = self.run_wrapper(interrupt=signal.SIGINT)
        self.assertEqual(result.returncode, 130)
        self.assertEqual(result.events, ["cancel"])


if __name__ == "__main__":
    unittest.main()

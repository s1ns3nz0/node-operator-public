#!/usr/bin/env python3
# Check objective: Verify the Raft snapshot S3 upload integrity boundary with mocked dependencies.
"""Mocked regression tests for the Raft snapshot S3 integrity boundary."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
UPLOADER = REPO_ROOT / "scripts/ops/save-private-vault-raft-snapshot.sh"


class SnapshotUploadIntegrityTests(unittest.TestCase):
    def run_uploader(self, case: str, kms_key: str | None = None) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            ops = temporary_root / "scripts/ops"
            ops.mkdir(parents=True)
            mock_bin = temporary_root / "bin"
            mock_bin.mkdir()
            shutil.copy2(UPLOADER, ops / UPLOADER.name)
            (ops / UPLOADER.name).chmod(0o755)
            vault_called = temporary_root / "vault-called"
            (ops / "with-private-vault.sh").write_text(
                "#!/usr/bin/env bash\nset -eu\ntouch \"$MOCK_VAULT_CALLED\"\nshift\n\"$@\"\n", encoding="utf-8"
            )
            (ops / "with-private-vault.sh").chmod(0o755)
            (mock_bin / "vault").write_text(
                """#!/usr/bin/env bash
set -eu
case "$*" in
  *"snapshot save"*) printf snapshot > "${!#}" ;;
  *"snapshot inspect"*) printf '{}\\n' ;;
  *) exit 64 ;;
esac
""",
                encoding="utf-8",
            )
            (mock_bin / "vault").chmod(0o755)
            (mock_bin / "aws").write_text(
                """#!/usr/bin/env bash
set -eu
operation="${2:-}"
case "$operation" in
  get-object-lock-configuration) printf '%s\\n' '{"ObjectLockConfiguration":{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"GOVERNANCE","Days":90}}}}' ;;
  get-bucket-versioning) printf '%s\\n' '{"Status":"Enabled"}' ;;
  describe-key)
    case "$*" in
      *generated*) printf '%s\\n' '{"KeyMetadata":{"Arn":"arn:aws:kms:ap-northeast-2:123:key/generated"}}' ;;
      *) printf '%s\\n' '{"KeyMetadata":{"Arn":"arn:aws:kms:ap-northeast-2:123:key/snapshot"}}' ;;
    esac ;;
  get-bucket-encryption)
    if [ "$MOCK_CASE" = generatedsuccess ]; then
      printf '%s\\n' '{"ServerSideEncryptionConfiguration":{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"arn:aws:kms:ap-northeast-2:123:key/generated"}}]}}'
    else
      printf '%s\\n' '{"ServerSideEncryptionConfiguration":{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"arn:aws:kms:ap-northeast-2:123:key/snapshot"}}]}}'
    fi ;;
  put-object)
    [ "$MOCK_CASE" != uploadfailure ] || exit 41
    for ((i=1; i<=$#; i++)); do
      [ "${!i}" != --checksum-sha256 ] || { j=$((i + 1)); printf '%s' "${!j}" > "$MOCK_CHECKSUM"; }
      [ "${!i}" != --ssekms-key-id ] || { j=$((i + 1)); printf '%s' "${!j}" > "$MOCK_SSEKMS_KEY"; }
    done
    [ "$MOCK_CASE" != inflightdelay ] || sleep 2
    python3 - "$MOCK_METADATA" "$MOCK_CASE" "$(cat "$MOCK_CHECKSUM")" <<'PY'
import json
import sys
from datetime import datetime, timedelta, timezone

path, case, checksum = sys.argv[1:]
last_modified = datetime.now(timezone.utc).replace(microsecond=769000)
retention = last_modified + timedelta(days=90)
if case == "expirywrong":
    retention -= timedelta(seconds=2)
if case == "roundingtolerance":
    # Real S3 shape: whole-second LastModified, fractional retention based on
    # the same write instant. The configured 90-day retention remains intact.
    last_modified = last_modified.replace(microsecond=0) + timedelta(seconds=1)
if case == "roundingtolerancefail":
    last_modified = last_modified.replace(microsecond=0) + timedelta(seconds=1)
    retention = last_modified + timedelta(days=90, seconds=-2)
metadata = {
    "ServerSideEncryption": "aws:kms",
    "SSEKMSKeyId": "arn:aws:kms:ap-northeast-2:123:key/generated" if case == "generatedsuccess" else "arn:aws:kms:ap-northeast-2:123:key/snapshot",
    "VersionId": "version-1",
    "ChecksumType": "FULL_OBJECT",
    "ChecksumSHA256": checksum,
    "ContentLength": 8,
    "ObjectLockMode": "GOVERNANCE",
    "LastModified": last_modified.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00"),
    "ObjectLockRetainUntilDate": retention.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00"),
}
if case == "hashwrong": metadata["ChecksumSHA256"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
if case == "missing": metadata.pop("ChecksumSHA256")
if case == "composite": metadata["ChecksumType"] = "COMPOSITE"
if case == "lengthwrong": metadata["ContentLength"] = 7
if case == "kmswrong": metadata["SSEKMSKeyId"] = "arn:aws:kms:ap-northeast-2:123:key/other"
if case == "versionwrong": metadata["VersionId"] = "version-2"
if case == "encryptionwrong": metadata["ServerSideEncryption"] = "AES256"
if case == "lockmodewrong": metadata["ObjectLockMode"] = "COMPLIANCE"
with open(path, "w", encoding="utf-8") as output:
    json.dump(metadata, output)
PY
    if [ "$MOCK_CASE" = nullversion ]; then
      printf '%s\\n' '{"VersionId":"null"}'
    else
      printf '%s\\n' '{"VersionId":"version-1"}'
    fi
    ;;
  head-object)
    cat "$MOCK_METADATA"
    ;;
  *) exit 64 ;;
esac
""",
                encoding="utf-8",
            )
            (mock_bin / "aws").chmod(0o755)
            environment = {
                **os.environ,
                "PATH": f"{mock_bin}:{os.environ['PATH']}",
                "VAULT_TOKEN": "test-token-not-a-real-secret",
                "MOCK_CASE": case,
                "MOCK_CHECKSUM": str(temporary_root / "checksum"),
                "TMPDIR": str(temporary_root),
                "MOCK_METADATA": str(temporary_root / "metadata.json"),
                "MOCK_SSEKMS_KEY": str(temporary_root / "ssekms-key"),
                "MOCK_VAULT_CALLED": str(vault_called),
            }
            command = [str(ops / UPLOADER.name), "--bucket", "test-bucket"]
            if kms_key is not None:
                command.extend(["--kms-key", kms_key])
            result = subprocess.run(
                command,
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )
            if case == "bucketkeymismatch":
                self.assertFalse(vault_called.exists(), "bucket-key mismatch must fail before Vault access")
            if case == "generatedsuccess":
                self.assertEqual((temporary_root / "ssekms-key").read_text(), "arn:aws:kms:ap-northeast-2:123:key/generated")
            self.assertEqual(list(temporary_root.glob("node-operator-vault-raft.*")), [])
            return result

    def test_success_requires_remote_full_object_checksum(self) -> None:
        result = self.run_uploader("success")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS:", result.stdout)

    def test_fractional_utc_retention_passes_after_upload_delay(self) -> None:
        result = self.run_uploader("inflightdelay")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS:", result.stdout)

    def test_s3_one_second_metadata_rounding_tolerance_passes(self) -> None:
        result = self.run_uploader("roundingtolerance")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS:", result.stdout)

    def test_s3_metadata_gap_over_one_second_never_reports_pass(self) -> None:
        result = self.run_uploader("roundingtolerancefail")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PASS:", result.stdout)

    def test_wrong_remote_checksum_never_reports_pass(self) -> None:
        result = self.run_uploader("hashwrong")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PASS:", result.stdout)

    def test_missing_remote_checksum_never_reports_pass(self) -> None:
        result = self.run_uploader("missing")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PASS:", result.stdout)

    def test_composite_checksum_never_reports_pass(self) -> None:
        result = self.run_uploader("composite")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PASS:", result.stdout)

    def test_wrong_remote_length_never_reports_pass(self) -> None:
        result = self.run_uploader("lengthwrong")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PASS:", result.stdout)

    def test_insufficient_actual_retention_never_reports_pass(self) -> None:
        result = self.run_uploader("expirywrong")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PASS:", result.stdout)

    def test_upload_failure_never_reports_pass(self) -> None:
        result = self.run_uploader("uploadfailure")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PASS:", result.stdout)

    def test_wrong_kms_key_never_reports_pass(self) -> None:
        result = self.run_uploader("kmswrong")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PASS:", result.stdout)

    def test_generated_kms_key_mismatch_fails_before_uploader_vault_operation(self) -> None:
        result = self.run_uploader("bucketkeymismatch", "arn:aws:kms:ap-northeast-2:123:key/generated")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required SSE-KMS key", result.stderr)

    def test_generated_kms_key_matching_bucket_and_object_succeeds(self) -> None:
        result = self.run_uploader("generatedsuccess", "arn:aws:kms:ap-northeast-2:123:key/generated")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS:", result.stdout)

    def test_empty_kms_key_is_rejected_before_any_dependency(self) -> None:
        result = subprocess.run([str(UPLOADER), "--kms-key", ""], text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 64)
        self.assertIn("--kms-key requires a non-empty", result.stderr)

    def test_wrong_version_never_reports_pass(self) -> None:
        result = self.run_uploader("versionwrong")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PASS:", result.stdout)

    def test_null_version_id_never_reports_pass(self) -> None:
        result = self.run_uploader("nullversion")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PASS:", result.stdout)

    def test_wrong_encryption_never_reports_pass(self) -> None:
        result = self.run_uploader("encryptionwrong")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PASS:", result.stdout)

    def test_wrong_lock_mode_never_reports_pass(self) -> None:
        result = self.run_uploader("lockmodewrong")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PASS:", result.stdout)


if __name__ == "__main__":
    unittest.main()

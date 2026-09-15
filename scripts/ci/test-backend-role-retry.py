#!/usr/bin/env python3
# Check objective: Retry-owned backend roles receive state access without adopting explicit or foreign roles.
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "scripts/release/interactive-hoodi-release.sh").read_text()
START = SOURCE.index("backend_role_explicit=false")
END = SOURCE.index("# The signing-fence policy targets", START)
BLOCK = SOURCE[START:END]
MOCK = r'''
account=123456789012; region=ap-northeast-2; deployment_name=test-node
identity='{"Arn":"arn:aws:iam::123456789012:user/operator"}'
aws() {
  case "$1 $2" in
    'iam get-role')
      if [ "$MODE" = absent ]; then echo '(NoSuchEntity)' >&2; return 1; fi
      printf '%s\n' "$DEFAULT_BACKEND_PRINCIPAL_ARN" ;;
    'iam list-role-tags') printf '%s\n' "$ROLE_TAGS" ;;
    'iam create-role') return 0 ;;
    *) return 99 ;;
  esac
}
'''


class BackendRetryTest(unittest.TestCase):
    def test_role_ownership_branches(self):
        for mode, explicit, foreign, expected in (
            ("absent", False, False, "true"),
            ("existing", False, False, "true"),
            ("existing", True, False, "false"),
            ("existing", False, True, None),
        ):
            with self.subTest(mode=mode, explicit=explicit, foreign=foreign):
                tags = {"Project": "node-operator", "Deployment": "foreign" if foreign else "test-node", "DeploymentRegion": "ap-northeast-2", "ManagedBy": "node-operator-installer"}
                env = dict(os.environ, MODE=mode, DEFAULT_BACKEND_PRINCIPAL_ARN="arn:aws:iam::123456789012:role/external" if explicit else "", ROLE_TAGS=json.dumps({"Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}))
                result = subprocess.run(["bash", "-eu", "-c", MOCK + BLOCK + '\nprintf "%s" "$backend_role_managed"'], env=env, text=True, capture_output=True)
                self.assertEqual(result.returncode, 65 if expected is None else 0, result.stderr)
                if expected is not None:
                    self.assertEqual(result.stdout, expected)
        self.assertIn('if [ "${backend_role_managed:-false}" = true ]; then\n  bootstrap_output=', SOURCE)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# Check objective: Resolve bootstrap state from the supplied module, never an inherited shell variable.
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "scripts/release/node-operator-release.sh").read_text()
FUNCTION = re.search(r"^bootstrap_has_local_state\(\) \{\n.*?^\}", SOURCE, re.M | re.S).group()


class LocalStateTest(unittest.TestCase):
    def test_supplied_directory_controls_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "selected"
            inherited = Path(directory) / "inherited"
            selected.mkdir()
            inherited.mkdir()
            (inherited / "terraform.tfstate").write_text('{"resources":[{}]}')
            command = FUNCTION + '\nmodule="$2"; bootstrap_has_local_state "$1"'
            def check(expected):
                result = subprocess.run(["bash", "-eu", "-c", command, "test", str(selected), str(inherited)], capture_output=True)
                self.assertEqual(result.returncode, expected, result.stderr.decode())
            check(1)
            (selected / "terraform.tfstate").write_text(json.dumps({"resources": [{}]}))
            check(0)
            (selected / "terraform.tfstate").write_text("invalid")
            check(2)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Remove inherited publication approvals only inside an isolated test clone.

Tests install their own synthetic authorization after this reset. This helper
never modifies the source checkout or changes production authorization logic.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
fixture = Path(sys.argv[1]).resolve(strict=True)
temporary_roots = (Path(tempfile.gettempdir()).resolve(), Path('/tmp').resolve(), Path('/private/tmp').resolve())
if fixture == root or not any(base in fixture.parents for base in temporary_roots) or not (fixture / '.git').is_dir():
    raise SystemExit('expected an isolated temporary Git clone')
for component in ('prysm', 'fence', 'client-chart', 'signer-probe'):
    path = fixture / 'release' / f'{component}-publication-authorization.json'
    if path.is_symlink():
        raise SystemExit('unsafe fixture authorization')
    path.unlink(missing_ok=True)
subprocess.run(['git', '-C', str(fixture), 'add', '-u', '--', 'release'], check=True)

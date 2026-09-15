#!/usr/bin/env python3
"""Expand explicitly invoked orchestration scripts for static source-contract tests.

This is not a YAML parser or proof of runtime behavior. Only literal calls to
reviewed workflow/release entrypoint directories are expanded; missing inputs
are errors, and unrelated scripts cannot satisfy a workflow's source contract.
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]


def expand_text(source):
    def implementation(match):
        ref = match[2]
        body = (ROOT / ref).read_text()
        # Keep the body at its actual job/step boundary. Appending all scripts
        # would incorrectly attribute read-only code to a later signing job.
        return match[0] + "\n" + "\n".join(match[1] + "  " + line for line in body.splitlines())
    return re.sub(
        r"^([ ]*)run: (?:bash )?(scripts/(?:ci/workflows|release)/[A-Za-z0-9_-]+\.sh)(?:[^\n]*)$",
        implementation, source, flags=re.M,
    )


def expand(path):
    return expand_text(Path(path).read_text())


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: workflow-source.py WORKFLOW")
    print(expand(sys.argv[1]))

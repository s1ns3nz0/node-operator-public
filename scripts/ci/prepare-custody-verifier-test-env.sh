#!/usr/bin/env bash
# Create a disposable, hash-enforced Python environment for the offline custody verifier.
set -euo pipefail

usage() {
  printf '%s\n' 'usage: prepare-custody-verifier-test-env.sh --upstream-root ABSOLUTE_CHECKOUT --work-dir ABSOLUTE_NEW_DIRECTORY [--python ABSOLUTE_PYTHON]' >&2
  exit 64
}

upstream_root=''
work_dir=''
python_bin='python3'
while [ "$#" -gt 0 ]; do
  case "$1" in
    --upstream-root) [ "$#" -ge 2 ] || usage; upstream_root="$2"; shift 2 ;;
    --work-dir) [ "$#" -ge 2 ] || usage; work_dir="$2"; shift 2 ;;
    --python) [ "$#" -ge 2 ] || usage; python_bin="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[ -n "$upstream_root" ] && [ -n "$work_dir" ] || usage
case "$upstream_root" in /*) ;; *) usage ;; esac
case "$work_dir" in /*) ;; *) usage ;; esac
case "$python_bin" in /*) ;; python3) ;; *) usage ;; esac
[ -d "$upstream_root" ] || { printf '%s\n' 'custody verifier upstream checkout is unavailable' >&2; exit 65; }
[ ! -e "$work_dir" ] || { printf '%s\n' 'custody verifier work directory already exists' >&2; exit 65; }
if [ "$python_bin" != python3 ]; then
  [ -x "$python_bin" ] || { printf '%s\n' 'custody verifier Python executable is unavailable' >&2; exit 65; }
fi

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repository_root="$(CDPATH='' cd -- "$script_dir/../.." && pwd)"
source_verifier="$repository_root/scripts/ops/verify-custody-keystore-secret.py"

# Reuse the verifier's canonical fixed-lock and checked-package validation before
# creating a directory or invoking an installer.
if ! "$python_bin" - "$source_verifier" "$upstream_root" <<'PY'
import importlib.util
import sys
from pathlib import Path

try:
    spec = importlib.util.spec_from_file_location("custody_source_verifier", sys.argv[1])
    if spec is None or spec.loader is None:
        raise ValueError()
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.verify_source(Path(sys.argv[2]))
except Exception:
    raise SystemExit(65)
PY
then
  printf '%s\n' 'custody verifier source lock validation failed' >&2
  exit 65
fi

git_status="$(git -C "$upstream_root" status --porcelain=v1 --untracked-files=all -- ':(glob)**/*.py' 2>/dev/null)" || {
  printf '%s\n' 'custody verifier Python source status failed' >&2; exit 65;
}
[ -z "$git_status" ] || {
  printf '%s\n' 'custody verifier Python source is dirty' >&2; exit 65;
}

umask 077
mkdir "$work_dir"
"$python_bin" -m venv "$work_dir/venv"
"$work_dir/venv/bin/python" -m pip install --disable-pip-version-check --no-input --require-hashes -r "$upstream_root/requirements.txt"

printf 'CUSTODY_VERIFIER_UPSTREAM_ROOT=%s\n' "$upstream_root"
printf 'CUSTODY_VERIFIER_PYTHON=%s\n' "$work_dir/venv/bin/python"
printf 'CUSTODY_VERIFIER_TEST_COMMAND=CUSTODY_VERIFIER_UPSTREAM_ROOT=%q CUSTODY_VERIFIER_PYTHON=%q python3 scripts/ci/test-verify-custody-keystore-secret.py\n' "$upstream_root" "$work_dir/venv/bin/python"

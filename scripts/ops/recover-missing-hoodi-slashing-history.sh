#!/usr/bin/env bash
set -euo pipefail
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec python3 -I -B "$dir/recover-missing-hoodi-slashing-history.py" "$@"

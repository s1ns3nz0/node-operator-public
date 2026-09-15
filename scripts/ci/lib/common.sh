#!/usr/bin/env bash
set -euo pipefail
require_command() { command -v "$1" >/dev/null 2>&1 || { printf 'required command is unavailable: %s\n' "$1" >&2; exit 127; }; }
require_file() { [ -f "$1" ] || { printf 'required file is unavailable: %s\n' "$1" >&2; exit 1; }; }
repo_root() { git rev-parse --show-toplevel; }

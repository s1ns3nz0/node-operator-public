#!/usr/bin/env bash
# Check objective: Select one successful image-publication run as a hint and fetch its independently validated records.
set -euo pipefail

[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || { printf '%s\n' 'GITHUB_SHA must be an exact lowercase revision' >&2; exit 64; }
[[ -n "${GITHUB_REPOSITORY:-}" ]] || { printf '%s\n' 'GITHUB_REPOSITORY is required' >&2; exit 64; }
output_directory="${RUNNER_TEMP:?RUNNER_TEMP is required}/release-publication-records"

candidate="${PUBLICATION_RUN_ID:-}"
if [ -z "$candidate" ]; then
  candidate="$(gh run list --workflow image-publish.yml --commit "$GITHUB_SHA" --branch main --status success --limit 1 --json databaseId --jq '.[0].databaseId // empty')"
fi
[[ "$candidate" =~ ^[1-9][0-9]*$ ]] || {
  printf '%s\n' 'No successful image-publish.yml run exists for this exact main revision; dispatch image-publish.yml with target=all at this revision before retrying.' >&2
  exit 65
}

python3 scripts/ci/fetch-release-publication-records.py \
  --repository "$GITHUB_REPOSITORY" \
  --source-sha "$GITHUB_SHA" \
  --run-id "$candidate" \
  --output-dir "$output_directory"

authorization="release/prysm-publication-authorization.json"
if [ -f "$authorization" ] && [ ! -L "$authorization" ]; then
  prysm_output="${RUNNER_TEMP}/prysm-publication-record"
  [ ! -e "$prysm_output" ] && [ ! -L "$prysm_output" ] || { printf '%s\n' 'Prysm publication record output already exists' >&2; exit 65; }
  python3 scripts/ci/fetch-prysm-mtls-publication-record.py --authorization-path "$authorization" --source-root "$PWD" --output-dir "$prysm_output"
elif [ -e "$authorization" ] || [ -L "$authorization" ]; then
  printf '%s\n' 'Prysm publication authorization is unsafe' >&2; exit 65
fi

authorization="release/fence-publication-authorization.json"
if [ -f "$authorization" ] && [ ! -L "$authorization" ]; then
  fence_output="${RUNNER_TEMP}/fence-publication-record"
  [ ! -e "$fence_output" ] && [ ! -L "$fence_output" ] || { printf '%s\n' 'Fence publication record output already exists' >&2; exit 65; }
  python3 scripts/ci/fetch-fence-publication-record.py --authorization-path "$PWD/$authorization" --source-root "$PWD" --output-dir "$fence_output"
elif [ -e "$authorization" ] || [ -L "$authorization" ]; then
  printf '%s\n' 'Fence publication authorization is unsafe' >&2; exit 65
fi

authorization="release/signer-probe-publication-authorization.json"
if [ -f "$authorization" ] && [ ! -L "$authorization" ]; then
  signer_probe_output="${RUNNER_TEMP}/signer-probe-publication-record"
  [ ! -e "$signer_probe_output" ] && [ ! -L "$signer_probe_output" ] || { printf '%s\n' 'signer-probe publication record output already exists' >&2; exit 65; }
  python3 scripts/ci/fetch-signer-probe-publication-record.py --authorization-path "$PWD/$authorization" --source-root "$PWD" --output-dir "$signer_probe_output"
elif [ -e "$authorization" ] || [ -L "$authorization" ]; then
  printf '%s\n' 'signer-probe publication authorization is unsafe' >&2; exit 65
fi

authorization="release/client-chart-publication-authorization.json"
if [ -f "$authorization" ] && [ ! -L "$authorization" ]; then
  client_chart_output="${RUNNER_TEMP}/client-chart-publication-records"
  [ ! -e "$client_chart_output" ] && [ ! -L "$client_chart_output" ] || { printf '%s\n' 'client chart publication records output already exists' >&2; exit 65; }
  # Do not overwrite the caller's GITHUB_TOKEN or use the cross-repository
  # token for Node Operator evidence. Scope it to this one child process.
  if [ -n "${GITOPS_EVIDENCE_TOKEN:-}" ]; then
    GH_TOKEN="$GITOPS_EVIDENCE_TOKEN" python3 scripts/ci/fetch-client-chart-publication-records.py --authorization-path "$PWD/$authorization" --output-dir "$client_chart_output"
  elif [ "${GITHUB_ACTIONS:-false}" = true ]; then
    printf '%s\n' 'GitOps evidence reader App token is required in Actions; configure gitops-evidence-reader.' >&2
    exit 65
  else
    python3 scripts/ci/fetch-client-chart-publication-records.py --authorization-path "$PWD/$authorization" --output-dir "$client_chart_output"
  fi
elif [ -e "$authorization" ] || [ -L "$authorization" ]; then
  printf '%s\n' 'client chart publication authorization is unsafe' >&2; exit 65
fi

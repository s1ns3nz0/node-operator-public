#!/usr/bin/env bash
set -euo pipefail

# Establish a short-lived SSM path to the private EKS API, then run the given
# command with an ephemeral kubeconfig. It neither reads Kubernetes Secrets nor
# prints credential material.
usage() {
  printf 'Usage: %s -- <command> [arguments...]\n' "${0##*/}" >&2
  exit 64
}

[ "${1:-}" = -- ] || usage
shift
[ "$#" -gt 0 ] || usage

for command in aws kubectl nc mktemp unlink; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'missing command: %s\n' "$command" >&2
    exit 69
  }
done

region="${AWS_REGION:-ap-northeast-2}"
cluster_name="${EKS_CLUSTER_NAME:-node-operator}"
instance_id="${SSM_OPS_INSTANCE_ID:?SSM_OPS_INSTANCE_ID must identify the current deployment SSM host}"
eks_port="${PRIVATE_EKS_LOCAL_PORT:-9443}"
session_log="$(mktemp "${TMPDIR:-/tmp}/node-operator-ssm.XXXXXX")"
kubeconfig_file="$(mktemp "${TMPDIR:-/tmp}/node-operator-kubeconfig.XXXXXX")"
session_pid=''
session_id=''
session_id_ambiguous=0
command_pid=''

# The Session Manager plugin prints this line only after StartSession has
# created the server-side session. Keep the value in this process only: it is
# an ownership handle for cleanup, not an artifact to retain or report.
capture_session_id() {
  local line candidate
  local session_id_pattern='(^|[[:space:]])SessionId:[[:space:]]*([[:alnum:]_.:-]+)($|[[:space:]])'

  while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" =~ $session_id_pattern ]]; then
      candidate="${BASH_REMATCH[2]}"
      if [ -z "$session_id" ]; then
        session_id="$candidate"
      elif [ "$session_id" != "$candidate" ]; then
        session_id_ambiguous=1
        return 1
      fi
    fi
  done < "$session_log"
}

cleanup() {
  local original_status="${1:-$?}"
  local cleanup_failed=0
  set +e

  # Re-scan before termination so a malformed or contradictory plugin output
  # cannot turn a locally observed ID into authority over another session.
  if [ -n "$session_id" ] && [ "$session_id_ambiguous" -eq 0 ]; then
    if capture_session_id && [ "$session_id_ambiguous" -eq 0 ]; then
      env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u GITHUB_TOKEN \
        aws ssm terminate-session --session-id "$session_id" --region "$region" >/dev/null 2>&1 || cleanup_failed=1
    fi
  fi
  if [ -n "$command_pid" ]; then
    kill -TERM "$command_pid" 2>/dev/null || true
    wait "$command_pid" 2>/dev/null || true
  fi
  if [ -n "$session_pid" ]; then
    kill -TERM "$session_pid" 2>/dev/null || true
    wait "$session_pid" 2>/dev/null || true
  fi
  unlink "$session_log" "$kubeconfig_file" 2>/dev/null || true

  if [ "$cleanup_failed" -ne 0 ]; then
    printf '%s\n' 'failed to terminate the owned SSM session' >&2
  fi
  if [ "$original_status" -eq 0 ] && [ "$cleanup_failed" -ne 0 ]; then
    return 1
  fi
  return "$original_status"
}

on_exit() {
  local original_status=$?
  local cleanup_status

  # Prevent the explicit exit below from re-entering this trap. A trap's
  # return value is not a reliable way to preserve a failed child status.
  trap - EXIT
  if cleanup "$original_status"; then
    cleanup_status=0
  else
    cleanup_status=$?
  fi
  if [ "$original_status" -ne 0 ]; then
    exit "$original_status"
  fi
  exit "$cleanup_status"
}

trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 129' HUP
trap 'exit 143' TERM

endpoint="$(aws eks describe-cluster --name "$cluster_name" --region "$region" --query 'cluster.endpoint' --output text | sed 's#https://##')"
# A newly-created private ops host can be running before the SSM agent has
# completed registration. Starting a port-forward during that window exits
# immediately with a misleading "session was not ready" error. Wait for the
# owned instance to report Online before creating the tunnel.
ssm_online=0
for _ in $(seq 1 180); do
  ping_status="$(aws ssm describe-instance-information --region "$region" \
    --filters "Key=InstanceIds,Values=$instance_id" \
    --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || true)"
  if [ "$ping_status" = Online ]; then
    ssm_online=1
    break
  fi
  sleep 1
done
[ "$ssm_online" -eq 1 ] || {
  printf 'SSM instance %s did not become Online within 180 seconds\n' "$instance_id" >&2
  exit 1
}
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY -u GITHUB_TOKEN aws ssm start-session \
  --target "$instance_id" \
  --document-name AWS-StartPortForwardingSessionToRemoteHost \
  --parameters "{\"host\":[\"$endpoint\"],\"portNumber\":[\"443\"],\"localPortNumber\":[\"$eks_port\"]}" \
  --region "$region" >"$session_log" 2>&1 &
session_pid=$!
session_ready=0
for _ in $(seq 1 30); do
  capture_session_id || {
    printf '%s\n' 'ambiguous SSM session ownership; refusing tunnel startup' >&2
    exit 1
  }
  if ! kill -0 "$session_pid" 2>/dev/null; then
    printf '%s\n' 'SSM tunnel exited before a session was ready' >&2
    exit 1
  fi
  if [ -n "$session_id" ] && nc -z 127.0.0.1 "$eks_port" 2>/dev/null; then
    session_ready=1
    break
  fi
  sleep 1
done
[ -n "$session_id" ] || {
  printf '%s\n' 'SSM tunnel did not report an owned session ID' >&2
  exit 1
}
[ "$session_ready" -eq 1 ] || {
  printf '%s\n' 'private EKS tunnel did not open' >&2
  exit 1
}

aws eks update-kubeconfig --name "$cluster_name" --region "$region" --kubeconfig "$kubeconfig_file" >/dev/null
context="$(kubectl --kubeconfig "$kubeconfig_file" config view --minify -o jsonpath='{.contexts[0].name}')"
kubectl --kubeconfig "$kubeconfig_file" config set-cluster "$context" \
  --server="https://127.0.0.1:${eks_port}" --tls-server-name="$endpoint" >/dev/null

# An explicit stdin redirect prevents Bash from replacing a background child's
# stdin with /dev/null, so callers can still use prompts and pipelines.
KUBECONFIG="$kubeconfig_file" "$@" <&0 &
command_pid=$!
wait "$command_pid"

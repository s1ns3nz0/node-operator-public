#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
script="$root/scripts/release/run-platform-bootstrap.sh"
build_monitor="$root/scripts/release/platform_bootstrap_build.py"
replay_monitor="$root/scripts/release/platform_bootstrap_replay.py"
entrypoint="$root/scripts/release/interactive-hoodi-release.sh"
fail() { printf 'FAIL platform bootstrap contract: %s\n' "$*" >&2; exit 1; }

test -x "$script" || fail 'platform helper must be executable'
for required in \
  'apply-argocd-bootstrap.sh" plan' \
  'apply-vault-bootstrap.sh" plan' \
  'apply-argocd-bootstrap.sh" apply' \
  'apply-vault-bootstrap.sh" apply' \
  'platform_bootstrap_build.py' \
  'platform_bootstrap_replay.py' \
  'vault_bootstrap_cluster_admin' \
  'all(.resource_changes[]?'; do
  grep -Fq "$required" "$script" || fail "missing control: $required"
done

test -f "$build_monitor" || fail 'platform helper does not include the durable CodeBuild monitor'
for required in 'codebuild","start-build' 'codebuild","batch-get-builds' 'start-intent' 'buildComplete'; do
  grep -Fq "$required" "$build_monitor" || fail "durable monitor missing control: $required"
done
test -f "$replay_monitor" || fail 'platform helper does not include the whole-platform replay monitor'
for required in 'platform-bootstrap-replay' 'argocd_apply' 'revoke_complete' 'fcntl.flock'; do
  grep -Fq "$required" "$replay_monitor" || fail "whole-platform replay monitor missing control: $required"
done

grep -Fq 'run-platform-bootstrap.sh' "$entrypoint" || fail 'interactive entrypoint does not invoke platform helper'
grep -Fq 'GITHUB_TOKEN' "$script" && fail 'platform helper must not manipulate GITHUB_TOKEN'
if rg -n '(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|VAULT_TOKEN|recovery[_-]?key|private[_-]?key)[[:space:]]*=' "$script"; then
  fail 'platform helper contains a credential assignment'
fi

printf '%s\n' 'PASS platform bootstrap plan/apply/revoke contract is present and credential-safe.'

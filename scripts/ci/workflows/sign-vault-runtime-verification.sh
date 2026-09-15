#!/usr/bin/env bash
# Check objective: Keylessly sign only the exact revalidated Vault runtime verification statement.
# Purpose: Build, keylessly sign, and immediately verify the exact current-run Vault runtime statement.
# Inputs: Main-branch checkout, run identity, OIDC context, and downloaded verification evidence.
# Outputs: Statement JSON and Sigstore bundle beneath RUNNER_TEMP/vault-signed-evidence.
# Side effects: Requests an OIDC-backed signature and writes local evidence; never builds, publishes, or deploys images.
set -euo pipefail
umask 077
test "$GITHUB_REF" = refs/heads/main
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
scripts/ci/install-validator-signing-fence-release-tools.sh "$RUNNER_TEMP/vault-sign-tools"
export PATH="$RUNNER_TEMP/vault-sign-tools:$PATH"
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE GH_TOKEN GITHUB_TOKEN
evidence="$RUNNER_TEMP/vault-signed-evidence"
python3 scripts/ci/vault-runtime-verification-statement.py build "$evidence" "$GITHUB_SHA" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" > "$evidence/verification-statement.json"
cosign sign-blob --yes --bundle "$evidence/verification-statement.sigstore.json" "$evidence/verification-statement.json"
bash scripts/ci/verify-vault-runtime-signed-evidence.sh "$evidence" "$GITHUB_SHA" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT"
echo 'PASS: signed digest-bound verification evidence; not CI build provenance, image registry signature, or deployment authorization.' >> "$GITHUB_STEP_SUMMARY"

#!/usr/bin/env bash
# Purpose: The sole public deployment entrypoint for the downloaded release.
# Inputs: No command-line options; the interactive flow asks only for required
# non-secret values and ceremony inputs at the appropriate boundary.
# Outputs: A complete Hoodi validator deployment or a resumable private handoff.
# Side effects: The same guarded release flow provisions infrastructure, private
# access, Vault, workloads, custody and activation in dependency order.
set -euo pipefail
# Keep the authenticated source tree immutable while running Python helpers.
export PYTHONDONTWRITEBYTECODE=1
[ "$#" -eq 0 ] || { printf '%s\n' 'This is the sole release entrypoint and accepts no command-line options. Run it without arguments.' >&2; exit 64; }

print_startup_guidance() {
  local heading='' reset=''
  if [ -t 2 ] && [ -z "${NO_COLOR+x}" ]; then
    heading='\033[1;36m'
    reset='\033[0m'
  fi

  printf '%bInstaller startup guidance%b\n' "$heading" "$reset" >&2
  printf '%s\n' '  1. Ordinary installation' >&2
  printf '%s\n' '     Sign in to the intended AWS account with permissions for the selected deployment. Self-hosted CI or release-runner setup is not required for a downloaded-bundle install.' >&2
  printf '%s\n' '  2. Derived deployment context' >&2
  printf '%s\n' '     No flags or environment file are required. The installer derives the AWS profile/Region/account from AWS CLI and exact GitHub repository IDs from gh CLI plus git origin.' >&2
  printf '%s\n' '     It generates a bounded deployment name and uses only release-authorized immutable artifacts. Do not provide credentials, tokens, private keys, passwords, or recovery material to this command.' >&2
  printf '%s\n' '  3. Key and Vault ceremony boundaries' >&2
  printf '%s\n' '     Keep custody files in your selected private directory. Secret onboarding into Vault occurs only at the later ceremony. Enter a keystore password only at its designated hidden ceremony prompt, never at startup or in logs.' >&2
  printf '%s\n' '     Vault initialization is later and acknowledged. It produces recovery material only then; its selected share count and threshold are explained then, never generated automatically at startup.' >&2
  printf '%s\n' '  4. Optional self-hosted CI/release administration' >&2
  printf '%s\n' '     For a private CodeBuild runner, manually authorize the CodeConnections GitHub App in the AWS console (Developer Tools > Settings > Connections). The repository-scoped connection status must read AVAILABLE.' >&2
  printf '%s\n' '     This banner only displays readiness commands; deployment checks run later after input selection:' >&2
  printf '%s\n' '       aws sts get-caller-identity --profile <selected-profile> --region <selected-region>' >&2
  printf '%s\n' '       aws codeconnections get-connection --connection-arn <connection-arn> --profile <selected-profile> --region <selected-region> --query Connection.ConnectionStatus --output text' >&2
  printf '%s\n' '     No GitHub API token or connection check is required for an ordinary install.' >&2
  printf '%s\n' '  5. GitHub trust separation' >&2
  printf '%s\n' '     GitHub Environment variables hold non-secret identifiers such as AWS account IDs and role ARNs; GitHub secrets remain separate and are not requested here.' >&2
  printf '%s\n' '     Self-hosted release maintainers manually set RELEASE_RUNNER_ROLE_ARN and RELEASE_ARTIFACT_BUCKET as variables in the GitHub release Environment. The optional gitops-evidence-reader Environment uses GITOPS_EVIDENCE_APP_CLIENT_ID as a variable and GITOPS_EVIDENCE_APP_PRIVATE_KEY as a secret; configure these in GitHub, not .env or installer output.' >&2
  printf '%s\n' '     For generated CodeBuild project names, set PRIVATE_RELEASE_RUNNER_PROJECT as a repository Actions variable (needed before runner scheduling), and RELEASE_SIGNER_PROJECT in the release Environment. If omitted, the original node-operator-baseline-private-release and node-operator-baseline-release-signer names remain selected.' >&2
  printf '%s\n' '     GitHub OIDC trust is separate from CodeConnections: applicable Terraform provisions its OIDC provider and roles, while GitHub App authorization does not create that trust. Existing GITHUB_TOKEN is preserved.' >&2
  printf '%s\n' 'Continuing with local bundle verification or the downloaded-bundle installer flow.' >&2
}

print_startup_guidance
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/../.." && pwd -P)"

# Extracted bundles keep this executable under source/scripts/release. Do not
# mistake that source subtree for a Git checkout and rebuild the signed bundle.
if [ "$(basename "$repo_root")" = source ] && [ -f "$repo_root/../bundle-manifest.json" ] && [ ! -L "$repo_root/../bundle-manifest.json" ]; then
  exec "$script_dir/interactive-hoodi-release.sh"
fi

# A checked-out repository does not contain the outer verified-bundle
# manifest. Build that manifest locally so the public command remains a
# genuine single entrypoint for developers and release consumers alike.
if [ ! -f "$repo_root/bundle-manifest.json" ] && [ -f "$repo_root/scripts/ci/build-release-bundle.sh" ]; then
  command -v mktemp >/dev/null 2>&1 || { printf '%s\n' 'missing command: mktemp' >&2; exit 69; }
  command -v tar >/dev/null 2>&1 || { printf '%s\n' 'missing command: tar' >&2; exit 69; }
  command -v install >/dev/null 2>&1 || { printf '%s\n' 'missing command: install' >&2; exit 69; }
  bundle_output="$(mktemp -d "${TMPDIR:-/tmp}/node-operator-release.XXXXXX")"
  bundle_root="$(mktemp -d "${TMPDIR:-/tmp}/node-operator-bundle.XXXXXX")"
  cleanup() { rm -rf -- "$bundle_output" "$bundle_root"; }
  trap cleanup EXIT INT TERM
  printf '%s\n' 'No verified bundle detected; building and validating a local release bundle.' >&2
  "$repo_root/scripts/ci/build-release-bundle.sh" "$bundle_output"
  tar -xf "$bundle_output/node-operator-release-bundle.tar" -C "$bundle_root"
  # The interactive entrypoint derives its non-secret context from AWS CLI,
  # gh CLI, and the git remote. It never copies or loads an environment file.
  NODE_OPERATOR_SOURCE_REPOSITORY_ROOT="$repo_root" "$bundle_root/source/scripts/release/interactive-hoodi-release.sh"
  exit $?
fi

exec "$script_dir/interactive-hoodi-release.sh"

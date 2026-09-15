#!/usr/bin/env bash
# Bootstrap the public-project GitOps boundary without exposing App credentials.
#
# One-time GitHub UI prerequisite: create or select a GitHub App with only
# Actions: Read-only repository permission, install it only on the chosen
# private GitOps repository, then generate a private key. GitHub's OAuth CLI
# token cannot create or install Apps. This script creates/verifies the private
# GitOps repository, creates the public project's Actions Environment, stores
# the non-secret Client ID, and (only when explicitly given a local key path)
# uploads the key through `gh secret set` without printing its contents.
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  bootstrap-public-gitops.sh --owner OWNER --gitops-repository NAME \
    --public-repository NAME --app-client-id CLIENT_ID \
    [--app-private-key /absolute/path/to/key.pem]

When --app-private-key is omitted interactively, the script asks for its
absolute path without displaying the input. Non-interactive callers must pass it.

The GitHub App must already be created and installed in GitHub's UI with
Actions: Read-only permission and access restricted to the GitOps repository.
This script never prints or stores the private-key contents.
USAGE
}

owner=''; gitops_repository=''; public_repository=''; app_client_id=''; app_private_key=''
while (($#)); do
  case "$1" in
    --owner) owner="${2:-}"; shift 2 ;;
    --gitops-repository) gitops_repository="${2:-}"; shift 2 ;;
    --public-repository) public_repository="${2:-}"; shift 2 ;;
    --app-client-id) app_client_id="${2:-}"; shift 2 ;;
    --app-private-key) app_private_key="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 64 ;;
  esac
done

[[ "$owner" =~ ^[A-Za-z0-9-]+$ && "$gitops_repository" =~ ^[A-Za-z0-9_.-]+$ && "$public_repository" =~ ^[A-Za-z0-9_.-]+$ ]] || { usage; exit 64; }
[[ "$app_client_id" =~ ^[A-Za-z0-9_-]{8,128}$ ]] || { printf '%s\n' 'GitHub App Client ID is invalid.' >&2; exit 64; }
if [[ -z "$app_private_key" ]]; then
  [[ -t 0 && -t 1 ]] || { printf '%s\n' 'Pass --app-private-key /absolute/path/to/key.pem in non-interactive mode.' >&2; exit 64; }
  printf 'Absolute path to the GitHub App private-key PEM (input is not displayed): ' >&2
  IFS= read -r -s app_private_key
  printf '\n' >&2
fi
[[ "$app_private_key" = /* && -f "$app_private_key" && ! -L "$app_private_key" ]] || { printf '%s\n' 'App private key must be a regular absolute file.' >&2; exit 64; }

command -v gh >/dev/null 2>&1 || { printf '%s\n' 'missing command: gh' >&2; exit 69; }
gh auth status >/dev/null 2>&1 || { printf '%s\n' 'GitHub CLI is not authenticated; run gh auth login first.' >&2; exit 69; }

gitops="$owner/$gitops_repository"
public="$owner/$public_repository"
if ! gh repo view "$public" --json nameWithOwner,isPrivate --jq '.nameWithOwner == "'"$public"'" and .isPrivate == false' >/dev/null; then
  printf '%s\n' 'Public operator repository is absent, inaccessible, or not public.' >&2
  exit 65
fi
if ! gh repo view "$gitops" --json nameWithOwner,isPrivate --jq '.nameWithOwner == "'"$gitops"'" and .isPrivate == true' >/dev/null; then
  gh repo create "$gitops" --private --description "Protected GitOps configuration for $public" --disable-wiki --add-readme >/dev/null
fi

# Environment creation is idempotent. It contains no secret value by itself.
gh api --method PUT "repos/$public/environments/gitops-evidence-reader" >/dev/null
gh variable set GITOPS_EVIDENCE_APP_CLIENT_ID --repo "$public" --env gitops-evidence-reader --body "$app_client_id"
if [[ -n "$app_private_key" ]]; then
  gh secret set GITOPS_EVIDENCE_APP_PRIVATE_KEY --repo "$public" --env gitops-evidence-reader < "$app_private_key"
fi

printf 'PASS: GitOps repository %s is private and public repository %s has environment gitops-evidence-reader.\n' "$gitops" "$public"
printf '%s\n' 'Client ID and App private-key secret are configured.'

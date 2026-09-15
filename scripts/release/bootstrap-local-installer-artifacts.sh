#!/usr/bin/env bash
# Build/sign/publish handoff for a fresh, already-provisioned artifact target.
# The verified release bundle is read-only: all locally produced authority stays
# below the caller's private work directory.
set -euo pipefail
umask 077

bundle=''; work=''; account=''; region=''; deployment=''; revision=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle-root) bundle="${2:-}"; shift 2 ;;
    --work-dir) work="${2:-}"; shift 2 ;;
    --account) account="${2:-}"; shift 2 ;;
    --region) region="${2:-}"; shift 2 ;;
    --deployment-name) deployment="${2:-}"; shift 2 ;;
    --release-sha) revision="${2:-}"; shift 2 ;;
    *) printf '%s\n' "unsupported local artifact bootstrap argument: $1" >&2; exit 64 ;;
  esac
done
case "$bundle:$work" in /*:/*) ;; *) printf '%s\n' 'bundle root and work directory must be absolute' >&2; exit 64 ;; esac
[ -d "$bundle/source" ] && [ ! -L "$bundle/source" ] && [ -f "$bundle/bundle-manifest.json" ] && [ ! -L "$bundle/bundle-manifest.json" ] || { printf '%s\n' 'bundle root is not a safe release layout' >&2; exit 65; }
[ -d "$work" ] && [ ! -L "$work" ] && [ -f "$work/artifact-prerequisites.json" ] && [ ! -L "$work/artifact-prerequisites.json" ] || { printf '%s\n' 'local artifact bootstrap requires completed zero prepare-artifacts' >&2; exit 65; }
[[ "$account" =~ ^[0-9]{12}$ && "$region" =~ ^[a-z]{2}-[a-z0-9-]+-[0-9]+$ && "$deployment" =~ ^[a-z][a-z0-9-]{1,18}[a-z0-9]$ && "$revision" =~ ^[0-9a-f]{40}$ ]] || { printf '%s\n' 'local artifact bootstrap context is invalid' >&2; exit 64; }
publisher="${NODE_OPERATOR_LOCAL_ARTIFACT_PUBLISHER:-}"
[ -n "$publisher" ] || { printf '%s\n' 'set NODE_OPERATOR_LOCAL_ARTIFACT_PUBLISHER to the reviewed local build/sign/publish command' >&2; exit 69; }
[ -x "$publisher" ] && [ ! -L "$publisher" ] || { printf '%s\n' 'local artifact publisher must be an executable regular file' >&2; exit 65; }
authority="$work/local-artifact-authority.json"
[ ! -e "$authority" ] && [ ! -L "$authority" ] || { printf '%s\n' 'refusing to overwrite local artifact authority' >&2; exit 65; }
"$publisher" --bundle-root "$bundle" --work-dir "$work" --account "$account" --region "$region" --deployment-name "$deployment" --release-sha "$revision" --output "$authority"
[ -f "$authority" ] && [ ! -L "$authority" ] || { printf '%s\n' 'local publisher did not create its authority projection' >&2; exit 65; }
signature="$work/local-artifact-authority.sigstore.json"
public_key="${NODE_OPERATOR_LOCAL_ARTIFACT_AUTHORITY_PUBLIC_KEY:-}"
case "$public_key" in /*) ;; *) printf '%s\n' 'set NODE_OPERATOR_LOCAL_ARTIFACT_AUTHORITY_PUBLIC_KEY to the local authority signing public key' >&2; exit 69 ;; esac
[ -f "$public_key" ] && [ ! -L "$public_key" ] && [ -f "$signature" ] && [ ! -L "$signature" ] || { printf '%s\n' 'local publisher must retain a regular authority signature and public key' >&2; exit 65; }
command -v cosign >/dev/null 2>&1 || { printf '%s\n' 'cosign is required to verify local artifact authority' >&2; exit 69; }
cosign verify-blob --key "$public_key" --bundle "$signature" "$authority" >/dev/null
printf 'PASS local artifact build/sign/publish authority is available at %s.\n' "$authority"

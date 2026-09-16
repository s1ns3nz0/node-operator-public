#!/usr/bin/env bash
# Build, publish, and sign first-party Vault artifacts from a verified bundle.
set -euo pipefail
umask 077
bundle=''; work=''; account=''; region=''; deployment=''; revision=''; output=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle-root) bundle="${2:-}"; shift 2;; --work-dir) work="${2:-}"; shift 2;; --account) account="${2:-}"; shift 2;; --region) region="${2:-}"; shift 2;; --deployment-name) deployment="${2:-}"; shift 2;; --release-sha) revision="${2:-}"; shift 2;; --output) output="${2:-}"; shift 2;; *) printf 'unsupported local artifact publisher argument: %s\n' "$1" >&2; exit 64;;
  esac
done
case "$bundle:$work:$output" in /*:/*:/*) ;; *) printf '%s\n' 'publisher paths must be absolute' >&2; exit 64;; esac
[[ "$account" =~ ^[0-9]{12}$ && "$region" =~ ^[a-z]{2}-[a-z0-9-]+-[0-9]+$ && "$deployment" =~ ^[a-z][a-z0-9-]{1,18}[a-z0-9]$ && "$revision" =~ ^[0-9a-f]{40}$ ]] || { printf '%s\n' 'publisher context is invalid' >&2; exit 64; }
[ -d "$bundle/source" ] && [ ! -L "$bundle/source" ] && [ -f "$bundle/bundle-manifest.json" ] && [ ! -L "$bundle/bundle-manifest.json" ] || { printf '%s\n' 'bundle source is unsafe' >&2; exit 65; }
[ -d "$work" ] && [ ! -L "$work" ] && [ "$(dirname "$output")" = "$work" ] && [ ! -e "$output" ] && [ ! -L "$output" ] || { printf '%s\n' 'authority output is unsafe' >&2; exit 65; }
command -v docker >/dev/null 2>&1 || { printf '%s\n' 'docker is required to build first-party artifacts' >&2; exit 69; }
command -v aws >/dev/null 2>&1 || { printf '%s\n' 'aws is required to publish first-party artifacts' >&2; exit 69; }
ensure_cosign() {
  command -v cosign >/dev/null 2>&1 && return 0
  # The public macOS path uses Homebrew's signed formula distribution. Do not
  # download an unchecked executable or alter PATH outside this process.
  if [ "$(uname -s)" = Darwin ] && command -v brew >/dev/null 2>&1; then
    printf '%s\n' 'Installing required Cosign through Homebrew…' >&2
    brew install cosign >&2
  fi
  command -v cosign >/dev/null 2>&1 || { printf '%s\n' 'Cosign could not be installed automatically; install cosign and rerun the installer' >&2; exit 69; }
}
ensure_cosign
source="$bundle/source"; registry="$account.dkr.ecr.$region.amazonaws.com"; key_prefix="$work/local-artifact-authority"
# Authenticate the Docker daemon to this exact deployment registry before the
# first build tag is pushed. AWS CLI credentials do not automatically create a
# Docker registry session.
aws ecr get-login-password --region "$region" | docker login --username AWS --password-stdin "$registry" >/dev/null
private_key="$key_prefix.key"; public_key="$key_prefix.pub"; signature="$work/local-artifact-authority.sigstore.json"
for path in "$private_key" "$public_key" "$signature"; do [ ! -e "$path" ] && [ ! -L "$path" ] || { printf '%s\n' 'refusing to overwrite local authority signing material' >&2; exit 65; }; done
cosign generate-key-pair --output-key-prefix "$key_prefix" >/dev/null
[ -f "$private_key" ] && [ ! -L "$private_key" ] && [ -f "$public_key" ] && [ ! -L "$public_key" ] || { printf '%s\n' 'cosign did not create regular signing material' >&2; exit 65; }
chmod 600 "$private_key" "$public_key"
artifacts_file="$work/.local-artifact-authority-artifacts.json"
[ ! -e "$artifacts_file" ] && [ ! -L "$artifacts_file" ] || { printf '%s\n' 'local authority staging path is unsafe' >&2; exit 65; }
printf '[' > "$artifacts_file"
first=true
for spec in \
  'vault-bootstrap:.ci/toolchains/vault-bootstrap.Dockerfile:gitops-vault' \
  'gitops-oci-mirror:.ci/toolchains/gitops-oci-mirror.Dockerfile:gitops-vault' \
  'vault-audit-relay:.ci/vault-audit-relay/Dockerfile:vault-audit-relay'; do
  IFS=: read -r component dockerfile repository_suffix <<EOF
$spec
EOF
  dockerfile_path="$source/$dockerfile"
  [ -f "$dockerfile_path" ] && [ ! -L "$dockerfile_path" ] || { printf 'verified source lacks Dockerfile: %s\n' "$dockerfile" >&2; exit 65; }
  repository="$deployment-baseline-$repository_suffix"
  tag="local-$revision-$component"
  image="$registry/$repository:$tag"
  docker build --pull=false --platform linux/amd64 --file "$dockerfile_path" --tag "$image" "$source" >/dev/null
  docker push "$image" >/dev/null
  digest="$(aws ecr describe-images --registry-id "$account" --region "$region" --repository-name "$repository" --image-ids "imageTag=$tag" --query 'imageDetails[0].imageDigest' --output text)"
  [[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || { printf 'published digest is invalid for %s\n' "$component" >&2; exit 65; }
  destination="$registry/$repository@$digest"
  if [ "$component" = gitops-oci-mirror ]; then destination_json=null; else destination_json="\"$destination\""; fi
  $first || printf ',' >> "$artifacts_file"; first=false
  printf '{"component":"%s","source":"%s","destination":%s,"authority":"local-build-sign-publish"}' "$component" "$destination" "$destination_json" >> "$artifacts_file"
done
printf ']' >> "$artifacts_file"
python3 - "$artifacts_file" "$account" "$region" "$deployment" "$revision" "$output" <<'PY'
import json, os, sys
artifacts, account, region, deployment, revision, output = sys.argv[1:]
value={"schema_version":1,"release_revision":revision,"deployment":{"aws_account_id":account,"aws_region":region,"deployment_name":deployment},"artifacts":json.load(open(artifacts, encoding="utf-8"))}
tmp=output+".tmp"
with open(tmp,"x",encoding="utf-8") as handle:
    json.dump(value,handle,sort_keys=True,separators=(",",":")); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
os.chmod(tmp,0o600); os.link(tmp,output); os.unlink(tmp)
PY
rm -f "$artifacts_file"
cosign sign-blob --yes --key "$private_key" --bundle "$signature" "$output" >/dev/null
[ -f "$signature" ] && [ ! -L "$signature" ] || { printf '%s\n' 'cosign did not create authority signature' >&2; exit 65; }
cosign verify-blob --insecure-ignore-tlog --key "$public_key" --bundle "$signature" "$output" >/dev/null
printf 'PASS local first-party Vault artifacts published and authority written: %s\n' "$output"

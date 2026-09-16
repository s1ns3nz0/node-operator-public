#!/usr/bin/env bash
# Populate all index-less installer artifact authority from reviewed bundle inputs.
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
source="$bundle/source"; catalog="$source/.ci/gitops/approved-oci-artifacts.json"
[ -d "$source" ] && [ ! -L "$source" ] && [ -f "$bundle/bundle-manifest.json" ] && [ ! -L "$bundle/bundle-manifest.json" ] && [ -f "$catalog" ] && [ ! -L "$catalog" ] || { printf '%s\n' 'bundle source authority is unsafe or incomplete' >&2; exit 65; }
[ -d "$work" ] && [ ! -L "$work" ] && [ "$(dirname "$output")" = "$work" ] && [ ! -e "$output" ] && [ ! -L "$output" ] || { printf '%s\n' 'authority output is unsafe' >&2; exit 65; }
for command in aws docker helm curl python3 cosign; do command -v "$command" >/dev/null 2>&1 || { printf 'required command unavailable: %s\n' "$command" >&2; exit 69; }; done
registry="$account.dkr.ecr.$region.amazonaws.com"; key_prefix="$work/local-artifact-authority"; private_key="$key_prefix.key"; public_key="$key_prefix.pub"; signature="$work/local-artifact-authority.sigstore.json"; rows="$work/.local-artifact-authority-artifacts.json"
for path in "$private_key" "$public_key" "$signature" "$rows"; do [ ! -e "$path" ] && [ ! -L "$path" ] || { printf '%s\n' 'refusing to overwrite local authority material' >&2; exit 65; }; done
aws ecr get-login-password --region "$region" | docker login --username AWS --password-stdin "$registry" >/dev/null
aws ecr get-login-password --region "$region" | helm registry login --username AWS --password-stdin "$registry" >/dev/null
cosign generate-key-pair --output-key-prefix "$key_prefix" >/dev/null
[ -f "$private_key" ] && [ ! -L "$private_key" ] && [ -f "$public_key" ] && [ ! -L "$public_key" ] || { printf '%s\n' 'cosign did not create regular signing material' >&2; exit 65; }
chmod 600 "$private_key" "$public_key"
printf '[' > "$rows"; first=true
append() { $first || printf ',' >> "$rows"; first=false; printf '{"component":"%s","source":"%s","destination":%s,"authority":"local-build-sign-publish"}' "$1" "$2" "$3" >> "$rows"; }
digest_for() { aws ecr describe-images --registry-id "$account" --region "$region" --repository-name "$1" --image-ids "imageTag=$2" --query 'imageDetails[0].imageDigest' --output text; }
# First-party source is built only from the signed bundle's reviewed Dockerfiles.
for spec in 'vault-bootstrap:.ci/toolchains/vault-bootstrap.Dockerfile:gitops-vault' 'gitops-oci-mirror:.ci/toolchains/gitops-oci-mirror.Dockerfile:gitops-vault' 'vault-audit-relay:.ci/vault-audit-relay/Dockerfile:vault-audit-relay' 'prysm-validator:.ci/prysm-mtls/Dockerfile:validator-prysm' 'validator-signing-fence:.ci/validator-signing-fence/Dockerfile:validator-fence' 'validator-signer-identity-probe:.ci/validator-signer-identity-probe/Dockerfile:validator-signer-identity-probe'; do
  IFS=: read -r component dockerfile suffix <<EOF
$spec
EOF
  [ -f "$source/$dockerfile" ] && [ ! -L "$source/$dockerfile" ] || { printf 'reviewed source lacks Dockerfile: %s\n' "$dockerfile" >&2; exit 65; }
  repository="$deployment-baseline-$suffix"; tag="local-$revision-$component"; image="$registry/$repository:$tag"
  docker build --pull=false --platform linux/amd64 --file "$source/$dockerfile" --tag "$image" "$source" >/dev/null
  docker push "$image" >/dev/null; digest="$(digest_for "$repository" "$tag")"
  [[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || { printf 'published digest is invalid for %s\n' "$component" >&2; exit 65; }
  destination="$registry/$repository@$digest"; [ "$component" = gitops-oci-mirror ] && append "$component" "$destination" null || append "$component" "$destination" "\"$destination\""
done
# Mirror only immutable digest-pinned images selected by the reviewed catalog.
python3 - "$catalog" <<'PY' | while IFS=$'\t' read -r component source_image suffix; do
import json, re, sys
catalog=json.load(open(sys.argv[1], encoding='utf-8'))
want={"vault-server":("docker.io/hashicorp/vault@","gitops-vault"),"vault-injector":("docker.io/hashicorp/vault-k8s@","gitops-vault"),"cert-manager-controller":("quay.io/jetstack/cert-manager-controller@","gitops-cert-manager"),"cert-manager-webhook":("quay.io/jetstack/cert-manager-webhook@","gitops-cert-manager"),"cert-manager-cainjector":("quay.io/jetstack/cert-manager-cainjector@","gitops-cert-manager"),"cert-manager-startupapicheck":("quay.io/jetstack/cert-manager-startupapicheck@","gitops-cert-manager")}
for component,(prefix,suffix) in want.items():
 rows=[x for x in catalog["artifacts"] if isinstance(x,dict) and x.get("source","").startswith(prefix)]
 if len(rows)!=1 or not re.fullmatch(re.escape(prefix)+r"sha256:[a-f0-9]{64}", rows[0]["source"]): raise SystemExit("reviewed catalog selection is missing or ambiguous: "+component)
 print(component, rows[0]["source"], suffix, sep="\t")
PY
  repository="$deployment-baseline-$suffix"; tag="local-$revision-$component"; docker buildx imagetools create --tag "$registry/$repository:$tag" "$source_image" >/dev/null
  digest="$(digest_for "$repository" "$tag")"; expected="${source_image##*@}"
  [ "$digest" = "$expected" ] || { printf 'mirrored digest differs from reviewed source for %s\n' "$component" >&2; exit 65; }
  append "$component" "$source_image" "\"$registry/$repository@$digest\""
done
# Checked-in archive checksum and publisher-expected OCI digest are both verified.
python3 - "$catalog" <<'PY' | while IFS=$'\t' read -r component chart_name chart_url chart_sha chart_digest suffix tag; do
import json, re, sys
c=json.load(open(sys.argv[1], encoding='utf-8'))
for name, component, suffix in (("vault","vault-chart","gitops-vault"),("cert-manager","cert-manager-chart","gitops-cert-manager")):
 rows=[x for x in c["helm_archives"] if isinstance(x,dict) and x.get("name")==name]
 if len(rows)!=1: raise SystemExit("reviewed chart selection is missing or ambiguous: "+name)
 x=rows[0]
 if not all(isinstance(x.get(k),str) for k in ("source","sha256","ecrManifestDigest","ecrTag")) or not x["source"].startswith("https://") or not re.fullmatch(r"[a-f0-9]{64}",x["sha256"]) or not re.fullmatch(r"sha256:[a-f0-9]{64}",x["ecrManifestDigest"]): raise SystemExit("reviewed chart authority is invalid: "+name)
 print(component,name,x["source"],x["sha256"],x["ecrManifestDigest"],suffix,x["ecrTag"],sep="\t")
PY
  archive="$work/$chart_name-$tag.tgz"; [ ! -e "$archive" ] && [ ! -L "$archive" ] || exit 65
  curl --fail --location --silent --show-error --output "$archive" "$chart_url"
  python3 - "$archive" "$chart_sha" <<'PY'
import hashlib, sys
if hashlib.sha256(open(sys.argv[1], 'rb').read()).hexdigest() != sys.argv[2]:
    raise SystemExit("reviewed chart archive checksum differs")
PY
  helm push "$archive" "oci://$registry/$deployment-baseline-$suffix" >/dev/null
  digest="$(digest_for "$deployment-baseline-$suffix/$chart_name" "$tag")"; [ "$digest" = "$chart_digest" ] || { printf 'published chart digest differs from reviewed source for %s\n' "$component" >&2; exit 65; }
  destination="$registry/$deployment-baseline-$suffix/$chart_name@$digest"; append "$component" "$destination" "\"$destination\""
done
# A bundle carries the reviewed client-chart archive; arbitrary GitHub history is never a fallback.
client_archive="$source/release/node-operator-client-chart.tgz"; client_meta="$source/release/node-operator-client-chart.json"
[ -f "$client_archive" ] && [ ! -L "$client_archive" ] && [ -f "$client_meta" ] && [ ! -L "$client_meta" ] || { printf '%s\n' 'verified bundle lacks reviewed node-operator client chart source' >&2; exit 65; }
client_version="$(python3 - "$client_archive" "$client_meta" <<'PY'
import hashlib,json,re,sys
archive,meta=sys.argv[1:]; v=json.load(open(meta,encoding='utf-8'))
if set(v)!={'version','archive_sha256'} or not re.fullmatch(r'0\.1\.[0-9]+',v['version']) or v['archive_sha256'] != hashlib.sha256(open(archive,'rb').read()).hexdigest(): raise SystemExit(65)
print(v['version'])
PY
)"
helm push "$client_archive" "oci://$registry/$deployment-baseline-gitops-client" >/dev/null
digest="$(digest_for "$deployment-baseline-gitops-client/node-operator-client" "$client_version")"; [[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || exit 65
destination="$registry/$deployment-baseline-gitops-client/node-operator-client@$digest"; append node-operator-client-chart "$destination" "\"$destination\""
printf ']' >> "$rows"
python3 - "$rows" "$account" "$region" "$deployment" "$revision" "$output" <<'PY'
import json,os,sys
rows,account,region,deployment,revision,output=sys.argv[1:]
value={"schema_version":1,"release_revision":revision,"deployment":{"aws_account_id":account,"aws_region":region,"deployment_name":deployment},"artifacts":json.load(open(rows,encoding="utf-8"))}
tmp=output+".tmp"; open(tmp,"x",encoding="utf-8").write(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n"); os.chmod(tmp,0o600); os.link(tmp,output); os.unlink(tmp)
PY
rm -f "$rows"
cosign sign-blob --yes --key "$private_key" --bundle "$signature" "$output" >/dev/null
[ -f "$signature" ] && [ ! -L "$signature" ] || { printf '%s\n' 'cosign did not create authority signature' >&2; exit 65; }
cosign verify-blob --insecure-ignore-tlog --key "$public_key" --bundle "$signature" "$output" >/dev/null
printf 'PASS local installer artifacts published and authority written: %s\n' "$output"

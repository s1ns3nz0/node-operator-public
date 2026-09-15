#!/usr/bin/env bash
# Check objective: Prove installer-owned toolchain records follow only a successful, bound registry verification.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
publisher="$root/scripts/release/publish-toolchain-image.sh"
indexer="$root/scripts/release/create-installer-artifact-index.py"
workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT
sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
config="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
fail() { printf 'FAIL toolchain publication record: %s\n' "$*" >&2; exit 1; }

mkdir -p "$workspace/bin" "$workspace/staged/toolchain-sbom" "$workspace/records"
events="$workspace/events"
image_prefix="ghcr.io/s1ns3nz0/node-operator"
# shellcheck disable=SC2016 # The fake Docker program must receive these expansions literally.
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
  'case "$1" in' \
  '  load) printf "load:%s\\n" "${2:-}" >> "$EVENTS"; exit 0 ;;' \
  '  tag) printf "tag:%s:%s\\n" "$2" "$3" >> "$EVENTS"; exit 0 ;;' \
  '  image)' \
  '    [ "$2" = inspect ] && [ "$3" = --format ] || exit 91' \
  '    case "$4" in' \
  '      *io.node-operator.toolchain-input-sha*) printf "%s\n" "$FAKE_INPUT_SHA" ;;' \
  '      *"{{.Id}}"*) printf "%s\n" "$FAKE_CONFIG_DIGEST" ;;' \
  '      *) exit 91 ;;' \
  '    esac ;;' \
  '  login) cat >/dev/null; printf "login\\n" >> "$EVENTS" ;;' \
  '  push) printf "push:%s\\n" "$2" >> "$EVENTS"; [ "${FAKE_DOCKER_MODE:-ok}" != push-fail ] || exit 93 ;;' \
  '  buildx)' \
  '    [ "$2 $3 $4" = "imagetools inspect --raw" ] || exit 95' \
  '    [ "${FAKE_DOCKER_MODE:-ok}" != registry-missing ] || exit 94' \
  '    if [ "${FAKE_DOCKER_MODE:-ok}" = oci-index ]; then printf "{\\\"schemaVersion\\\":2,\\\"manifests\\\":[]}\\n"; elif [ "${FAKE_DOCKER_MODE:-ok}" = pinned-mismatch ] && [[ "$5" = *@sha256:* ]]; then printf "{\\\"schemaVersion\\\":2,\\\"config\\\":{\\\"digest\\\":\\\"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\\\"}}\\n"; else printf "{\\\"schemaVersion\\\":2,\\\"config\\\":{\\\"digest\\\":\\\"%s\\\"}}\\n" "${FAKE_MANIFEST_CONFIG:-$FAKE_CONFIG_DIGEST}"; fi ;;' \
  '  *) printf "unexpected docker command: %s\\n" "$*" >&2; exit 95 ;;' \
  'esac' > "$workspace/bin/docker"
chmod +x "$workspace/bin/docker"

printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
  '[ "$1 $2 $3 $4" = "eval --fail --format pretty" ] && [ "$5" = --data ] && [ "$7" = --input ] && [ "$9" = "true = data.nodeoperator.image_sbom.allow" ] && [ "$#" -eq 9 ] || exit 95' \
  'printf "opa\\n" >> "$EVENTS"' '[ "${FAKE_OPA_MODE:-ok}" != false ]' > "$workspace/bin/opa"
chmod +x "$workspace/bin/opa"
cat > "$workspace/bin/cosign" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'cosign:%s\n' "$1" >> "$EVENTS"
[ "${FAKE_COSIGN_MODE:-ok}" != fail ] || exit 96
case "$1" in
  sign) [ "$#" -eq 3 ] && [ "$2" = --yes ] && [ "$3" = "$FAKE_IMAGE@$FAKE_MANIFEST_DIGEST" ] || exit 95 ;;
  attest)
    [ "$#" -eq 7 ] && [ "$2" = --yes ] && [ "$3" = --type ] && [ "$5" = --predicate ] && [ "$7" = "$FAKE_IMAGE@$FAKE_MANIFEST_DIGEST" ] || exit 95
    case "$4" in cyclonedx|https://github.com/s1ns3nz0/node-operator/attestations/image-build-receipt/v1) ;; *) exit 95 ;; esac
    ;;
  verify)
    [ "$#" -eq 10 ] && [ "$2 $3 $4" = "--output json --certificate-identity" ] && [ "$5" = 'https://github.com/s1ns3nz0/node-operator/.github/workflows/image-publish.yml@refs/heads/main' ] && [ "$6" = --certificate-oidc-issuer ] && [ "$7" = https://token.actions.githubusercontent.com ] && [ "$8" = --certificate-github-workflow-sha ] && [ "$9" = "$GITHUB_SHA" ] && [ "${10}" = "$FAKE_IMAGE@$FAKE_MANIFEST_DIGEST" ] || { printf 'unexpected cosign verify arguments: %s\n' "$*" >&2; exit 95; }
    printf '{"critical":{"type":"https://sigstore.dev/cosign/sign/v1","identity":{"docker-reference":"%s@%s"},"image":{"docker-manifest-digest":"%s"}}}\n' "$FAKE_IMAGE" "$FAKE_MANIFEST_DIGEST" "$FAKE_MANIFEST_DIGEST"
    ;;
  verify-attestation)
    [ "$#" -eq 12 ] && [ "$2" = --type ] && [ "$4 $5 $6" = "--output json --certificate-identity" ] && [ "$7" = 'https://github.com/s1ns3nz0/node-operator/.github/workflows/image-publish.yml@refs/heads/main' ] && [ "$8" = --certificate-oidc-issuer ] && [ "$9" = https://token.actions.githubusercontent.com ] && [ "${10}" = --certificate-github-workflow-sha ] && [ "${11}" = "$GITHUB_SHA" ] && [ "${12}" = "$FAKE_IMAGE@$FAKE_MANIFEST_DIGEST" ] || exit 95
    kind=''; previous=''; for arg in "$@"; do [ "$previous" = --type ] && kind="$arg"; previous="$arg"; done
    case "$kind" in cyclonedx|https://github.com/s1ns3nz0/node-operator/attestations/image-build-receipt/v1) ;; *) exit 95 ;; esac
    python3 - "$kind" <<'PY'
import base64, json, os, sys
kind=sys.argv[1]; predicate=json.load(open(os.environ['FAKE_SBOM'] if kind == 'cyclonedx' else os.environ['FAKE_RECEIPT']))
predicate_type='https://cyclonedx.org/bom' if kind == 'cyclonedx' else 'https://github.com/s1ns3nz0/node-operator/attestations/image-build-receipt/v1'
statement={'_type':'https://in-toto.io/Statement/v0.1','subject':[{'name':os.environ['FAKE_IMAGE'],'digest':{'sha256':os.environ['FAKE_MANIFEST_DIGEST'][7:]}}],'predicateType':predicate_type,'predicate':predicate}
print(json.dumps({'payloadType':'application/vnd.in-toto+json','payload':base64.b64encode(json.dumps(statement,separators=(',',':')).encode()).decode()}))
PY
    ;;
  *) exit 95 ;;
esac
EOF
chmod +x "$workspace/bin/cosign"

printf 'FROM scratch\n' > "$workspace/Dockerfile"
input_sha="$({ sha256sum "$workspace/Dockerfile"; } | awk '{print $1}' | sha256sum | awk '{print $1}')"
printf '%s\n' "$input_sha" > "$workspace/staged/toolchain-input.sha256"
python3 - "$workspace/staged/toolchain-image.tar" "$workspace/staged/toolchain-sbom/sbom.cyclonedx.json" "$sha" <<'PY'
import hashlib,json,sys,tarfile
from io import BytesIO
archive,sbom,revision=sys.argv[1:]
with tarfile.open(archive,'w') as image:
 for name,data in [('manifest.json',b'[{"Config":"config.json","RepoTags":["fixture:latest"],"Layers":["layer.tar"]}]'),('config.json',b'{}'),('layer.tar',b'')]:
  member=tarfile.TarInfo(name); member.size=len(data); image.addfile(member,BytesIO(data))
digest=hashlib.sha256(open(archive,'rb').read()).hexdigest()
document={'bomFormat':'CycloneDX','specVersion':'1.5','metadata':{'component':{'name':'fixture','version':'sha256:'+digest},'tools':[{'name':'fixture-syft'}]},'components':[{'type':'library','name':'fixture','version':'1','purl':'pkg:generic/fixture@1'}]}
open(sbom,'w').write(json.dumps(document,separators=(',',':'))+'\n')
PY

create_receipt() {
  local component="$1"
  rm -f "$workspace/staged/toolchain-sbom/receipt.json"
  python3 "$root/scripts/ci/image_sbom_evidence.py" create --archive "$workspace/staged/toolchain-image.tar" --sbom "$workspace/staged/toolchain-sbom/sbom.cyclonedx.json" --revision "$sha" --image-config-digest "$config" --subject "$component" --output "$workspace/staged/toolchain-sbom/receipt.json"
  python3 "$root/scripts/ci/image_sbom_evidence.py" verify --archive "$workspace/staged/toolchain-image.tar" --sbom "$workspace/staged/toolchain-sbom/sbom.cyclonedx.json" --revision "$sha" --image-config-digest "$config" --subject "$component" --receipt "$workspace/staged/toolchain-sbom/receipt.json"
}

run_publisher() {
  local component="$1"
  local record_dir="$2"
  [ "${CREATE_RECEIPT:-true}" = true ] && create_receipt "$component"
  PATH="$workspace/bin:$PATH" \
    DOCKERFILE="$workspace/Dockerfile" INPUT_FILE='' IMAGE="$image_prefix/$component" IMAGE_NAME="$component" \
    GITHUB_REF=refs/heads/main GITHUB_REPOSITORY=s1ns3nz0/node-operator GITHUB_SHA="$sha" GITHUB_RUN_ID=123 REGISTRY_TOKEN=token REGISTRY_USERNAME=actor RUNNER_TEMP="$record_dir" EVENTS="$events" \
    TOOLCHAIN_IMAGE_DIR="$workspace/staged" FAKE_INPUT_SHA="$input_sha" FAKE_CONFIG_DIGEST="$config" FAKE_IMAGE="$image_prefix/$component" FAKE_MANIFEST_DIGEST="sha256:$(printf '{\"schemaVersion\":2,\"config\":{\"digest\":\"%s\"}}\n' "$config" | sha256sum | awk '{print $1}')" FAKE_SBOM="$workspace/staged/toolchain-sbom/sbom.cyclonedx.json" FAKE_RECEIPT="$workspace/staged/toolchain-sbom/receipt.json" \
    bash "$publisher"
}

assert_valid_record() {
  local component="$1" record_dir="$2" record="$2/toolchain-publication-records/$1-publication-record.json"
  [ -f "$record" ] || fail "missing $component record"
  python3 - "$indexer" "$record" "$component" <<'PY'
import importlib.util
import pathlib
import sys
spec = importlib.util.spec_from_file_location("index", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
value = module._record(pathlib.Path(sys.argv[2]), sys.argv[3], "a" * 40, "input-hash-and-registry-digest")
assert value["image_ref"] == "ghcr.io/s1ns3nz0/node-operator/" + sys.argv[3] + "@" + value["manifest_digest"]
PY
  python3 - "$record" <<'PY'
import stat
import sys
assert stat.S_IMODE(__import__("os").stat(sys.argv[1]).st_mode) == 0o600
PY
}

event_number() {
  local event="$1" line
  line="$(grep -n -m 1 -F "$event" "$events" || true)"
  [ -n "$line" ] || fail "missing event: $event"
  printf '%s\n' "${line%%:*}"
}

assert_before() {
  local earlier="$1" later="$2"
  [ "$(event_number "$earlier")" -lt "$(event_number "$later")" ] || fail "event ordering is invalid: $earlier before $later"
}

assert_no_promotion_or_record() {
  local component="$1" record_dir="$2"
  [ ! -e "$record_dir/toolchain-publication-records/$component-publication-record.json" ] || fail "failure left a publication record"
  ! grep -F -q "push:$image_prefix/$component:main" "$events" || fail 'failure promoted the main tag'
}

for component in vault-bootstrap gitops-oci-mirror; do
  record_dir="$workspace/records/$component"
  mkdir -p "$record_dir"
  : > "$events"
  run_publisher "$component" "$record_dir"
  assert_valid_record "$component" "$record_dir"
  immutable="$image_prefix/$component:$sha"
  main="$image_prefix/$component:main"
  assert_before opa login
  assert_before "push:$immutable" cosign:sign
  assert_before cosign:sign "push:$main"
done

for mode in registry-mismatch registry-missing pinned-mismatch oci-index invalid-input push-fail opa-false cosign-fail tampered-receipt; do
  record_dir="$workspace/records/$mode"
  mkdir -p "$record_dir"
  : > "$events"
  if [ "$mode" = invalid-input ]; then
    printf '%064d\n' 0 > "$workspace/staged/toolchain-input.sha256"
  fi
  if [ "$mode" = tampered-receipt ]; then
    create_receipt vault-bootstrap
    printf '%s\n' '{"tampered":true}' > "$workspace/staged/toolchain-sbom/receipt.json"
  fi
  if [ "$mode" = registry-mismatch ]; then
    if FAKE_MANIFEST_CONFIG="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" run_publisher vault-bootstrap "$record_dir" >/dev/null 2>&1; then fail "$mode unexpectedly succeeded"; fi
  elif [ "$mode" = registry-missing ]; then
    if FAKE_DOCKER_MODE=registry-missing run_publisher vault-bootstrap "$record_dir" >/dev/null 2>&1; then fail "$mode unexpectedly succeeded"; fi
  elif [ "$mode" = pinned-mismatch ]; then
    if FAKE_DOCKER_MODE=pinned-mismatch run_publisher vault-bootstrap "$record_dir" >/dev/null 2>&1; then fail "$mode unexpectedly succeeded"; fi
  elif [ "$mode" = oci-index ]; then
    if FAKE_DOCKER_MODE=oci-index run_publisher vault-bootstrap "$record_dir" >/dev/null 2>&1; then fail "$mode unexpectedly succeeded"; fi
  elif [ "$mode" = push-fail ]; then
    if FAKE_DOCKER_MODE=push-fail run_publisher vault-bootstrap "$record_dir" >/dev/null 2>&1; then fail "$mode unexpectedly succeeded"; fi
  elif [ "$mode" = opa-false ]; then
    if FAKE_OPA_MODE=false run_publisher vault-bootstrap "$record_dir" >/dev/null 2>&1; then fail "$mode unexpectedly succeeded"; fi
    event_number opa >/dev/null
    ! grep -F -q login "$events" || fail 'OPA rejection authenticated to the registry'
  elif [ "$mode" = cosign-fail ]; then
    if FAKE_COSIGN_MODE=fail run_publisher vault-bootstrap "$record_dir" >/dev/null 2>&1; then fail "$mode unexpectedly succeeded"; fi
    event_number cosign:sign >/dev/null
    event_number "push:$image_prefix/vault-bootstrap:$sha" >/dev/null
  elif [ "$mode" = tampered-receipt ]; then
    if CREATE_RECEIPT=false run_publisher vault-bootstrap "$record_dir" >/dev/null 2>&1; then fail "$mode unexpectedly succeeded"; fi
    ! grep -F -q login "$events" || fail 'tampered receipt authenticated to the registry'
  elif run_publisher vault-bootstrap "$record_dir" >/dev/null 2>&1; then
    fail "$mode unexpectedly succeeded"
  fi
  assert_no_promotion_or_record vault-bootstrap "$record_dir"
  if [ "$mode" = invalid-input ]; then printf '%s\n' "$input_sha" > "$workspace/staged/toolchain-input.sha256"; fi
done

if "$workspace/bin/docker" unexpected >/dev/null 2>&1; then fail 'fake Docker accepted an unknown command'; fi
if EVENTS="$events" "$workspace/bin/opa" unexpected >/dev/null 2>&1; then fail 'fake OPA accepted unexpected arguments'; fi
if EVENTS="$events" "$workspace/bin/cosign" unexpected >/dev/null 2>&1; then fail 'fake cosign accepted an unknown command'; fi
if EVENTS="$events" "$workspace/bin/cosign" verify unexpected >/dev/null 2>&1; then fail 'fake cosign accepted unexpected arguments'; fi

record_dir="$workspace/records/preexisting"
record="$record_dir/toolchain-publication-records/vault-bootstrap-publication-record.json"
mkdir -p "$(dirname "$record")"
printf '%s\n' 'preserve this pre-existing record' > "$record"
before="$(sha256sum "$record" | awk '{print $1}')"
if run_publisher vault-bootstrap "$record_dir" >/dev/null 2>&1; then fail 'pre-existing record was overwritten'; fi
[ "$before" = "$(sha256sum "$record" | awk '{print $1}')" ] || fail 'pre-existing record bytes changed'

printf 'PASS toolchain publication records are verified, atomic, and index-compatible.\n'

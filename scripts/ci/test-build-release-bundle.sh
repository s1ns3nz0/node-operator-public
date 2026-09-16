#!/usr/bin/env bash
# Check objective: Prove release-bundle generation is deterministic and contains required reviewed inputs.
set -euo pipefail

publication_records_directory=''; prysm_publication_record=''; fence_publication_record=''; client_chart_records=''; signer_probe_publication_record=''; oci_payload_manifest=''
while [ "$#" -gt 1 ]; do case "$1" in --publication-records-dir) [ -n "${2:-}" ] || exit 64; publication_records_directory="$2"; shift 2 ;; --prysm-publication-record) [ -n "${2:-}" ] || exit 64; prysm_publication_record="$2"; shift 2 ;; --fence-publication-record) [ -n "${2:-}" ] || exit 64; fence_publication_record="$2"; shift 2 ;; --client-chart-publication-records) [ -n "${2:-}" ] || exit 64; client_chart_records="$2"; shift 2 ;; --signer-probe-publication-record) [ -n "${2:-}" ] || exit 64; signer_probe_publication_record="$2"; shift 2 ;; --oci-payload-manifest) [ -n "${2:-}" ] || exit 64; oci_payload_manifest="$2"; shift 2 ;; *) exit 64 ;; esac; done
if [ "$#" -eq 0 ]; then first=''; offline_fixture=true; elif [ "$#" -eq 1 ]; then first="$1"; offline_fixture=false; else exit 64; fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib/common.sh"
require_command jq
require_command tar
require_command cmp
python3 "$script_dir/test-slashing-recovery-bundle-inputs.py"
python3 "$script_dir/test-prepare-hoodi-missing-slashing-history.py"

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

# Zero-argument tests exercise legacy/index construction without remote inputs.
# Isolate that fixture from real release authorizations; explicit evidence calls
# still test the selected release unchanged and must supply all required records.
if [ "$offline_fixture" = true ] && [ -z "$publication_records_directory$prysm_publication_record$fence_publication_record$client_chart_records$signer_probe_publication_record$oci_payload_manifest" ] &&
   { [ -f "$(repo_root)/release/prysm-publication-authorization.json" ] ||
     [ -f "$(repo_root)/release/fence-publication-authorization.json" ] ||
     [ -f "$(repo_root)/release/client-chart-publication-authorization.json" ] ||
     [ -f "$(repo_root)/release/signer-probe-publication-authorization.json" ]; }; then
  fixture="$temporary_directory/offline-source"
  mkdir "$fixture"
  git -C "$(repo_root)" archive HEAD | tar -xf - -C "$fixture"
  for component in prysm fence client-chart signer-probe; do
    path="$fixture/release/$component-publication-authorization.json"
    [ ! -f "$path" ] || unlink "$path"
  done
  # Exercise this test revision, including uncommitted test-only changes.
  cp "$script_dir/test-build-release-bundle.sh" "$fixture/scripts/ci/test-build-release-bundle.sh"
  cp "$script_dir/build-release-bundle.sh" "$fixture/scripts/ci/build-release-bundle.sh"
  cp "$script_dir/test-slashing-recovery-bundle-inputs.py" "$fixture/scripts/ci/test-slashing-recovery-bundle-inputs.py"
  cp "$script_dir/test-prepare-hoodi-missing-slashing-history.py" "$fixture/scripts/ci/test-prepare-hoodi-missing-slashing-history.py"
  cp "$script_dir/../ops/prepare-hoodi-missing-slashing-history.sh" "$fixture/scripts/ops/prepare-hoodi-missing-slashing-history.sh"
  git -C "$fixture" init -q
  git -C "$fixture" add .
  git -C "$fixture" -c user.name=Fixture -c user.email=fixture@example.invalid -c commit.gpgsign=false commit -qm 'Offline legacy bundle fixture'
  (cd "$fixture" && bash scripts/ci/test-build-release-bundle.sh)
  exit 0
fi

# The production builder must require the pinned Syft executable. Only this
# zero-argument offline fixture path supplies the local scan interface it
# exercises. Explicit-output or publication-record invocations therefore keep
# requiring the real scanner and cannot publish synthetic SBOM evidence.
if [ "$offline_fixture" = true ] && [ -z "$publication_records_directory$prysm_publication_record$fence_publication_record$client_chart_records$signer_probe_publication_record$oci_payload_manifest" ]; then
  fake_tools="$temporary_directory/fake-tools"
  mkdir -m 700 "$fake_tools"
  cat > "$fake_tools/syft" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "${1:-}" = scan ] || exit 64
shift
input="${1:-}"
shift
source_name=''; source_version=''; output=''; quiet=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --source-name) source_name="${2:-}"; shift 2 ;;
    --source-version) source_version="${2:-}"; shift 2 ;;
    --output) output="${2#cyclonedx-json=}"; shift 2 ;;
    --quiet) quiet=true; shift ;;
    *) exit 64 ;;
  esac
done
[[ "$input" = file:* && -n "$source_name" && "$source_version" =~ ^sha256:[0-9a-f]{64}$ && -n "$output" && "$quiet" = true ]] || exit 64
[ ! -e "$output" ] && [ ! -L "$output" ] || exit 65
printf '{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"name":"%s","version":"%s"},"tools":{"components":[{"name":"syft"}]}},"components":[]}\n' "$source_name" "$source_version" > "$output"
EOF
  chmod 700 "$fake_tools/syft"
  export PATH="$fake_tools:$PATH"
fi

first="${first:-$temporary_directory/first}"
build_bundle() {
  local arguments=(--publication-records-dir "$1")
  [ -z "$prysm_publication_record" ] || arguments+=(--prysm-publication-record "$prysm_publication_record")
  [ -z "$fence_publication_record" ] || arguments+=(--fence-publication-record "$fence_publication_record")
  [ -z "$client_chart_records" ] || arguments+=(--client-chart-publication-records "$client_chart_records")
  [ -z "$signer_probe_publication_record" ] || arguments+=(--signer-probe-publication-record "$signer_probe_publication_record")
  [ -z "$oci_payload_manifest" ] || arguments+=(--oci-payload-manifest "$oci_payload_manifest")
  "$script_dir/build-release-bundle.sh" "${arguments[@]}" "$2"
}
if [ -n "$publication_records_directory" ]; then
  build_bundle "$publication_records_directory" "$first" >/dev/null
  build_bundle "$publication_records_directory" "$temporary_directory/second" >/dev/null
else
  [ -z "$prysm_publication_record" ] && [ -z "$fence_publication_record" ] && [ -z "$client_chart_records" ] && [ -z "$signer_probe_publication_record" ] || { printf '%s\n' 'candidate records require publication records' >&2; exit 64; }
  arguments=()
  [ -z "$oci_payload_manifest" ] || arguments+=(--oci-payload-manifest "$oci_payload_manifest")
  "$script_dir/build-release-bundle.sh" ${arguments[@]+"${arguments[@]}"} "$first" >/dev/null
  "$script_dir/build-release-bundle.sh" ${arguments[@]+"${arguments[@]}"} "$temporary_directory/second" >/dev/null
fi

for filename in node-operator-release-bundle.tar node-operator-release-bundle.sha256 manifest.json provenance-input.json; do
  cmp "$first/$filename" "$temporary_directory/second/$filename"
done

digest="$(awk '{print $1}' "$first/node-operator-release-bundle.sha256")"
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]
actual="sha256:$(shasum -a 256 "$first/node-operator-release-bundle.tar" | awk '{print $1}')"
[ "$digest" = "$actual" ]

# These synthetic, public records separately exercise local index assembly and
# its negative paths; production records are retrieved and supplied explicitly.
publication_records="$temporary_directory/publication-records"
mkdir -m 700 "$publication_records"
source_revision="$(git -C "$(repo_root)" rev-parse HEAD)"
python3 - "$publication_records" "$source_revision" <<'PY'
import json, sys
from pathlib import Path

directory, revision = Path(sys.argv[1]), sys.argv[2]
for component, method, letter in (
    ("vault-bootstrap", "input-hash-and-registry-digest", "a"),
    ("vault-audit-relay", "cosign-and-slsa", "b"),
    ("gitops-oci-mirror", "input-hash-and-registry-digest", "c"),
):
    digest = "sha256:" + letter * 64
    record = {
        "schema_version": 1, "component": component, "kind": "image",
        "release_revision": revision, "build_revision": revision,
        "third_party_source_revision": None,
        "image_ref": f"ghcr.io/s1ns3nz0/node-operator/{component}@{digest}",
        "manifest_digest": digest, "input_sha256": letter * 64,
        "publication": {"workflow": "image-publish.yml", "run_id": "1", "invocation": "test"},
        "verification": {"method": method, "status": "passed"},
    }
    (directory / f"{component}-publication-record.json").write_text(json.dumps(record, sort_keys=True))
PY
indexed_first="$temporary_directory/indexed-first"
indexed_second="$temporary_directory/indexed-second"
build_bundle "$publication_records" "$indexed_first" >/dev/null
build_bundle "$publication_records" "$indexed_second" >/dev/null
for filename in node-operator-release-bundle.tar node-operator-release-bundle.sha256 manifest.json provenance-input.json; do
  cmp "$indexed_first/$filename" "$indexed_second/$filename"
done
indexed_extract="$temporary_directory/indexed-extract"
mkdir "$indexed_extract"
tar -xf "$indexed_first/node-operator-release-bundle.tar" -C "$indexed_extract"
index_path="rendered/installer-artifact-index.json"
test -f "$indexed_extract/$index_path"
jq -e --arg revision "$source_revision" '
  .schema_version == 1 and .release_revision == $revision and
  .components["vault-bootstrap"].manifest_digest == ("sha256:" + ("a" * 64)) and
  .components["vault-audit-relay"].verification == {method:"cosign-and-slsa",status:"passed"} and
  .components["gitops-oci-mirror"].manifest_digest == ("sha256:" + ("c" * 64))
' "$indexed_extract/$index_path" >/dev/null
jq -e --arg path "$index_path" --arg sha "$(shasum -a 256 "$indexed_extract/$index_path" | awk '{print $1}')" \
  'any(.entries[]; .path == $path and .sha256 == $sha)' "$indexed_first/manifest.json" >/dev/null

missing_records="$temporary_directory/missing-publication-records"
mkdir -m 700 "$missing_records"
cp "$publication_records/vault-bootstrap-publication-record.json" "$missing_records/"
cp "$publication_records/vault-audit-relay-publication-record.json" "$missing_records/"
if build_bundle "$missing_records" "$temporary_directory/missing-output" >/dev/null 2>&1; then
  printf '%s\n' 'bundle accepted incomplete publication records' >&2
  exit 1
fi
python3 - "$publication_records/vault-bootstrap-publication-record.json" <<'PY'
import json, sys
path = sys.argv[1]
value = json.load(open(path))
value["release_revision"] = "f" * 40
open(path, "w").write(json.dumps(value, sort_keys=True))
PY
if build_bundle "$publication_records" "$temporary_directory/mismatched-output" >/dev/null 2>&1; then
  printf '%s\n' 'bundle accepted publication evidence for a different revision' >&2
  exit 1
fi

tar -tf "$first/node-operator-release-bundle.tar" | LC_ALL=C sort > "$temporary_directory/archive-paths.txt"
for required_path in \
  bundle-manifest.json \
  rendered/prysm.yaml \
  rendered/nethermind.yaml \
  source/deploy/base/namespace.yaml \
  source/deploy/prysm/kustomization.yaml \
  source/deploy/nethermind/kustomization.yaml \
  source/deploy/argocd/node-operator-client-application.yaml \
  source/deploy/kyverno/kustomization.yaml \
  source/deploy/kyverno/policies/node-operator-workload-baseline.yaml \
  source/deploy/kyverno/policies/node-operator-project-workload-baseline.yaml \
  source/scripts/ops/apply-kyverno-project-coverage.sh \
  source/deploy/validator/onboarding-contract.yaml \
  source/deploy/validator/vault-runtime-egress-policy.yaml \
  source/deploy/validator/vault/onboarding-write.hcl \
  source/deploy/validator/vault/runtime-read.hcl \
  source/deploy/validator/vault/slashing-db-read.hcl \
  source/deploy/validator/vault/client-tls-read.hcl \
  source/deploy/validator/vault/runtime-kubernetes-auth-role.json \
  source/deploy/validator/vault/slashing-db-kubernetes-auth-role.json \
  source/deploy/validator/vault/client-tls-kubernetes-auth-role.json \
  source/docs/gitops/vault-tls-internal-ca.example.yaml \
  source/infra/terraform/eks.tf \
  source/infra/terraform/gitops-client-chart-retention.json \
  source/infra/bootstrap-state/main.tf \
  source/infra/foundation-network/main.tf \
  source/infra/foundation-network/backend.hcl.example \
  source/infra/ops-access/main.tf \
  source/infra/ops-access/.terraform.lock.hcl \
  source/infra/ops-access/backend.hcl.example \
  source/infra/ops-access/terraform.tfvars.example \
  source/infra/baseline/variables.tf \
  source/release/hoodi-release-contract.json \
  source/scripts/release/node-operator-release.sh \
  source/scripts/release/prepare-zero-resource-inputs.sh \
  source/scripts/release/prepare-hoodi-zero-release-inputs.sh \
  source/scripts/release/hoodi-validator-release.sh \
  source/scripts/release/bootstrap-local-installer-artifacts.sh \
  source/scripts/release/local-installer-artifact-publisher.sh \
  source/scripts/release/apply-vault-bootstrap.sh \
  source/scripts/release/run-platform-bootstrap.sh \
  source/scripts/release/node-operator-install.sh \
  source/scripts/release/interactive_deploy.py \
  source/scripts/release/installer_state.py \
  source/scripts/release/installer_preflight.py \
  source/scripts/release/installer_infrastructure.py \
  source/scripts/release/installer_ops_access.py \
  source/scripts/release/installer_ops_execution.py \
  source/scripts/release/installer_ops_verify.py \
  source/scripts/release/installer_vault_inputs.py \
  source/scripts/release/installer_vault_execution.py \
  source/scripts/release/installer_vault_authority.py \
  source/scripts/release/installer_vault_platform.py \
  source/scripts/release/prepare-ops-access-inputs.sh \
  source/scripts/release/prepare-hoodi-validator-deployment.sh \
  source/scripts/release/stage-hoodi-validator-deployment.sh \
  source/scripts/ops/render-hoodi-validator-runtime.sh \
  source/scripts/ops/render-hoodi-validator-client.sh \
  source/scripts/ops/recover-and-bootstrap-hoodi-validator-runtime-vault.sh \
  source/scripts/ops/recover-and-bootstrap-hoodi-engine-api-vault.sh \
  source/scripts/ops/recover-and-bootstrap-hoodi-vault-v2.sh \
  source/scripts/ops/bootstrap-node-operator-vault-v2.sh \
  source/scripts/ops/ensure-node-operator-runtime-kv-v2.sh \
  source/scripts/ops/recover-and-migrate-hoodi-runtime-secrets-to-vault.sh \
  source/scripts/ops/preflight-live-vault-cutover.sh \
  source/scripts/ops/apply-live-engine-vault-cutover.sh \
  source/scripts/ops/apply-live-validator-vault-cutover.sh \
  source/scripts/ops/prune-legacy-validator-tls-mounts.sh \
  source/scripts/ops/finalize-live-vault-secret-cutover.sh \
  source/scripts/ops/verify-live-vault-cutover-convergence.sh \
  source/scripts/ops/collect-hoodi-signer-public-key-evidence.sh \
  source/scripts/ops/recover-and-onboard-hoodi-validator-keystore.sh \
  source/scripts/ops/recover-missing-hoodi-slashing-history.py \
  source/.ci/web3signer-hardened/source.lock.json \
  source/scripts/ops/lib/uc5-beacon-reader.py \
  source/scripts/ops/prepare-hoodi-missing-slashing-history.sh \
  source/.ci/validator/approved-runtime-images.json \
  source/.ci/validator/approved-client-images.json \
  source/.ci/gitops/approved-oci-artifacts.json \
  source/.ci/prysm-mtls/source.lock.json \
  source/.ci/prysm-mtls/Dockerfile \
  source/.ci/prysm-mtls/Dockerfile.dockerignore \
  source/.ci/prysm-mtls/patches/0001-web3signer-http-mtls.patch \
  source/.ci/prysm-mtls/patches/0002-security-dependencies.patch \
  source/policy/decision.rego; do
  grep -F -x -- "$required_path" "$temporary_directory/archive-paths.txt" >/dev/null
done
for excluded_path in \
  source/scripts/ops/verify-hoodi-example-signer-tls-rejection.sh \
  source/scripts/ops/configure-private-vault-operator-auth.sh \
  source/scripts/ops/recover-and-configure-private-vault-operator-auth.sh \
  source/scripts/ops/with-private-vault-operator.sh \
  source/scripts/ops/publish-reviewed-vault-grpc-candidates.sh \
  source/scripts/ci/check-ops-access-ssm-retention-plan.sh \
  source/deploy/validator/vault/remote-signer-kubernetes-auth-role.json \
  source/deploy/validator/vault/remote-signer.hcl \
  source/deploy/validator/vault/tls-rotation.hcl; do
  if grep -F -x -- "$excluded_path" "$temporary_directory/archive-paths.txt" >/dev/null; then
    printf 'bundle release boundary unexpectedly includes: %s\n' "$excluded_path" >&2
    exit 1
  fi
done

extract_directory="$temporary_directory/extract"
mkdir "$extract_directory"
tar -xf "$first/node-operator-release-bundle.tar" -C "$extract_directory"
find "$extract_directory" -type f -print | sed "s|$extract_directory/||" | LC_ALL=C sort > "$temporary_directory/archive-files.txt"
{ jq -r '.entries[].path' "$first/manifest.json"; printf '%s\n' bundle-manifest.json; } | LC_ALL=C sort > "$temporary_directory/manifest-files.txt"
cmp "$temporary_directory/manifest-files.txt" "$temporary_directory/archive-files.txt"
if grep -F -- '__pycache__/' "$temporary_directory/archive-files.txt" >/dev/null; then
  printf '%s\n' 'bundle archive contains Python bytecode cache files' >&2
  exit 1
fi
grep -F -- 'name: prysm-hoodi-gp3-kms' "$extract_directory/rendered/prysm.yaml" >/dev/null
grep -F -- 'name: nethermind-hoodi-gp3-kms' "$extract_directory/rendered/nethermind.yaml" >/dev/null
cmp <(git show HEAD:deploy/prysm/kustomization.yaml) "$extract_directory/source/deploy/prysm/kustomization.yaml"
cmp <(git show HEAD:policy/decision.rego) "$extract_directory/source/policy/decision.rego"
cmp <(git show HEAD:.ci/gitops/approved-oci-artifacts.json) "$extract_directory/source/.ci/gitops/approved-oci-artifacts.json"
cmp <(git show HEAD:.ci/validator/approved-runtime-images.json) "$extract_directory/source/.ci/validator/approved-runtime-images.json"
jq -e --arg path 'source/.ci/validator/approved-runtime-images.json' --arg sha "$(git show HEAD:.ci/validator/approved-runtime-images.json | shasum -a 256 | awk '{print $1}')" \
  'any(.entries[]; .path == $path and .sha256 == $sha)' "$first/manifest.json" >/dev/null
for template in \
  deploy/validator/vault/onboarding-write.hcl \
  deploy/validator/vault/runtime-read.hcl \
  deploy/validator/vault/slashing-db-read.hcl \
  deploy/validator/vault/client-tls-read.hcl \
  deploy/validator/vault/runtime-kubernetes-auth-role.json \
  deploy/validator/vault/slashing-db-kubernetes-auth-role.json \
  deploy/validator/vault/client-tls-kubernetes-auth-role.json; do
  cmp <(git show "HEAD:$template") "$extract_directory/source/$template"
  jq -e --arg path "source/$template" --arg sha "$(git show "HEAD:$template" | shasum -a 256 | awk '{print $1}')" \
    'any(.entries[]; .path == $path and .sha256 == $sha)' "$first/manifest.json" >/dev/null
done
for prysm_input in \
  .ci/prysm-mtls/source.lock.json \
  .ci/prysm-mtls/Dockerfile \
  .ci/prysm-mtls/Dockerfile.dockerignore \
  .ci/prysm-mtls/patches/0001-web3signer-http-mtls.patch \
  .ci/prysm-mtls/patches/0002-security-dependencies.patch; do
  cmp <(git show "HEAD:$prysm_input") "$extract_directory/source/$prysm_input"
  jq -e --arg path "source/$prysm_input" --arg sha "$(git show "HEAD:$prysm_input" | shasum -a 256 | awk '{print $1}')" \
    'any(.entries[]; .path == $path and .sha256 == $sha)' "$first/manifest.json" >/dev/null
done
"$extract_directory/source/scripts/release/node-operator-release.sh" verify --bundle-root "$extract_directory" >/dev/null
# Reproducible bundles can carry an independently authorized candidate record,
# but staging the coupled client and fence requires both authorities.  Exercise
# the approved legacy path, the complete-authority path, or the rejection
# boundary explicitly; never make a partial bundle look deployment-ready.
prepare_validator() {
  local output="$1" prysm_image="$2" fence_image="$3"
  "$extract_directory/source/scripts/release/prepare-hoodi-validator-deployment.sh" \
    --validator-set hoodi-release-001 \
    --validator-public-key 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --withdrawal-address 0x403ff64383b8ddf994d5563550c8040d89f025ac \
    --aws-account-id 123456789012 \
    --web3signer-image 123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-runtime-web3signer@sha256:9a20e02a5821ad72fd318fa2a3ec0158a9a5acd9db80aa9214e9cc991ad4dbc3 \
    --postgres-image 123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-runtime-postgres@sha256:030da09481c3876b71a7e49738a932e1c18c398201a1e4ccfdbff1e5a541215b \
    --prysm-validator-image "$prysm_image" \
    --signing-fence-image "$fence_image" \
    --kubernetes-api-cidr 10.100.0.1/32 --output-dir "$output"
}
prysm_auth="$extract_directory/source/release/prysm-publication-authorization.json"
fence_auth="$extract_directory/source/release/fence-publication-authorization.json"
prysm_record="$extract_directory/rendered/prysm-mtls-publication-record.json"
fence_record="$extract_directory/rendered/fence-release-verification.json"
authority_paths=("$prysm_auth" "$fence_auth" "$prysm_record" "$fence_record")
authority_count=0
for authority_path in "${authority_paths[@]}"; do
  if [ -e "$authority_path" ] || [ -L "$authority_path" ]; then
    authority_count=$((authority_count + 1))
  fi
done
prepared="$temporary_directory/prepared-validator"
case "$authority_count" in
  0)
    prepare_validator "$prepared" \
      123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-prysm@sha256:7fe554adf0efd27c0e5c5a3f80a3bbbec3d3872626208cf0a003b0dee7761f89 \
      123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-fence@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb >/dev/null
    ;;
  4)
    for authority_path in "${authority_paths[@]}"; do
      [ -f "$authority_path" ] && [ ! -L "$authority_path" ] || { printf '%s\n' 'complete validator authority contains an unsafe path' >&2; exit 1; }
    done
    prysm_digest="$(jq -er '.target.manifest_digest | select(type == "string" and test("^sha256:[a-f0-9]{64}$"))' "$prysm_record")"
    fence_digest="$(jq -er '.artifact_digest | select(type == "string" and test("^sha256:[a-f0-9]{64}$"))' "$fence_record")"
    prepare_validator "$prepared" \
      "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/hoodi-release-001-baseline-validator-prysm@$prysm_digest" \
      "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/hoodi-release-001-baseline-validator-fence@$fence_digest" >/dev/null
    ;;
  *)
    set +e
    prepare_validator "$prepared" \
      123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-prysm@sha256:7fe554adf0efd27c0e5c5a3f80a3bbbec3d3872626208cf0a003b0dee7761f89 \
      123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-fence@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb >"$temporary_directory/partial-validator.stdout" 2>"$temporary_directory/partial-validator.stderr"
    partial_status=$?
    set -e
    [ "$partial_status" -eq 65 ] || { printf 'partial validator authority failed with unexpected exit: %s\n' "$partial_status" >&2; exit 1; }
    grep -F -x -- 'release authorization is invalid or orphaned' "$temporary_directory/partial-validator.stderr" >/dev/null || { printf '%s\n' 'partial validator authority did not reach the authorization rejection' >&2; exit 1; }
    [ ! -f "$prepared/validator-deployment-handoff.json" ] || { printf '%s\n' 'partial validator authority produced a completed deployment handoff' >&2; exit 1; }
    ;;
esac
if [ "$authority_count" -eq 0 ] || [ "$authority_count" -eq 4 ]; then
  jq -e '.validator_set == "hoodi-release-001" and .staged_client_replicas == 0 and .staged_fence_replicas == 0' "$prepared/validator-deployment-handoff.json" >/dev/null
fi
jq -e --arg digest "$digest" '
  .schema_version == "v1" and
  .artifact.digest == $digest and
  (.entries | type == "array" and length > 10) and
  all(.entries[]; (.path | startswith("source/") or startswith("rendered/")) and (.sha256 | test("^[0-9a-f]{64}$")))
' "$first/manifest.json" >/dev/null
jq -e 'any(.entries[]; .path == "source/.ci/gitops/approved-oci-artifacts.json" and (.sha256 | test("^[0-9a-f]{64}$")))' "$first/manifest.json" >/dev/null
jq -e --arg digest "$digest" '
  .subject == [{name:"node-operator-release-bundle.tar",digest:{sha256:($digest | ltrimstr("sha256:"))}}] and
  .predicate.buildDefinition.buildType == "https://node-operator.example/release-bundle/v1" and
  .predicate.runDetails.builder.id == "local://node-operator/scripts/ci/build-release-bundle.sh"
' "$first/provenance-input.json" >/dev/null
jq -e --arg digest "$digest" '
  .bomFormat == "CycloneDX" and
  (.components | type == "array") and
  .metadata.component.name == "node-operator-release-bundle.tar" and
  .metadata.component.version == $digest and
  (.metadata.tools.components | any(.[]; .name == "syft"))
' "$first/sbom.cyclonedx.json" >/dev/null

if grep -r -n -E -- 'DO_NOT_PERSIST_|-----BEGIN( [A-Z]+)? PRIVATE KEY-----|(^|[[:space:]])kind:[[:space:]]*Secret([[:space:]]|$)' "$extract_directory" "$first/manifest.json" "$first/provenance-input.json" "$first/sbom.cyclonedx.json" >/dev/null; then
  printf 'bundle contains raw fixture or sensitive material\n' >&2
  exit 1
fi

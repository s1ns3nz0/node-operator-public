#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
context="$repo_root/.ci/vault-agent-hardened"
image_tag="${VAULT_AGENT_TEST_IMAGE:-node-operator-vault-agent-hardened:test}"
scan_output="${VAULT_AGENT_SCAN_OUTPUT:-}"
cleanup_scan=false
config_container=""
mock_container=""
signal_container=""
compat_container=""
vault_server_container=""
test_network=""

for tool in docker grype jq mktemp grep; do
  command -v "$tool" >/dev/null || { printf 'missing command: %s\n' "$tool" >&2; exit 69; }
done
if [[ -z "$scan_output" ]]; then
  scan_output="$(mktemp /tmp/vault-agent-hardened-grype.XXXXXX.json)"
  cleanup_scan=true
fi
cleanup() {
  if [[ -n "$config_container" ]]; then docker rm -f "$config_container" >/dev/null 2>&1 || true; fi
  if [[ -n "$signal_container" ]]; then docker rm -f "$signal_container" >/dev/null 2>&1 || true; fi
  if [[ -n "$compat_container" ]]; then docker rm -f "$compat_container" >/dev/null 2>&1 || true; fi
  if [[ -n "$vault_server_container" ]]; then docker rm -f "$vault_server_container" >/dev/null 2>&1 || true; fi
  if [[ -n "$mock_container" ]]; then docker rm -f "$mock_container" >/dev/null 2>&1 || true; fi
  if [[ -n "$test_network" ]]; then docker network rm "$test_network" >/dev/null 2>&1 || true; fi
  if [[ "$cleanup_scan" == true ]]; then rm -f -- "$scan_output"; fi
}
trap cleanup EXIT

if [[ "${VAULT_AGENT_SKIP_BUILD:-false}" != true ]]; then
  docker buildx build --load --platform linux/amd64 --progress=plain \
    --tag "$image_tag" --file "$context/Dockerfile" "$context"
fi
image_id="$(docker image inspect --format '{{.Id}}' "$image_tag")"
[[ "$image_id" =~ ^sha256:[a-f0-9]{64}$ ]] || { printf 'invalid image id\n' >&2; exit 1; }

inspect="$(docker image inspect "$image_id")"
jq -e '.[0].Architecture == "amd64"
  and .[0].Os == "linux"
  and .[0].Config.User == "100:1000"
  and .[0].Config.Entrypoint == ["vault"]
  and .[0].Config.Labels["io.node-operator.vault-agent-only"] == "true"' \
  <<<"$inspect" >/dev/null

run=(docker run --rm --platform linux/amd64 --network none --read-only
  --cap-drop ALL --security-opt no-new-privileges
  --tmpfs "/home/vault:rw,noexec,nosuid,nodev,uid=100,gid=1000,mode=0750"
  --tmpfs "/vault/secrets:rw,noexec,nosuid,nodev,uid=100,gid=1000,mode=0750"
  "$image_id")

version="$("${run[@]}" version)"
grep -Fq 'Vault v2.1.0' <<<"$version"
help="$("${run[@]}" agent -help)"
grep -Fq 'Vault Agent' <<<"$help"
grep -Fq -- '-config' <<<"$help"

for forbidden in server kv status token; do
  if "${run[@]}" "$forbidden" >/dev/null 2>&1; then
    printf 'forbidden Vault command succeeded: %s\n' "$forbidden" >&2
    exit 1
  fi
done

docker run --rm --platform linux/amd64 --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /home/vault:rw,noexec,nosuid,nodev,uid=100,gid=1000,mode=0750 \
  --tmpfs /vault/secrets:rw,noexec,nosuid,nodev,uid=100,gid=1000,mode=0750 \
  --entrypoint /bin/sh "$image_id" -ceu '
  test "$(id -u)" = 100
  test "$(id -g)" = 1000
  command -v vault >/dev/null
  command -v base64 >/dev/null
  test -w /home/vault
  test -w /vault/secrets
  test ! -w /usr/local/bin/vault
'

config_dir="$(mktemp -d /tmp/vault-agent-config.XXXXXX)"
trap 'rm -rf -- "$config_dir"; cleanup' EXIT
printf '%s\n' 'synthetic-jwt-not-a-secret' > "$config_dir/token"
cat > "$config_dir/agent.hcl" <<'EOF'
exit_after_auth = true
vault { address = "http://127.0.0.1:8200" }
auto_auth {
  method "kubernetes" {
    mount_path = "auth/kubernetes"
    config = { role = "synthetic", token_path = "/fixture/token" }
  }
  sink "file" { config = { path = "/home/vault/token" } }
}
template {
  contents = "{{ with secret \"kv/data/synthetic\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/vault/secrets/rendered"
}
EOF
chmod 0444 "$config_dir/agent.hcl" "$config_dir/token"
config_container="vault-agent-config-test-$$"
docker run --detach --name "$config_container" --platform linux/amd64 --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /home/vault:rw,noexec,nosuid,nodev,uid=100,gid=1000,mode=0750 \
  --tmpfs /vault/secrets:rw,noexec,nosuid,nodev,uid=100,gid=1000,mode=0750 \
  --mount "type=bind,src=$config_dir,dst=/fixture,readonly" \
  "$image_id" agent -config=/fixture/agent.hcl -exit-after-auth >/dev/null
sleep 3
config_output="$(docker logs "$config_container" 2>&1)"
[[ "$(docker inspect --format '{{.State.Running}}' "$config_container")" == true ]] || {
  printf 'agent exited instead of retrying unreachable synthetic auth\n' >&2
  exit 1
}
grep -Eq 'auth handler|authenticate|connection refused' <<<"$config_output"
if grep -Fq 'synthetic-jwt-not-a-secret' <<<"$config_output"; then
  printf 'agent logged authentication material\n' >&2
  exit 1
fi
docker rm -f "$config_container" >/dev/null
config_container=""

# Exercise the exact AgentCommand dispatcher through successful Kubernetes
# auto-auth, file sink, template rendering, exit_after_auth, and SIGTERM. The
# mock implements only the two synthetic Vault API responses and has no host
# port or external network path.
mock_tag="${VAULT_AGENT_MOCK_IMAGE:-node-operator-vault-agent-mock:test}"
if [[ "${VAULT_AGENT_MOCK_SKIP_BUILD:-false}" != true ]]; then
  docker buildx build --load --platform linux/amd64 --progress=plain \
    --target mock-vault --tag "$mock_tag" --file "$context/Dockerfile" "$context"
fi
mock_id="$(docker image inspect --format '{{.Id}}' "$mock_tag")"
[[ "$mock_id" =~ ^sha256:[a-f0-9]{64}$ ]] || { printf 'invalid mock image id\n' >&2; exit 1; }
if [[ "${VAULT_AGENT_MOCK_SKIP_BUILD:-false}" == true ]]; then
  [[ "$mock_id" == sha256:a62f85f70e3479663b579f8e6ffdc6a0e6f15025dbf82723d22883480aebb68f ]] || {
    printf 'cached mock is not the reviewed fixture image\n' >&2; exit 1;
  }
fi
test_network="vault-agent-test-$$"
mock_container="vault-agent-mock-$$"
# Syntactically valid but deliberately non-cryptographic fixture. The real
# Kubernetes auth plugin parses JWT claims before delegating signature trust
# to TokenReview. This token is accepted only by our isolated fake reviewer.
synthetic_claims='{"iss":"kubernetes/serviceaccount","sub":"system:serviceaccount:hoodi:validator","aud":["vault"],"iat":1,"nbf":1,"exp":4102444800,"kubernetes.io/serviceaccount/namespace":"hoodi","kubernetes.io/serviceaccount/service-account.name":"validator","kubernetes.io/serviceaccount/service-account.uid":"synthetic-service-account-uid"}'
synthetic_jwt="$(jq -nr '"{\"alg\":\"RS256\",\"typ\":\"JWT\"}"|@base64').$(jq -nr --arg claims "$synthetic_claims" '$claims|@base64' | tr '+/' '-_' | tr -d '=').c3ludGhldGlj"
printf '%s' "$synthetic_jwt" > "$config_dir/compat-token"
chmod 0444 "$config_dir/compat-token"
docker network create --internal "$test_network" >/dev/null
docker run --detach --name "$mock_container" --network "$test_network" \
  --network-alias vault-agent-mock --platform linux/amd64 \
  -e "SYNTHETIC_SERVICE_ACCOUNT_JWT=$synthetic_jwt" \
  --read-only --cap-drop ALL --security-opt no-new-privileges "$mock_id" >/dev/null

output_dir="$config_dir/output"
mkdir "$output_dir"
chmod 0777 "$output_dir"
sed 's|http://127.0.0.1:8200|http://vault-agent-mock:8200|; s|/home/vault/token|/vault/secrets/token|' \
  "$config_dir/agent.hcl" > "$config_dir/success.hcl"
chmod 0444 "$config_dir/success.hcl"
config_container="vault-agent-success-test-$$"
docker run --detach --name "$config_container" --network "$test_network" --platform linux/amd64 --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /home/vault:rw,noexec,nosuid,nodev,uid=100,gid=1000,mode=0750 \
  --mount "type=bind,src=$config_dir,dst=/fixture,readonly" \
  --mount "type=bind,src=$output_dir,dst=/vault/secrets" \
  "$image_id" agent -config=/fixture/success.hcl -exit-after-auth >/dev/null
for _ in $(seq 1 30); do
  [[ "$(docker inspect --format '{{.State.Running}}' "$config_container")" == false ]] && break
  sleep 1
done
[[ "$(docker inspect --format '{{.State.Running}}' "$config_container")" == false ]] || {
  printf 'successful synthetic Agent did not honor exit_after_auth\n' >&2; exit 1;
}
[[ "$(docker inspect --format '{{.State.ExitCode}}' "$config_container")" == 0 ]]
[[ "$(cat "$output_dir/rendered")" == rendered-ok ]]
[[ -s "$output_dir/token" ]]
success_logs="$(docker logs "$config_container" 2>&1)"
if grep -Eq 'synthetic-(jwt-not-a-secret|client-token)' <<<"$success_logs"; then
  printf 'successful Agent logged authentication material\n' >&2; exit 1
fi
docker rm "$config_container" >/dev/null
config_container=""

sed 's/exit_after_auth = true/exit_after_auth = false/' \
  "$config_dir/success.hcl" > "$config_dir/signal.hcl"
chmod 0444 "$config_dir/signal.hcl"
rm -f -- "$output_dir/rendered" "$output_dir/token"
signal_container="vault-agent-signal-test-$$"
docker run --detach --name "$signal_container" --network "$test_network" --platform linux/amd64 --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /home/vault:rw,noexec,nosuid,nodev,uid=100,gid=1000,mode=0750 \
  --mount "type=bind,src=$config_dir,dst=/fixture,readonly" \
  --mount "type=bind,src=$output_dir,dst=/vault/secrets" \
  "$image_id" agent -config=/fixture/signal.hcl >/dev/null
for _ in $(seq 1 30); do [[ -s "$output_dir/rendered" ]] && break; sleep 1; done
[[ "$(cat "$output_dir/rendered")" == rendered-ok ]]
docker stop --time 5 "$signal_container" >/dev/null
[[ "$(docker inspect --format '{{.State.ExitCode}}' "$signal_container")" == 0 ]]
docker rm "$signal_container" >/dev/null
signal_container=""

# Exercise the hardened 2.1.0 Agent against the exact official linux/amd64
# Vault 1.20.4 server at the same version as the deployment. The server, Kubernetes
# TokenReview endpoint, policy, role, JWT, token, and secret are all ephemeral
# synthetic fixtures on this internal network; no host port or live service is
# reachable.
vault_server_image="${VAULT_AGENT_TEST_SERVER_IMAGE:-hashicorp/vault@sha256:20ff3ed4a4da750d1be0757c82e0a10accc00c26c157bde3a694f2b227300caf}"
case "$vault_server_image" in
  hashicorp/vault@sha256:20ff3ed4a4da750d1be0757c82e0a10accc00c26c157bde3a694f2b227300caf) server_version='1.20.4' ;;
  sha256:5463f9d70fe71b897b165e019dbc1e85aeaa8271130572bd060729dc124ff51f) server_version='2.1.0' ;;
  sha256:8fbe048a50769523a577be1fd41fe7f476e1bda4a345cf25874da6426ac25e49) server_version='2.1.0' ;; # gRPC1.83.2 synthetic fixture only
  *) printf 'unreviewed compatibility server image\n' >&2; exit 64 ;;
esac
vault_server_container="vault-server-1204-test-$$"
docker run --detach --name "$vault_server_container" --network "$test_network" \
  --network-alias vault-server-1204 --platform linux/amd64 --user 100:1000 \
  --entrypoint /bin/vault --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /home/vault:rw,noexec,nosuid,nodev,uid=100,gid=1000,mode=0750 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev \
  --tmpfs /vault/file:rw,noexec,nosuid,nodev,uid=100,gid=1000 \
  --tmpfs /vault/logs:rw,noexec,nosuid,nodev,uid=100,gid=1000 \
  -e VAULT_ADDR=http://127.0.0.1:8200 \
  -e VAULT_TOKEN=synthetic-root-token \
  -e VAULT_DEV_ROOT_TOKEN_ID=synthetic-root-token \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  "$vault_server_image" server -dev -dev-root-token-id=synthetic-root-token \
  -dev-listen-address=0.0.0.0:8200 >/dev/null
server_ready=false
for _ in $(seq 1 30); do
  if docker exec "$vault_server_container" vault status >/dev/null 2>&1; then server_ready=true; break; fi
  sleep 1
done
[[ "$server_ready" == true ]] || { printf 'Vault compatibility server did not become ready\n' >&2; exit 1; }
docker exec "$vault_server_container" vault version | grep -Fq "Vault v$server_version"
docker exec "$vault_server_container" vault audit enable file file_path=/vault/logs/audit.json log_raw=false >/dev/null
docker exec "$vault_server_container" vault auth enable kubernetes >/dev/null
docker exec "$vault_server_container" vault write auth/kubernetes/config \
  kubernetes_host=http://vault-agent-mock:8200 \
  token_reviewer_jwt=synthetic-reviewer-token \
  disable_local_ca_jwt=true disable_iss_validation=true >/dev/null
printf '%s\n' 'path "kv/data/synthetic" { capabilities = ["read"] }' \
  | docker exec -i "$vault_server_container" vault policy write synthetic - >/dev/null
docker exec "$vault_server_container" vault secrets enable -path=kv kv-v2 >/dev/null
docker exec "$vault_server_container" vault kv put kv/synthetic value=rendered-1204 >/dev/null
docker exec "$vault_server_container" vault write auth/kubernetes/role/synthetic \
  bound_service_account_names=validator \
  bound_service_account_namespaces=hoodi \
  audience=vault policies=synthetic ttl=5m >/dev/null

compat_output_dir="$config_dir/compat-output"
mkdir "$compat_output_dir"
chmod 0777 "$compat_output_dir"
cat > "$config_dir/compat-1204.hcl" <<'EOF'
exit_after_auth = true
vault { address = "http://vault-server-1204:8200" }
auto_auth {
  method "kubernetes" {
    mount_path = "auth/kubernetes"
    config = { role = "synthetic", token_path = "/fixture/compat-token" }
  }
  sink "file" { config = { path = "/vault/secrets/token" } }
}
template {
  contents = "{{ with secret \"kv/data/synthetic\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/vault/secrets/rendered"
}
EOF
chmod 0444 "$config_dir/compat-1204.hcl"
compat_container="vault-agent-1204-compat-test-$$"
docker run --detach --name "$compat_container" --network "$test_network" \
  --platform linux/amd64 --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /home/vault:rw,noexec,nosuid,nodev,uid=100,gid=1000,mode=0750 \
  --mount "type=bind,src=$config_dir,dst=/fixture,readonly" \
  --mount "type=bind,src=$compat_output_dir,dst=/vault/secrets" \
  "$image_id" agent -config=/fixture/compat-1204.hcl -exit-after-auth >/dev/null
for _ in $(seq 1 30); do
  [[ "$(docker inspect --format '{{.State.Running}}' "$compat_container")" == false ]] && break
  sleep 1
done
[[ "$(docker inspect --format '{{.State.Running}}' "$compat_container")" == false ]] || {
  printf 'Vault 2.1.0 Agent did not complete against Vault 1.20.4\n' >&2; exit 1;
}
[[ "$(docker inspect --format '{{.State.ExitCode}}' "$compat_container")" == 0 ]]
[[ "$(cat "$compat_output_dir/rendered")" == rendered-1204 ]]
[[ -s "$compat_output_dir/token" ]]
compat_logs="$(docker logs "$compat_container" 2>&1)"
if grep -Fq "$synthetic_jwt" <<<"$compat_logs" || grep -Eq 'synthetic-(jwt-not-a-secret|reviewer-token|root-token)|rendered-1204' <<<"$compat_logs"; then
  printf 'Vault 1.20.4 compatibility test logged synthetic authentication material\n' >&2
  exit 1
fi
# Retain the real API fixture's audit records only in this process. The test
# must observe both login and KV requests, without raw credentials or values.
audit_records="$(docker exec "$vault_server_container" cat /vault/logs/audit.json)"
jq -se 'any(.[]; .type=="request" and .request.path=="auth/kubernetes/login") and
 any(.[]; .type=="request" and .request.path=="kv/data/synthetic") and
 any(.[]; .type=="response" and .request.path=="kv/data/synthetic" and
   ((.response.data.data.value // "")|startswith("hmac-sha256:")))' <<<"$audit_records" >/dev/null
if grep -Fq "$synthetic_jwt" <<<"$audit_records" || grep -Eq 'synthetic-(reviewer-token|root-token)|rendered-1204' <<<"$audit_records"; then
  printf 'file audit leaked synthetic authentication material or KV value\n' >&2; exit 1
fi
printf 'PASS: Agent Kubernetes auth, KV template and non-raw file audit against Vault %s\n' "$server_version"
docker rm "$compat_container" >/dev/null
compat_container=""
docker rm -f "$vault_server_container" >/dev/null
vault_server_container=""

cat > "$config_dir/grype.yaml" <<'EOF'
ignore: []
exclude: []
show-suppressed: true
only-fixed: false
only-notfixed: false
db:
  validate-age: true
  validate-by-hash-on-start: true
EOF
GRYPE_CONFIG="$config_dir/grype.yaml" grype --config "$config_dir/grype.yaml" \
  --show-suppressed "$image_id" -o json > "$scan_output"
jq -e '.descriptor.name == "grype"
  and .descriptor.db.status.valid == true
  and .descriptor.configuration.exclude == []
  and .descriptor.configuration["only-fixed"] == false
  and .descriptor.configuration["only-notfixed"] == false
  and .descriptor.configuration["show-suppressed"] == true
  and (.matches | type == "array")
  and ((.ignoredMatches // []) | type == "array")
  and all((.matches + [.ignoredMatches[]?.match])[];
    (.vulnerability.severity | type) == "string" and
    (.vulnerability.severity | ascii_downcase | IN("critical", "high") | not))
  and any(.source.target.repoDigests[]; endswith("@" + $id))' \
  --arg id "$image_id" "$scan_output" >/dev/null

printf 'PASS: hardened Vault Agent runtime and C/H=0 scan (%s)\n' "$image_id"
if [[ "$cleanup_scan" == false ]]; then printf 'scan=%s\n' "$scan_output"; fi

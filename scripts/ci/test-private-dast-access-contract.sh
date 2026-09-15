#!/usr/bin/env bash
# Check objective: Enforce private DAST reachability and reject retired or overbroad proxy access.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
manifest="$root/deploy/dast/service-and-network-policies.yaml"
installer="$root/scripts/ops/install-private-dast-public-cas.sh"

grep -Fq 'name: prysm-beacon' "$manifest"
grep -Fq 'name: nethermind-upcheck-proxy' "$manifest"
grep -Fq "upstream = 'nethermind-execution'" "$manifest"
grep -Fq "socket.create_connection((upstream, 30303), timeout=5)" "$manifest"
grep -Fq "if self.path != '/upcheck': self.send_error(404); return" "$manifest"
grep -Fq 'def do_POST(self): self.send_error(405)' "$manifest"
grep -Fq 'def do_PATCH(self): self.send_error(405)' "$manifest"
grep -Fq 'if conn is not None: conn.close()' "$manifest"
grep -Fq 'port: 8080' "$manifest"
ruby -ryaml -e '
  documents = YAML.load_stream(File.read(ARGV.fetch(0))).compact
  retired = documents.select { |document| document.dig("metadata", "namespace") == "node-operator-dast" || document.dig("metadata", "name") == "node-operator-dast" }
  abort("retired DAST namespace resources remain") unless retired.empty?
  dast_paths = documents.select { |document| YAML.dump(document).include?("node-operator.io/dast-client") || YAML.dump(document).include?("private-dast-scanner") }
  abort("stale DAST policy paths remain") unless dast_paths.empty?
  retired_signer_upcheck = [
    ["Service", "validator-signer-upcheck-proxy"],
    ["Deployment", "validator-signer-upcheck-proxy"],
    ["NetworkPolicy", "signer-upcheck-proxy-to-signer"],
    ["NetworkPolicy", "signer-upcheck-proxy-egress"]
  ]
  retired_signer_upcheck.each do |kind, name|
    abort("retired signer upcheck object remains: #{kind}/#{name}") if documents.any? { |document| document["kind"] == kind && document.dig("metadata", "name") == name }
  end

  proxies = documents.select { |document| document.dig("kind") == "Deployment" && document.dig("metadata", "name") == "nethermind-upcheck-proxy" }
  abort("missing fixed Nethermind upcheck proxy") unless proxies.length == 1
  proxies.each do |proxy|
    container = proxy.dig("spec", "template", "spec", "containers")&.fetch(0)
    abort("#{proxy.dig("metadata", "name")} must explicitly disable privilege") unless container&.dig("securityContext", "privileged") == false
  end

  nethermind = documents.find { |document| document.dig("kind") == "Service" && document.dig("metadata", "namespace") == "node-operator" && document.dig("metadata", "name") == "nethermind-execution" }
  abort("missing fixed Nethermind P2P Service") unless nethermind
  abort("wrong Nethermind P2P selector") unless nethermind.dig("spec", "selector") == {"app.kubernetes.io/name" => "nethermind"}
  ports = nethermind.dig("spec", "ports")
  abort("Nethermind Service must expose only TCP P2P 30303") unless ports == [{"name" => "p2p-tcp", "port" => 30303, "targetPort" => "p2p-tcp", "protocol" => "TCP"}]
' "$manifest"
grep -Fq 'PRIVATE KEY' "$installer"
# shellcheck disable=SC2016 # Assert literal commands in the installer contract.
grep -Fq 'openssl x509 -in "$signer_ca" -out "$signer_certificate"' "$installer"
if grep -Ev '^[[:space:]]*#' "$installer" | grep -Eq 'node-operator-dast|kubectl[[:space:]].*-n[[:space:]]+vault|vault-0|VAULT_TOKEN|JWT'; then
  printf 'signer CA installer must not access retired DAST or Vault material\n' >&2
  exit 1
fi
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
export TMPDIR="$scratch"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$scratch/key.pem" -out "$scratch/cert.pem" -subj /CN=test-dast-ca -days 1 >/dev/null 2>&1
cat "$scratch/cert.pem" "$scratch/key.pem" > "$scratch/mixed.pem"
mkdir -p "$scratch/bin"
cat > "$scratch/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *' create configmap '* ]]; then
  printf '%s\n' "$*" >> "$TEST_KUBECTL_CALLS"
  for argument in "$@"; do
    if [[ "$argument" == --from-file=ca.crt=* ]]; then
      file="${argument#--from-file=ca.crt=}"
      [[ "$file" == "$TMPDIR"/node-operator-signer-public-ca.* ]]
      openssl x509 -in "$file" -noout >/dev/null
      ! grep -q 'PRIVATE KEY' "$file"
    fi
  done
  printf 'public-configmap-fixture\n'
else
  cat >/dev/null
fi
EOF
chmod 0755 "$scratch/bin/kubectl"
if PRIVATE_EKS_SESSION=1 PATH="$scratch/bin:$PATH" "$installer" --signer-ca "$scratch/mixed.pem" >/dev/null 2>&1; then
  printf 'installer accepted a PEM containing a private key\n' >&2
  exit 1
fi
TEST_KUBECTL_CALLS="$scratch/calls" PRIVATE_EKS_SESSION=1 PATH="$scratch/bin:$PATH" "$installer" --signer-ca "$scratch/cert.pem" >/dev/null
test "$(wc -l < "$scratch/calls" | tr -d ' ')" = 1
grep -Fq -- '-n validator-operations create configmap validator-hoodi-example-signer-ca --from-file=ca.crt=' "$scratch/calls"

# Execute the fixed Nethermind reachability proxy. It may establish and close
# a TCP connection but must never send application bytes or expose JSON-RPC.
nethermind_proxy_code="$(awk '
  /              import socket/ { capture=1 }
  capture && /              HTTPServer\(\('\''0\.0\.0\.0'\'', 8080\), Handler\)\.serve_forever\(\)/ { exit }
  capture { sub(/^              /, ""); print }
' "$manifest")"
NETHERMIND_PROXY_CODE="$nethermind_proxy_code" python3 - <<'PY'
import os
import socket

connections = []
class Connection:
    def close(self): connections.append('closed')
def create_connection(address, timeout):
    assert address == ('nethermind-execution', 30303)
    assert timeout == 5
    connections.append('connected')
    return Connection()
socket.create_connection = create_connection
scope = {}
exec(os.environ['NETHERMIND_PROXY_CODE'], scope)
Handler = scope['Handler']

def invoke(method, path):
    handler = object.__new__(Handler)
    handler.path = path
    events = []
    handler.send_response = lambda status: events.append(('response', status))
    handler.end_headers = lambda: events.append(('end',))
    handler.send_error = lambda status: events.append(('error', status))
    getattr(handler, method)()
    return events

assert invoke('do_GET', '/upcheck') == [('response', 200), ('end',)]
assert connections == ['connected', 'closed']
for method in ('do_POST', 'do_PUT', 'do_DELETE', 'do_PATCH'):
    assert invoke(method, '/upcheck') == [('error', 405)]
assert invoke('do_GET', '/jsonrpc') == [('error', 404)]
assert connections == ['connected', 'closed']

import io
class Request:
    def __init__(self, method, path):
        self.input = io.BytesIO(f'{method} {path} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
        self.output = io.BytesIO()
    def makefile(self, *args): return self.input
    def sendall(self, data): self.output.write(data)
def unavailable_connection(*args, **kwargs): raise OSError('fixture upstream unavailable')
for method, path, status in [('GET', '/upcheck', 200), ('GET', '/denied', 404), ('POST', '/upcheck', 405), ('GET', '/upcheck', 503)]:
    if status == 503: socket.create_connection = unavailable_connection
    request = Request(method, path)
    Handler(request, ('127.0.0.1', 1), None)
    headers = request.output.getvalue().split(b'\r\n\r\n', 1)[0].lower()
    assert headers.startswith(f'http/1.0 {status} '.encode())
    assert b'\r\ndate:' in headers
    assert b'\r\nserver:' not in headers and b'python' not in headers
PY
if [ -n "${KYVERNO_BIN:-}" ] || command -v kyverno >/dev/null 2>&1; then
  bash "$root/scripts/ci/test-kyverno-workload-baseline.sh"
else
  printf 'SKIP: Kyverno CLI is unavailable; standalone real-engine fixture suite remains required.\n'
fi
printf 'PASS retired DAST access is absent; fixed upcheck proxies and signer public-CA rejection checks remain.\n'

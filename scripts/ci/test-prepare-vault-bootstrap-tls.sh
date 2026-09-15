#!/usr/bin/env bash
# Mock the TLS-only phase: it must not wait for, mutate, or read an existing Vault.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
helper="$root/scripts/release/prepare-vault-bootstrap-tls.sh"
scratch="$(mktemp -d)"; trap 'rm -rf -- "$scratch"' EXIT
manifest="$scratch/tls.yaml"; printf '%s\n' 'apiVersion: v1' 'kind: ConfigMap' 'metadata: {name: public-tls-input}' > "$manifest"
mkdir "$scratch/bin"; trace="$scratch/trace"
cat > "$scratch/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TRACE"
case "${1:-}" in
  get)
    case " $* " in
      *' namespace vault '*) [ "${MODE:-first}" = existing ] && printf 'namespace/vault\n' || true ;;
      *) ;;
    esac ;;
  -n)
    shift 2
    case "${1:-}" in
      get) case " $* " in *' statefulset vault '*) [ "${MODE:-first}" = existing ] && printf 'statefulset.apps/vault\n' || true ;; *' secret vault-tls '*) printf 'secret/vault-tls\n' ;; esac ;;
      wait) [ "${FAIL_TLS:-0}" = 1 ] && exit 75 ;;
      rollout) ;;
    esac ;;
  wait|apply|create|label)
    if [ "${FAIL_TLS:-0}" = 1 ] && [[ " $* " == *'certificate/vault-'* ]]; then exit 75; fi ;;
esac
true
EOF
chmod 700 "$scratch/bin/kubectl"
run() { PATH="$scratch/bin:$PATH" TRACE="$trace" MODE="$1" FAIL_TLS="${2:-0}" "$helper" --manifest "$manifest"; }
run first
grep -Fq 'apply -f' "$trace"
: > "$trace"
run existing
if grep -Eq '(apply|create|label|rollout.*statefulset/vault|secret.*-o (json|yaml))' "$trace"; then
  printf '%s\n' 'FAIL: existing Vault TLS check mutated Vault, required rollout, or read secret bytes' >&2; exit 1
fi
: > "$trace"
if run first 1; then printf '%s\n' 'FAIL: TLS certificate failure was accepted' >&2; exit 1; fi
grep -Fq 'certificate/vault-' "$trace"
: > "$trace"
if run existing 1; then printf '%s\n' 'FAIL: existing Vault TLS certificate failure was accepted' >&2; exit 1; fi
if grep -Eq '(apply|create|label|rollout.*statefulset/vault|secret.*-o (json|yaml))' "$trace"; then
  printf '%s\n' 'FAIL: failed existing Vault TLS check mutated Vault or read secret bytes' >&2; exit 1
fi
printf '%s\n' 'PASS: TLS preparation is certificate-only and leaves existing OnDelete/uninitialized Vault untouched.'

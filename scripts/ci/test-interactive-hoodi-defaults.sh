#!/usr/bin/env bash
# Check objective: interactive Hoodi defaults come only from CLI/repository context.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
helper="$root/scripts/release/interactive-hoodi-defaults.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"

cat > "$tmp/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  "configure get region --profile default") printf '%s\n' ap-northeast-2 ;;
  "sts get-caller-identity --output json") printf '%s\n' '{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/operator"}' ;;
  *) printf 'unexpected aws arguments: %s\n' "$*" >&2; exit 64 ;;
esac
EOF
cat > "$tmp/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = api ] && [ "$2" = repos/example/node-operator ] && [ "$3" = --jq ]
printf '%s\n' $'example/node-operator\t101\t202'
EOF
cat > "$tmp/bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = config ] && [ "$2" = --get ] && [ "$3" = remote.origin.url ]
printf '%s\n' https://github.com/example/node-operator.git
EOF
chmod 700 "$tmp/bin/aws" "$tmp/bin/gh" "$tmp/bin/git"

result="$(PATH="$tmp/bin:$PATH" HOME="$tmp/home" AWS_ACCESS_KEY_ID=must-not-read AWS_SECRET_ACCESS_KEY=must-not-read AWS_SESSION_TOKEN=must-not-read bash "$helper")"
jq -e '
  .aws_profile == "default" and .aws_region == "ap-northeast-2" and
  .aws_account_id == "123456789012" and (.deployment_name | test("^node-[0-9]{10}-[0-9a-f]{4}$")) and
  .github_repository == "example/node-operator" and .github_owner_id == "101" and .github_repository_id == "202" and
  .gitops_client_github_repository == "example/node-operator" and .gitops_client_github_owner_id == "101" and .gitops_client_github_repository_id == "202"
' <<<"$result" >/dev/null

if grep -En 'AWS_(SECRET_ACCESS_KEY|SESSION_TOKEN|ACCESS_KEY_ID)|GITHUB_TOKEN|VAULT_TOKEN|\.env|release/env|bundle_root/env' "$helper"; then
  printf '%s\n' 'interactive defaults helper reads a secret-bearing input' >&2
  exit 1
fi
printf '%s\n' 'PASS: interactive Hoodi defaults are derived without env files or secret reads.'

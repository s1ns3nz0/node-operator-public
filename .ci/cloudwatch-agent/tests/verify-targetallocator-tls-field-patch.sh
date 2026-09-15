#!/bin/sh
# Usage: sh tests/verify-targetallocator-tls-field-patch.sh /path/to/prometheusreceiver-module
# Applies the existing receiver patch first because the manager preimage is the
# resulting post-patch file, then validates the TLS compatibility patch with
# GNU patch on private copies only.
set -eu

module_dir=${1:?prometheusreceiver module directory is required}
root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
prom_patch="$root_dir/patches/prometheusreceiver-metric-family.patch"
tls_patch="$root_dir/patches/targetallocator-tls-field.patch"
expected_config_sha=2e0fc072d27e07d94d515b0bb24a7254705b9e15857ae77492238f0545429731
expected_manager_post_prom_sha=1cdebdd672a05532b7595576092825202a97fda651b5d43e0f67f9115877fe5e
expected_tls_patch_sha=1a9a9b67eafc139031f08512255cc7cba413d7138ec2a40d53734d81292a85b8
scratch_dir=$(mktemp -d)
trap 'rm -rf "$scratch_dir"' EXIT HUP INT TERM

patch --version | grep -F 'GNU patch' >/dev/null
test "$(sha256sum "$module_dir/targetallocator/config.go" | awk '{print $1}')" = "$expected_config_sha"
cp -R "$module_dir" "$scratch_dir/module"
chmod -R u+w "$scratch_dir/module"
patch --batch --fuzz=0 -d "$scratch_dir/module" -p1 < "$prom_patch"
test "$(sha256sum "$scratch_dir/module/targetallocator/manager.go" | awk '{print $1}')" = "$expected_manager_post_prom_sha"
test "$(sha256sum "$tls_patch" | awk '{print $1}')" = "$expected_tls_patch_sha"
patch --dry-run --batch --fuzz=0 -d "$scratch_dir/module" -p1 < "$tls_patch"
patch --batch --fuzz=0 -d "$scratch_dir/module" -p1 < "$tls_patch"
test "$(grep -R -h -o 'TLSSetting' "$scratch_dir/module/targetallocator/config.go" "$scratch_dir/module/targetallocator/manager.go" | wc -l | tr -d ' ')" -eq 0
test "$(grep -R -h -o '\.TLS\.' "$scratch_dir/module/targetallocator/config.go" "$scratch_dir/module/targetallocator/manager.go" | wc -l | tr -d ' ')" -eq 18
grep -F 'addFile(m.cfg.TLS.CAFile)' "$scratch_dir/module/targetallocator/manager.go" >/dev/null
grep -F 'addFile(m.cfg.TLS.CertFile)' "$scratch_dir/module/targetallocator/manager.go" >/dev/null
grep -F 'addFile(m.cfg.TLS.KeyFile)' "$scratch_dir/module/targetallocator/manager.go" >/dev/null

cp -R "$module_dir" "$scratch_dir/tampered"
chmod -R u+w "$scratch_dir/tampered"
patch --batch --fuzz=0 -d "$scratch_dir/tampered" -p1 < "$prom_patch"
sed -i.bak 's/allocConf\.TLSSetting\.KeyFile/allocConf.TLSSetting.changedKeyFile/' "$scratch_dir/tampered/targetallocator/config.go"
rm -f "$scratch_dir/tampered/targetallocator/config.go.bak"
if patch --dry-run --batch --fuzz=0 -d "$scratch_dir/tampered" -p1 < "$tls_patch"; then
  echo 'expected altered TLS preimage to reject the patch' >&2
  exit 1
fi

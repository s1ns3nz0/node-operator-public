#!/usr/bin/env bash
# Generate a bounded local artifact authority projection for a fresh deployment.
set -euo pipefail
umask 077
bundle=''; work=''; account=''; region=''; deployment=''; revision=''; output=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle-root) bundle="${2:-}"; shift 2;; --work-dir) work="${2:-}"; shift 2;; --account) account="${2:-}"; shift 2;; --region) region="${2:-}"; shift 2;; --deployment-name) deployment="${2:-}"; shift 2;; --release-sha) revision="${2:-}"; shift 2;; --output) output="${2:-}"; shift 2;; *) exit 64;; esac
done
[ -n "$bundle$work$account$region$deployment$revision$output" ] || exit 64
[ ! -e "$output" ] || exit 65
inventory="$bundle/rendered/installer-artifact-index.json"
[ -f "$inventory" ] || { printf '%s\n' 'release artifact inventory is unavailable' >&2; exit 65; }
python3 - "$inventory" "$account" "$region" "$deployment" "$revision" "$output" <<'PY'
import json, os, sys
src, account, region, deployment, revision, out = sys.argv[1:]
data=json.load(open(src))
components=data.get('components')
if not isinstance(components,dict): raise SystemExit('release artifact inventory is invalid')
value={'schema_version':1,'aws_account_id':account,'aws_region':region,'deployment_name':deployment,'release_sha':revision,'components':components}
tmp=out+'.tmp'
with open(tmp,'w') as f: json.dump(value,f,sort_keys=True); f.write('\n')
os.chmod(tmp,0o600); os.replace(tmp,out)
PY
printf 'PASS local artifact authority written: %s\n' "$output"

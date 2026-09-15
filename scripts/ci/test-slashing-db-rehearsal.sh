#!/usr/bin/env bash
# Check objective: Validate the slashing database rehearsal rendering.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"; renderer="$root/scripts/ops/render-slashing-db-rehearsal.py"; scratch="$(mktemp -d)"; trap 'rm -rf "$scratch"' EXIT
image='123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-runtime-postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
metadata="$scratch/clone.json"
jq -n --arg image "$image" '{schema_version:1,aws_account_id:"123456789012",source_volume_id:"resource-example",clone_volume_id:"resource-example",aws_region:"ap-northeast-2",availability_zone:"ap-northeast-2b",size_gib:50,encrypted:true,kms_key_arn:"arn:aws:kms:ap-northeast-2:123456789012:key/11111111-2222-3333-4444-555555555555",postgres_image:$image,postgres_major:16,validator_set:"hoodi-example",validator_public_key:("0x" + ("a" * 96))}' > "$metadata"
chmod 600 "$metadata"
PYTHONDONTWRITEBYTECODE=1 python3 "$renderer" --clone-metadata "$metadata" --output "$scratch/render.json"
jq -e --arg image "$image" '[.items[] | .kind] == ["PersistentVolume","PersistentVolumeClaim","NetworkPolicy","Pod"] and .items[0].spec.csi.volumeHandle == "resource-example" and .items[0].spec.claimRef == {namespace:"validator-operations",name:"validator-hoodi-example-slashing-db-rehearsal"} and (.items[0] | tostring | contains("resource-example")) and .items[0].spec.capacity.storage == "50Gi" and .items[1].spec.resources.requests.storage == "50Gi" and .items[0].spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions[0].values == ["ap-northeast-2b"] and .items[0].metadata.annotations["node-operator.io/ebs-encrypted"] == "true" and .items[0].metadata.annotations["node-operator.io/kms-key-arn"] == "arn:aws:kms:ap-northeast-2:123456789012:key/11111111-2222-3333-4444-555555555555" and .items[2].spec.policyTypes == ["Ingress","Egress"] and .items[3].spec.automountServiceAccountToken == false and .items[3].spec.restartPolicy == "Never" and .items[3].spec.containers[0].image == $image and (.items[3].spec.volumes | tostring | contains("resource-example") | not) and (.items[3].spec.initContainers[0].command[-1] | contains("cat /var/lib/postgresql/data/pgdata/PG_VERSION)\" = 16")) and (.items[3].spec.initContainers[0].command[-1] | contains("postgres --version"))' "$scratch/render.json" >/dev/null
for mutation in '.clone_volume_id="resource-example"' '.encrypted=false' '.availability_zone="ap-northeast-1a"' '.size_gib=0' '.postgres_major=9' '.aws_account_id="999999999999"'; do
  bad="$scratch/bad-${RANDOM}.json"; jq "$mutation" "$metadata" > "$bad"
  if python3 "$renderer" --clone-metadata "$bad" --output "$scratch/out-${RANDOM}.json" >/dev/null 2>&1; then exit 1; fi
done
jq '.kms_key_arn="arn:aws:kms:ap-northeast-2:999999999999:key/11111111-2222-3333-4444-555555555555"' "$metadata" > "$scratch/wrong-kms.json"
if python3 "$renderer" --clone-metadata "$scratch/wrong-kms.json" --output "$scratch/wrong-kms-out.json" >/dev/null 2>&1; then exit 1; fi
jq '.postgres_image="123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' "$metadata" > "$scratch/wrong-image.json"
if python3 "$renderer" --clone-metadata "$scratch/wrong-image.json" --output "$scratch/wrong-image-out.json" >/dev/null 2>&1; then exit 1; fi
if python3 "$renderer" --clone-metadata "$metadata" --output "$scratch/render.json" >/dev/null 2>&1; then exit 1; fi
if python3 "$renderer" --clone-metadata "$metadata" --output relative.json >/dev/null 2>&1; then exit 1; fi
printf 'PASS: clone rehearsal renderer is metadata-bound, isolated, and non-applying\n'

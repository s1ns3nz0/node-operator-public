#!/usr/bin/env bash
# Opt-in, disposable native prerequisite harness.  It never pulls images.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
for command in docker jq openssl; do command -v "$command" >/dev/null 2>&1 || { printf 'SKIP: missing %s; no image pull attempted\n' "$command"; exit 0; }; done
web_source="$(jq -er '.images.web3signer.source | select(type == "string")' "$root/.ci/validator/approved-runtime-images.json")"
postgres_source="$(jq -er '.images.postgres.source | select(type == "string")' "$root/.ci/validator/approved-runtime-images.json")"
lock="$(jq -er '.tag == "26.4.2" and .commit == "221996a5ddf6ab7648a8102ee029d9723762c116"' "$root/.ci/web3signer-hardened/source.lock.json")"
[ "$lock" = true ] || { printf '%s\n' 'FAIL: Web3Signer source lock is not the reviewed 26.4.2 commit' >&2; exit 1; }
if ! docker image inspect "$web_source" >/dev/null 2>&1 || ! docker image inspect "$postgres_source" >/dev/null 2>&1; then
  printf 'SKIP: exact local native prerequisites are unavailable (Web3Signer=%s PostgreSQL=%s); no pull attempted\n' "$web_source" "$postgres_source"
  exit 0
fi
fixture="$(mktemp -d /private/tmp/slashing-native.XXXXXX)"; run="slashing-native-${fixture##*/}"; network="${run}-net"; volume="${run}-db"; database="${run}-postgres"; migration_source="${run}-migration-source"; signer="${run}-signer"; network_created=false; volume_created=false; database_created=false; migration_source_created=false; signer_created=false
case "$fixture" in /private/tmp/slashing-native.??????) ;; *) printf '%s\n' 'FAIL: refused unsafe disposable fixture path' >&2; exit 69 ;; esac
cleanup() { set +e; [ "$signer_created" = true ] && docker rm -f "$signer" >/dev/null 2>&1; [ "$migration_source_created" = true ] && docker rm -f "$migration_source" >/dev/null 2>&1; [ "$database_created" = true ] && docker rm -f "$database" >/dev/null 2>&1; [ "$network_created" = true ] && docker network rm "$network" >/dev/null 2>&1; [ "$volume_created" = true ] && docker volume rm "$volume" >/dev/null 2>&1; rm -rf -- "$fixture"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$fixture/keys"; chmod 700 "$fixture/keys"
database_password="$(openssl rand -hex 24)"
test_private_key="00$(openssl rand -hex 31)"
test "$test_private_key" != "$(printf '00%.0s' $(seq 1 32))" || { printf '%s\n' 'FAIL: generated an unusable zero test key' >&2; exit 1; }
docker network create --internal "$network" >/dev/null; network_created=true
docker volume create "$volume" >/dev/null; volume_created=true
docker run -d --name "$database" --network "$network" --mount "type=volume,src=$volume,dst=/var/lib/postgresql/data" -e POSTGRES_USER=web3signer -e POSTGRES_DB=web3signer -e POSTGRES_PASSWORD="$database_password" "$postgres_source" >/dev/null; database_created=true
for _ in $(seq 1 60); do docker exec "$database" pg_isready -U web3signer -d web3signer >/dev/null 2>&1 && break; sleep 1; done
docker exec "$database" pg_isready -U web3signer -d web3signer >/dev/null || { printf '%s\n' 'FAIL: disposable PostgreSQL did not become ready' >&2; exit 1; }
# The maintenance subcommands must receive the password through Web3Signer's
# eth2-scoped environment default, not an argv option.  This exercises the
# same image digest and command shape used by the maintenance Job.
printf 'WEB3SIGNER_ETH2_SLASHING_PROTECTION_DB_PASSWORD=%s\n' "$database_password" >"$fixture/web3signer.env"
chmod 600 "$fixture/web3signer.env"
native=(docker run --rm --network "$network" --mount "type=bind,src=$fixture,dst=/work,readonly" --env-file "$fixture/web3signer.env" "$web_source" eth2 --slashing-protection-db-url="jdbc:postgresql://$database:5432/web3signer" --slashing-protection-db-username=web3signer)
# Subcommands require an already-migrated schema.  Copy only the migration SQL
# packaged in this exact image, then apply it to this owned disposable database.
docker create --name "$migration_source" "$web_source" >/dev/null; migration_source_created=true
docker cp "$migration_source:/opt/web3signer/migrations/postgresql/." "$fixture/migrations"
for migration in "$fixture"/migrations/V*.sql; do docker exec -i "$database" psql -v ON_ERROR_STOP=1 -U web3signer -d web3signer <"$migration" >/dev/null; done
test "$(docker exec "$database" psql -Atq -U web3signer -d web3signer -c 'SELECT version FROM database_version WHERE id = 1')" = 12
docker rm "$migration_source" >/dev/null; migration_source_created=false
# Empty database repair is a no-op before any signer has loaded a key.
"${native[@]}" watermark-repair --slot 64 --epoch 2 >/dev/null
test "$(docker exec "$database" psql -Atq -U web3signer -d web3signer -c 'SELECT count(*) FROM low_watermarks')" = 0
# The generated scalar is deliberately below the BLS order (leading zero) and
# exists only in this private disposable fixture.
cat >"$fixture/keys/ephemeral-test.yaml" <<EOF
type: file-raw
privateKey: $test_private_key
keyType: BLS
EOF
chmod 600 "$fixture/keys/ephemeral-test.yaml"
docker run -d --name "$signer" --network "$network" --mount "type=bind,src=$fixture,dst=/work,readonly" "$web_source" --key-store-path=/work/keys --http-host-allowlist='*' eth2 --network=minimal --slashing-protection-db-url="jdbc:postgresql://$database:5432/web3signer" --slashing-protection-db-username=web3signer --slashing-protection-db-password="$database_password" >/dev/null; signer_created=true
if [ "$(docker inspect --format '{{.State.Running}}' "$signer")" != true ]; then docker logs "$signer" >&2; exit 1; fi
for _ in $(seq 1 30); do docker exec "$signer" curl --silent --fail http://127.0.0.1:9000/api/v1/eth2/publicKeys >"$fixture/public-keys.json" && break; sleep 1; done
test -s "$fixture/public-keys.json"
key="$(python3 -c 'import json,sys; values=json.load(open(sys.argv[1])); assert isinstance(values,list) and len(values)==1; print(values[0])' "$fixture/public-keys.json")"
root="0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
cat >"$fixture/import.json" <<EOF
{"metadata":{"interchange_format_version":"5","genesis_validators_root":"$root"},"data":[{"pubkey":"$key","signed_blocks":[],"signed_attestations":[]}]}
EOF
chmod 600 "$fixture/import.json"
# Exact source contract: `eth2 import --from`, then `eth2 watermark-repair
# --slot S --epoch E`.
"${native[@]}" import --from /work/import.json >/dev/null
"${native[@]}" watermark-repair --slot 64 --epoch 2 >/dev/null
value="$(docker exec "$database" psql -Atq -U web3signer -d web3signer -c "SELECT concat_ws(':', slot, source_epoch, target_epoch) FROM low_watermarks")"
test "$value" = '64:2:2'
# Low watermarks only increase: a lower repair is accepted as a no-op.
"${native[@]}" watermark-repair --slot 63 --epoch 1 >/dev/null
value="$(docker exec "$database" psql -Atq -U web3signer -d web3signer -c "SELECT concat_ws(':', slot, source_epoch, target_epoch) FROM low_watermarks")"
test "$value" = '64:2:2'
docker restart "$database" >/dev/null
for _ in $(seq 1 30); do docker exec "$database" pg_isready -U web3signer -d web3signer >/dev/null 2>&1 && break; sleep 1; done
test "$(docker exec "$database" psql -Atq -U web3signer -d web3signer -c "SELECT concat_ws(':', slot, source_epoch, target_epoch) FROM low_watermarks")" = '64:2:2'
attestation_request() { epoch="$1"; cat <<EOF
{"type":"ATTESTATION","fork_info":{"fork":{"previous_version":"0x00000000","current_version":"0x00000000","epoch":"0"},"genesis_validators_root":"0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"},"attestation":{"slot":"64","index":"32","beacon_block_root":"0xb2eedb01adbd02c828d5eec09b4c70cbba12ffffba525ebf48aca33028e8ad89","source":{"epoch":"$epoch","root":"0x$(printf '00%.0s' $(seq 1 32))"},"target":{"epoch":"$epoch","root":"0xb2eedb01adbd02c828d5eec09b4c70cbba12ffffba525ebf48aca33028e8ad89"}}}
EOF
}
# A lower request must be refused; equality remains eligible to sign.  Distinct
# roots avoid duplicate-attestation detection obscuring the floor result.
status="$(attestation_request 1 | docker exec -i "$signer" curl --silent --output /tmp/below.json --write-out '%{http_code}' -H 'Content-Type: application/json' --data-binary @- "http://127.0.0.1:9000/api/v1/eth2/sign/$key")"; docker cp "$signer:/tmp/below.json" "$fixture/below.json"; if [ "$status" != 412 ]; then cat "$fixture/below.json" >&2; docker logs "$signer" >&2; exit 1; fi
status="$(attestation_request 2 | docker exec -i "$signer" curl --silent --output /tmp/equal.json --write-out '%{http_code}' -H 'Content-Type: application/json' --data-binary @- "http://127.0.0.1:9000/api/v1/eth2/sign/$key")"; docker cp "$signer:/tmp/equal.json" "$fixture/equal.json"; if [ "$status" != 200 ]; then cat "$fixture/equal.json" >&2; docker logs "$signer" >&2; exit 1; fi
python3 -c 'import json,sys; result=json.load(open(sys.argv[1])); assert isinstance(result.get("signature"),str) and result["signature"].startswith("0x")' "$fixture/equal.json"
docker stop "$signer" >/dev/null
# Exercise the maintenance predicates on native BYTEA keys, and prove repair
# preserves an existing partial signing record rather than reconstructing it.
history_before="$(docker exec "$database" psql -Atq -U web3signer -d web3signer -c 'SELECT row_to_json(a) FROM signed_attestations a ORDER BY target_epoch, source_epoch')"
test -n "$history_before"
"${native[@]}" watermark-repair --slot 96 --epoch 3 >/dev/null
test "$(docker exec "$database" psql -Atq -U web3signer -d web3signer -c 'SELECT row_to_json(a) FROM signed_attestations a ORDER BY target_epoch, source_epoch')" = "$history_before"
test "$(docker exec "$database" psql -Atq -U web3signer -d web3signer -c "SELECT count(*) FROM metadata WHERE encode(genesis_validators_root, 'hex') = '${root#0x}'")" = 1
test "$(docker exec "$database" psql -Atq -U web3signer -d web3signer -c "SELECT count(*) FROM low_watermarks lw JOIN validators v ON v.id = lw.validator_id WHERE encode(v.public_key, 'hex') = '${key#0x}' AND lw.slot >= 64 AND lw.source_epoch >= 2 AND lw.target_epoch >= 2")" = 1
printf '%s\n' 'PASS: disposable pinned native repair preserved slot 64/epoch 2 across lower no-op and restart; below-floor signing returned 412 and equality signed.'
printf '%s\n' 'PASS: later native repair preserved partial signing history; BYTEA identity/genesis and minimum-floor queries passed.'

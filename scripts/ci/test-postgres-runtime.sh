#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="${POSTGRES_RUNTIME_IMAGE:-node-operator-postgres-runtime:test}"
scan_output="${POSTGRES_RUNTIME_SCAN_OUTPUT:-}"
run_id="postgres-runtime-test-$$"
primary="${run_id}-primary"
restart="${run_id}-restart"
missing="${run_id}-missing"
denied="${run_id}-denied"
root_attempt="${run_id}-root"
data_volume="${run_id}-data"
missing_volume="${run_id}-missing-data"
denied_volume="${run_id}-denied-data"
root_volume="${run_id}-root-data"
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/postgres-runtime.XXXXXX")"
if test -z "$scan_output"; then
  scan_output="$fixture_dir/grype.json"
fi

cleanup() {
  docker rm -f "$primary" "$restart" "$missing" "$denied" "$root_attempt" >/dev/null 2>&1 || true
  docker volume rm "$data_volume" "$missing_volume" "$denied_volume" "$root_volume" >/dev/null 2>&1 || true
  rm -rf "$fixture_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

password="runtime-test-secret-$RANDOM-$RANDOM"
printf '%s\n' "$password" >"$fixture_dir/password"
chmod 0444 "$fixture_dir/password"
printf '%s\n' 'CREATE TABLE retained_marker (value text NOT NULL);' \
  "INSERT INTO retained_marker(value) VALUES ('retained-after-restart');" >"$fixture_dir/001.sql"
chmod 0444 "$fixture_dir/001.sql"

docker buildx build --load --platform linux/amd64 \
  --tag "$image" \
  --file "$repo_root/.ci/postgres-runtime/Dockerfile" \
  "$repo_root/.ci/postgres-runtime"
image_id="$(docker image inspect --format '{{.Id}}' "$image")"
case "$image_id" in
  sha256:*) ;;
  *) printf 'built image did not resolve to an immutable ID\n' >&2; exit 1 ;;
esac
runtime_ref="$image_id"
test "$(docker image inspect --format '{{.Config.User}}' "$runtime_ref")" = 999:999
test "$(docker image inspect --format '{{json .Config.Entrypoint}}' "$runtime_ref")" = '["docker-entrypoint.sh"]'
docker run --rm --network none --entrypoint /bin/sh "$runtime_ref" -ceu '! command -v gosu'

version="$(docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges "$runtime_ref" postgres --version)"
case "$version" in
  *'PostgreSQL) 16.15 '*) ;;
  *) printf 'unexpected PostgreSQL version\n' >&2; exit 1 ;;
esac

docker volume create "$data_volume" >/dev/null
docker run -d --name "$primary" --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m,uid=999,gid=999 \
  --tmpfs /var/run/postgresql:rw,noexec,nosuid,size=16m,uid=999,gid=999 \
  --mount "type=volume,src=$data_volume,dst=/var/lib/postgresql/data" \
  --mount "type=bind,src=$fixture_dir/password,dst=/run/secrets/postgres-password,readonly" \
  --mount "type=bind,src=$fixture_dir/001.sql,dst=/docker-entrypoint-initdb.d/001.sql,readonly" \
  -e POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password \
  -e POSTGRES_USER=web3signer -e POSTGRES_DB=web3signer "$runtime_ref" >/dev/null

ready=false
for _ in $(seq 1 60); do
  if value="$(docker exec "$primary" psql -Atq -U web3signer -d web3signer \
    -c 'SELECT value FROM retained_marker' 2>/dev/null)" \
    && test "$value" = retained-after-restart; then ready=true; break; fi
  sleep 1
done
test "$ready" = true
test "$(docker exec "$primary" psql -Atq -U web3signer -d web3signer \
  -c "SELECT datcollate || '|' || datctype FROM pg_database WHERE datname = current_database()")" = 'en_US.UTF-8|en_US.UTF-8'
if docker logs "$primary" 2>&1 | grep -Fq "$password"; then
  printf 'password appeared in container logs\n' >&2
  exit 1
fi
docker stop --time 30 "$primary" >/dev/null
docker rm "$primary" >/dev/null

docker run -d --name "$restart" --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m,uid=999,gid=999 \
  --tmpfs /var/run/postgresql:rw,noexec,nosuid,size=16m,uid=999,gid=999 \
  --mount "type=volume,src=$data_volume,dst=/var/lib/postgresql/data" \
  --mount "type=bind,src=$fixture_dir/password,dst=/run/secrets/postgres-password,readonly" \
  -e POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password \
  -e POSTGRES_USER=web3signer -e POSTGRES_DB=web3signer "$runtime_ref" >/dev/null
ready=false
for _ in $(seq 1 30); do
  if value="$(docker exec "$restart" psql -Atq -U web3signer -d web3signer \
    -c 'SELECT value FROM retained_marker' 2>/dev/null)" \
    && test "$value" = retained-after-restart; then ready=true; break; fi
  sleep 1
done
test "$ready" = true
docker stop --time 30 "$restart" >/dev/null
docker rm "$restart" >/dev/null

docker volume create "$missing_volume" >/dev/null
if docker run --name "$missing" --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m,uid=999,gid=999 \
  --tmpfs /var/run/postgresql:rw,noexec,nosuid,size=16m,uid=999,gid=999 \
  --mount "type=volume,src=$missing_volume,dst=/var/lib/postgresql/data" \
  -e POSTGRES_USER=web3signer -e POSTGRES_DB=web3signer "$runtime_ref" >/dev/null 2>&1; then
  printf 'missing password unexpectedly initialized database\n' >&2
  exit 1
fi

cp "$fixture_dir/password" "$fixture_dir/denied-password"
chmod 0000 "$fixture_dir/denied-password"
docker volume create "$denied_volume" >/dev/null
if docker run --name "$denied" --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m,uid=999,gid=999 \
  --tmpfs /var/run/postgresql:rw,noexec,nosuid,size=16m,uid=999,gid=999 \
  --mount "type=volume,src=$denied_volume,dst=/var/lib/postgresql/data" \
  --mount "type=bind,src=$fixture_dir/denied-password,dst=/run/secrets/postgres-password,readonly" \
  -e POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password \
  -e POSTGRES_USER=web3signer -e POSTGRES_DB=web3signer "$runtime_ref" >/dev/null 2>&1; then
  printf 'unreadable password unexpectedly initialized database\n' >&2
  exit 1
fi

docker volume create "$root_volume" >/dev/null
if docker run --name "$root_attempt" --user 0:0 --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --tmpfs /var/run/postgresql:rw,noexec,nosuid,size=16m \
  --mount "type=volume,src=$root_volume,dst=/var/lib/postgresql/data" \
  "$runtime_ref" postgres -C data_directory >/dev/null 2>&1; then
  printf 'root execution unexpectedly succeeded\n' >&2
  exit 1
fi

grype "docker:$image_id" -o json >"$scan_output"
if ! jq -e '
  .descriptor.name == "grype"
  and (.descriptor.version | type == "string" and length > 0)
  and .descriptor.db.status.valid == true
  and (.matches | type == "array")
' "$scan_output" >/dev/null; then
  printf 'invalid or incomplete Grype evidence\n' >&2
  exit 1
fi
test "$(jq '[.matches[] | select(.vulnerability.severity == "Critical" or .vulnerability.severity == "High")] | length' "$scan_output")" -eq 0

printf 'PASS postgres runtime: PostgreSQL 16.15, retained-volume restart, fail-closed inputs, Critical=0 High=0\n'

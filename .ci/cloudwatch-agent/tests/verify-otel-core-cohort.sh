#!/bin/sh
# Exercises the cohort gate through its public command interface.
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
gate="$root_dir/scripts/otel-core-cohort.sh"
map_file="$root_dir/otel-v0.128-module-sets.yaml"
map_sha=8a132206547abb244d1781f625cc337971b5e87e1871c0f0bcee82c8ba05b1fb
legacy_lock="$root_dir/legacy-expandconverter.lock"
legacy_lock_sha=19681f3395929434cc5eea397f1bf73089cdd33c4f2be257b702735895549772
scratch_dir=$(mktemp -d)
trap 'rm -rf "$scratch_dir"' EXIT HUP INT TERM

cat > "$scratch_dir/valid.txt" <<'EOF'
go.opentelemetry.io/collector/component v1.34.0
go.opentelemetry.io/collector/config/configgrpc v0.128.0
go.opentelemetry.io/collector/config/confignet v1.34.0
go.opentelemetry.io/collector/pipeline/xpipeline v0.128.0
go.opentelemetry.io/collector/confmap/converter/expandconverter v0.113.0
EOF

sh "$gate" verify "$map_file" "$map_sha" "$legacy_lock" "$legacy_lock_sha" "$scratch_dir/valid.txt"
sh "$gate" emit "$map_file" "$map_sha" "$legacy_lock" "$legacy_lock_sha" "$scratch_dir/valid.txt" > "$scratch_dir/args.txt"
grep -Fx 'go.opentelemetry.io/collector/config/configgrpc@v0.128.0' "$scratch_dir/args.txt" >/dev/null
grep -Fx 'go.opentelemetry.io/collector/config/confignet@v1.34.0' "$scratch_dir/args.txt" >/dev/null
grep -Fx 'go.opentelemetry.io/collector/confmap/converter/expandconverter@v0.113.0' "$scratch_dir/args.txt" >/dev/null

cat > "$scratch_dir/unmapped.txt" <<'EOF'
go.opentelemetry.io/collector/component v1.34.0
go.opentelemetry.io/collector/not-a-real-module v0.128.0
EOF
if sh "$gate" verify "$map_file" "$map_sha" "$legacy_lock" "$legacy_lock_sha" "$scratch_dir/unmapped.txt"; then
  echo 'unmapped module was accepted' >&2
  exit 1
fi

cat > "$scratch_dir/mismatched.txt" <<'EOF'
go.opentelemetry.io/collector/config/configgrpc v0.124.0
EOF
if sh "$gate" verify "$map_file" "$map_sha" "$legacy_lock" "$legacy_lock_sha" "$scratch_dir/mismatched.txt"; then
  echo 'mismatched module version was accepted' >&2
  exit 1
fi
sh "$gate" emit "$map_file" "$map_sha" "$legacy_lock" "$legacy_lock_sha" "$scratch_dir/mismatched.txt" > "$scratch_dir/mismatch-args.txt"
grep -Fx 'go.opentelemetry.io/collector/config/configgrpc@v0.128.0' "$scratch_dir/mismatch-args.txt" >/dev/null

: > "$scratch_dir/empty.txt"
if sh "$gate" verify "$map_file" "$map_sha" "$legacy_lock" "$legacy_lock_sha" "$scratch_dir/empty.txt"; then
  echo 'empty production closure was accepted' >&2
  exit 1
fi

printf '%s\n' 'example.invalid/noncore v1.0.0' > "$scratch_dir/noncore.txt"
if sh "$gate" verify "$map_file" "$map_sha" "$legacy_lock" "$legacy_lock_sha" "$scratch_dir/noncore.txt"; then
  echo 'non-core-only production closure was accepted' >&2
  exit 1
fi

printf '%s\n' 'go.opentelemetry.io/collector/config/configgrpc' > "$scratch_dir/truncated.txt"
if sh "$gate" verify "$map_file" "$map_sha" "$legacy_lock" "$legacy_lock_sha" "$scratch_dir/truncated.txt"; then
  echo 'truncated core closure record was accepted' >&2
  exit 1
fi

cp "$map_file" "$scratch_dir/tampered.yaml"
printf '\n# changed fixture\n' >> "$scratch_dir/tampered.yaml"
if sh "$gate" verify "$scratch_dir/tampered.yaml" "$map_sha" "$legacy_lock" "$legacy_lock_sha" "$scratch_dir/valid.txt"; then
  echo 'tampered module map was accepted' >&2
  exit 1
fi

cat > "$scratch_dir/wrong-legacy.txt" <<'EOF'
go.opentelemetry.io/collector/component v1.34.0
go.opentelemetry.io/collector/confmap/converter/expandconverter v0.113.1
EOF
if sh "$gate" emit "$map_file" "$map_sha" "$legacy_lock" "$legacy_lock_sha" "$scratch_dir/wrong-legacy.txt"; then
  echo 'wrong legacy version was accepted' >&2
  exit 1
fi

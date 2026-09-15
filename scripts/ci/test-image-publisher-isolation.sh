#!/usr/bin/env bash
# Check objective: Ensure image publishers have isolated, digest-scoped permissions and release paths.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$root/scripts/ci/lib/workflow-contract.sh"
workflow="$root/.github/workflows/image-publish.yml"

if ! ruby -ryaml -e '
  jobs = YAML.load_file(ARGV[0]).fetch("jobs")
  {"scanner-build" => "scanner-publish", "toolchain-build" => "toolchain-publish"}.each do |build_name, publish_name|
    build = jobs.fetch(build_name); publish = jobs.fetch(publish_name)
    abort unless build.dig("permissions", "packages") == "read" && publish.dig("permissions", "packages") == "write"
    abort unless publish.fetch("needs").include?(build_name)
    abort unless publish.fetch("if").include?("github.ref == '\''refs/heads/main'\''") && publish.fetch("if").include?("#{build_name}.result == '\''success'\''")
  end
' "$workflow"; then
  printf 'image build and publish jobs must remain isolated by package permission, dependency, and main-success gate\n' >&2
  exit 1
fi
grep -Fq 'docker save --output' <(workflow_source "$workflow")
grep -Fq 'docker load --input' <(workflow_source "$workflow")
grep -Fq 'retention-days: 1' "$workflow"

grep -Fq 'io.node-operator.scanner-input-sha' <(workflow_source "$workflow")
grep -Fq 'io.node-operator.toolchain-input-sha' <(workflow_source "$workflow")

# CloudWatch Agent local rebuild candidate

This directory defines an unpublished local rebuild candidate for AWS CloudWatch
Agent 1.300071.0. It rebuilds the three Linux runtime executables:
`amazon-cloudwatch-agent`, `start-amazon-cloudwatch-agent`, and
`config-translator`. It does not publish, mirror, contact AWS, amend an image
catalog, or waive scan findings.

`source-lock.json` is the source of truth for the official runtime image, source
commit, Go 1.27.1 builder manifest, candidate module inputs, and reviewed patch
preconditions. The scan-proposed `x/net` 0.56.0 and `x/text` 0.39.0 cannot
coexist with `x/crypto` 0.56.0; the prior solver selected `x/net` 0.57.0 and
`x/text` 0.41.0. The Prometheus 0.305.3 attempt resolved its graph but did not
compile to a candidate image.

## Verified local builder transport

The Dockerfile default remains the pinned Docker Hub Go manifest. A local alias
is used only with `--pull=false` when daemon registry retrieval is unavailable;
it is a verified transport workaround, not an approved runtime or release
dependency.

The retained OCI evidence binds the Go linux/amd64 manifest
`sha256:b475798fb16158e6c38e8b5ca2d870fbeaa8b7fec0fc8ec64b3dc20966040635`, config
`sha256:4914eace4b4c8c68ecd495fb71edbc01f706ba9a7ae0e5d38affbb512c36dee3`,
and seven ordered layer diff IDs. The loaded alias
`local/cloudwatch-go-builder:verified` is amd64 with Docker descriptor/image ID
`sha256:fc0a285bef616256d06bfe808a30cf8a02b7938354923c50c83533acd59c124b`.
Docker conversion adds empty defaults to the inspected config, but its semantic
config and RootFS match the verified archive.

The imported source and converted Docker transport archives were deleted during
user-requested disk cleanup. The verified local builder remains loaded. The
converted archive's recorded decompressed SHA-256 is
`0629937ab674ff517c162322a67b9ee880839290a71336b9cae5529c95110e7c`;
reconstructing that transport requires downloading the pinned source again.

## Current build state

The Dockerfile fetches only source commit
`7c48fecadbdb49314f123449fa2167361d307c10`, writes the known release version
for the shallow-clone Make fallback, applies exact pinned module updates, then
uses `go list -mod=mod -deps` only for the three production main packages. It
captures the resulting `go.mod`, `go.sum`, and module list, then compiles with
`GOFLAGS=-mod=readonly`, `GOMAXPROCS=2`, and `GOMEMLIMIT=2GiB`.

The complete Prometheus receiver package, including its target allocator,
compiles before the broader resolver regression to
surface receiver API errors early. Test and production stages share a local,
locked Go compiler cache; source modules remain uncached across rebuilds so
patch preimage checks still start from pristine bytes. The compiler cache is
not copied to the final image or published.

`go mod tidy` is intentionally excluded because it reaches unrelated upstream
test dependencies, including a missing `github.com/go-openapi/testify/v2/assert/yaml`
package. The full upstream test suite has not run and is not claimed as passing.

### Prometheus candidate and fail-closed patch

The prior `github.com/prometheus/prometheus` 0.311.3 candidate advanced the
OTel graph and broke the Amazon-forked receiver API. A subsequent 0.305.3
attempt, corresponding to Prometheus 3.5.3 LTS, used the version which the
[upstream GHSA-wg65-39gg-5wfj advisory](https://github.com/prometheus/prometheus/security/advisories/GHSA-wg65-39gg-5wfj)
lists as fixed. It retains the receiver's
`AppendHistogramCTZeroSample` storage interface, avoiding the later
`AppendHistogramSTZeroSample` mismatch. It passed production dependency
resolution and the hash-locked metadata patch, but it still failed compilation.

`patches/prometheusreceiver-metric-family.patch` is the Prometheus API patch. It
renames six observed `scrape.MetricMetadata` literals and three created-series
comparisons from `Metric` to `MetricFamily`; supplies an empty labels builder to
the changed `Target.DiscoveredLabels` API without shadowing the labels package;
and preserves the target allocator's classic-histogram behavior with a true
pointer required by Prometheus 0.305.3. Before applying it, the Dockerfile pins
the Amazon receiver pseudo-version, verifies all four affected source-file
hashes and the patch hash, runs a zero-fuzz dry run, applies it, and verifies
the exact replacements. Any changed fork content or patch causes the build to
fail.

`patches/targetallocator-tls-field.patch` separately updates the 18 production
`TLSSetting` field accesses to the OTel v0.128 `TLS` API. It preserves TLS
options and the fork's CA/certificate/key file watchers. Its manager preimage
is checked after the preceding Prometheus patch. GNU-patch positive and
altered-preimage checks passed; TLS runtime behavior still requires evidence.

The former patch form failed GNU `patch --dry-run` at the target-allocator hunk
before compiler execution. The regenerated patch is now validated in a
networkless linux/amd64 container derived from the verified builder, using GNU
patch 2.8: its checksum-bound fixture applies with `--batch --fuzz=0`, while a
deliberately changed transaction preimage is rejected. This validates patch
format and preconditions only. The subsequent full build passed patching and
version assertions, but readonly compilation found `configgrpc` 0.124 still
referencing `configauth.Authentication`, removed by the selected 0.128 module.
Build `mof9i29n804wl8gi1mh8bdezo` was intentionally interrupted after this error;
it produced no candidate image. Complete production-reachable core alignment
and compatibility with the Amazon forks remain unproven.

The Dockerfile checks in the complete official OTel Collector v0.128
[module-set map](https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector/v0.128.0/versions.yaml)
and verifies its SHA-256 before use. It derives the collector-core modules
reachable from the three production mains, emits their exact stable 1.34.0 or
beta 0.128.0 `go get` targets from that map, then rejects an unmapped or
wrong-version reachable core module before readonly compilation. It preserves
the Amazon receiver fork. The final module-map checks have passed in an actual
build; they do not establish fork API compatibility.

### Archived expand-converter compatibility module

`legacy-expandconverter.lock` separately pins the deprecated
`expandconverter` 0.113.0 module because it preserves existing customer
configuration semantics for bare `$VAR`, `${VAR}`, `${env:VAR}`, and the
double-escape path used for Prometheus regex backreferences. It is not part of
the official v0.128 module map and is not an SCA waiver. The Docker build
verifies the lock, module `go.mod`, and `expand.go` hashes before compilation,
and is configured to run an actual CWA `GetSettings` resolver-chain regression
for those cases before the production compile.
The module depends on an internal confmap API and remains an explicit upgrade
risk.

The latest local build (`obp0kzzr851spnw2jmi6tiqxx`) compiled the complete
Prometheus receiver and the Agent's Prometheus plugin, and passed the focused
JMX and legacy resolver regressions. The production Make stage then failed in
four OTel translator files: exporter authentication, optional OTLP protocols,
and target allocator TLS configuration still use older APIs. Make exited2.
No candidate image exists; the compiler cache was retained.

`patches/agent-prometheus-api.patch` adapts the Agent plugin's logging, labels
and TLS field access. Its checksum-bound GNU patch positive and tampered-input
checks passed, as did the actual production-mode plugin compile. This does not
establish complete runtime compatibility.

`dependency-evidence` exports the resolved module graph without running a full
compile. An actual export verified Prometheus0.305.3 and common0.65.0; use this
graph rather than inferring selected versions from an unrelated source tree.
The Make invocation explicitly supplies VERSION=1.300071.0 because shallow Git
history plus temporary regression files otherwise produces `-untracked` rather
than taking upstream's version-file fallback.

`patches/jmxreceiver-configoptional.patch` is a separate, hash-locked
compatibility candidate for that JMX failure. It follows the official v0.128
receiver pattern: initialize the optional gRPC configuration, retain the
existing JMX endpoint assignment, and leave HTTP absent/disabled. The Docker
path verifies the Amazon fork preimage and patch digest and runs GNU-patch
positive and altered-preimage-negative fixture checks before applying it. It
then runs a focused Go regression after core alignment. That test passed and
verifies optional-helper/default-config semantics: gRPC becomes present, retains
the configured endpoint, and leaves HTTP absent. It is not a full JMX receiver
runtime test, and the full candidate remains unbuilt.

No candidate image exists. A real production compile of the prior 0.311.3
candidate found concrete incompatibilities between that Prometheus version and
the Amazon-forked Prometheus receiver pinned by this Agent source:

- `scrape.MetricMetadata.Metric` was removed or changed;
- `storage.Appender` now requires `AppendHistogramSTZeroSample`;
- target allocator assignment now expects `*bool` rather than `bool`.

The same prior compile also showed OTel graph mismatches: `otlpreceiver` passes
`component.TelemetrySettings` where its internal telemetry package now expects
a distinct settings type, `internal/merge/confmap` treats
`otelconfmap.KeyDelimiter` as a constant, and `pipeline/xpipeline` references
the removed `globalsignal.MustNewSignal`. These are source/API compatibility
blockers, not scan waivers. A compatible, reviewed Amazon fork and aligned OTel
graph update, or a narrowly verified source patch, is required before another
candidate compile can succeed.

The 0.305.3 attempt confirmed a narrower but still incompatible mixed graph:
collector `component` and `confmap` selected 1.34.0, `pipeline` selected
0.128.0, while `xpipeline` and `service` remained 0.124.0. Compilation failed
because `xpipeline` references `globalsignal.MustNewSignal`; service telemetry
calls older `componentattribute` APIs; the Amazon receiver calls
`target.DiscoveredLabels()` without the newly required `*labels.Builder`; and
its target allocator assigns `bool` where `*bool` is now required. The build
was intentionally canceled after these compiler errors, rather than allowed to
consume resources draining known-failed work. No additional source patch is
approved beyond the separately described JMX and TLS-field compatibility patches.

A full local build may start only with at least 16 GiB host free space and must
be canceled before it reaches the mandatory 8 GiB floor. Several prior attempts
were canceled at that floor, and one stopped when Docker Desktop became
unavailable. Those are separate infrastructure constraints. No candidate smoke
test, Grype rescan, security admission, publication, or vulnerability PASS is
available.

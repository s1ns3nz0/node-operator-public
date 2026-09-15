# This is a local candidate only. It deliberately rebuilds every executable used
# by the container entrypoint, rather than overlaying one newly-built binary on
# the vendor image.
ARG GO_IMAGE=docker.io/library/golang@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS tools

RUN apt-get update \
    && apt-get install -y --no-install-recommends git make patch \
    && rm -rf /var/lib/apt/lists/*

FROM tools AS dependencies

ARG TARGETARCH
ARG SOURCE_COMMIT=7c48fecadbdb49314f123449fa2167361d307c10
# Bound compiler parallelism and Go heap growth during this local rebuild.
ENV GOMAXPROCS=2 GOMEMLIMIT=2GiB
WORKDIR /src

# Fetching the object by SHA and checking it out detached prevents a branch or
# tag movement from changing the candidate source.
RUN git init cloudwatch-agent \
    && git -C cloudwatch-agent remote add origin https://github.com/aws/amazon-cloudwatch-agent.git \
    && git -C cloudwatch-agent fetch --depth=1 origin ${SOURCE_COMMIT} \
    && git -C cloudwatch-agent checkout --detach FETCH_HEAD \
    && test "$(git -C cloudwatch-agent rev-parse HEAD)" = "${SOURCE_COMMIT}"

WORKDIR /src/cloudwatch-agent

# These patches are scoped to pinned Amazon receivers and Agent API consumers.
# Each application requires byte-for-byte matching reviewed source preimages.
COPY patches/prometheusreceiver-metric-family.patch /opt/cloudwatch-patches/prometheusreceiver-metric-family.patch
COPY patches/jmxreceiver-configoptional.patch /opt/cloudwatch-patches/jmxreceiver-configoptional.patch
COPY patches/targetallocator-tls-field.patch /opt/cloudwatch-patches/targetallocator-tls-field.patch
COPY patches/prometheus-new-api.patch /opt/cloudwatch-patches/prometheus-new-api.patch
COPY patches/agent-prometheus-api.patch /opt/cloudwatch-patches/agent-prometheus-api.patch
COPY otel-v0.128-module-sets.yaml /opt/cloudwatch-otel/versions.yaml
COPY scripts/otel-core-cohort.sh /opt/cloudwatch-scripts/otel-core-cohort.sh
COPY scripts/verify-legacy-expandconverter.sh /opt/cloudwatch-scripts/verify-legacy-expandconverter.sh
COPY legacy-expandconverter.lock /opt/cloudwatch-legacy/expandconverter.lock
COPY tests/legacy_expandconverter_resolver_test.go /opt/cloudwatch-tests/legacy_expandconverter_resolver_test.go
COPY tests/verify-jmxreceiver-configoptional-patch.sh /opt/cloudwatch-tests/verify-jmxreceiver-configoptional-patch.sh
COPY tests/jmxreceiver_configoptional_behavior_test.go /opt/cloudwatch-tests/jmxreceiver_configoptional_behavior_test.go

# Retain the upstream version file, and pass VERSION explicitly to Make below:
# a shallow clone with fixture files can produce a nonempty -untracked value
# that bypasses upstream's version-file fallback.
RUN printf '%s\n' '1.300071.0' > CWAGENT_VERSION

RUN test "$(sha256sum plugins/inputs/prometheus/target_allocator.go | awk '{print $1}')" = "a66d2613eb6cd171e1bfa6d90acc665a31e236258fd19ac772491f051344f3a5" \
    && test "$(sha256sum plugins/inputs/prometheus/metrics_receiver.go | awk '{print $1}')" = "bdea2a14351f7717c9dc9afcf1bfce08dcbc23a12c64246f2668272be6bb1856" \
    && test "$(sha256sum plugins/inputs/prometheus/metrics_type_handler.go | awk '{print $1}')" = "380adb6b4578c1b69895317ba3cb14cbb6c47c203aba1d4de2e68411dc8d7482" \
    && test "$(sha256sum plugins/inputs/prometheus/start.go | awk '{print $1}')" = "cb47b97775443d030c02d39e66664325f2d2c76b3c3051d6e4e16adbec8f173c" \
    && test "$(sha256sum /opt/cloudwatch-patches/agent-prometheus-api.patch | awk '{print $1}')" = "391df71072d838d66c77447bd4ecca4b667e52dbf625e1653d533411169f2592" \
    && patch --dry-run --batch --fuzz=0 -p1 < /opt/cloudwatch-patches/agent-prometheus-api.patch \
    && patch --batch --fuzz=0 -p1 < /opt/cloudwatch-patches/agent-prometheus-api.patch

# The scanner's exact x/net and x/text candidates conflict with x/crypto 0.56.0.
# Go's module solver selects the minimum compatible fixed versions (0.57.0 and
# 0.41.0); source-lock.json records that evidence and all requested targets.
RUN GOTOOLCHAIN=local go get \
      golang.org/x/crypto@v0.56.0 \
      golang.org/x/net@v0.57.0 \
      golang.org/x/text@v0.41.0 \
      google.golang.org/grpc@v1.83.1 \
      github.com/prometheus/prometheus@v0.305.3 \
      github.com/apache/thrift@v0.24.0 \
      github.com/klauspost/compress@v1.18.7 \
      go.opentelemetry.io/collector/config/configoptional@v0.128.0 \
    && test "$(sha256sum /opt/cloudwatch-legacy/expandconverter.lock | awk '{print $1}')" = "19681f3395929434cc5eea397f1bf73089cdd33c4f2be257b702735895549772" \
    && GOTOOLCHAIN=local go mod download go.opentelemetry.io/collector/confmap/converter/expandconverter@v0.113.0 \
    && legacy_module_dir="$(go env GOMODCACHE)/go.opentelemetry.io/collector/confmap/converter/expandconverter@v0.113.0" \
    && sh /opt/cloudwatch-scripts/verify-legacy-expandconverter.sh /opt/cloudwatch-legacy/expandconverter.lock 19681f3395929434cc5eea397f1bf73089cdd33c4f2be257b702735895549772 "$legacy_module_dir" \
    && GOTOOLCHAIN=local go mod download github.com/amazon-contributing/opentelemetry-collector-contrib/receiver/prometheusreceiver@v0.0.0-20260717191209-ee093fbfffbd \
    && module_dir="$(go env GOMODCACHE)/github.com/amazon-contributing/opentelemetry-collector-contrib/receiver/prometheusreceiver@v0.0.0-20260717191209-ee093fbfffbd" \
    && test -d "$module_dir" \
    && test "$(sha256sum "$module_dir/internal/metadata.go" | awk '{print $1}')" = "23f4e8697f83ecefc3d3aae33fc05a0617d16d3373155ffbefcecf9e5ec9e327" \
    && test "$(sha256sum "$module_dir/internal/metricfamily.go" | awk '{print $1}')" = "f65be0b69ee4ff5c9294d417b8634510c7ccee3bb473d666294e4eeedcd608fb" \
    && test "$(sha256sum "$module_dir/internal/transaction.go" | awk '{print $1}')" = "5f456ee16b91e756610dbdd604ac30c21c73a8ef31abea379b812dca3df6168a" \
    && test "$(sha256sum "$module_dir/targetallocator/manager.go" | awk '{print $1}')" = "fd745739940e3cf456840e390c3a4bf1fbb1fe0d2560c8f95e26826e29e2bf11" \
    && test "$(sha256sum /opt/cloudwatch-patches/prometheusreceiver-metric-family.patch | awk '{print $1}')" = "c3b8f473b146cd5b7044fdc45c9bbc484c4ad068be9513fdfd62b6bb923561d5" \
    && patch --dry-run --batch --fuzz=0 -d "$module_dir" -p1 < /opt/cloudwatch-patches/prometheusreceiver-metric-family.patch \
    && patch --batch --fuzz=0 -d "$module_dir" -p1 < /opt/cloudwatch-patches/prometheusreceiver-metric-family.patch \
    && test "$(sha256sum "$module_dir/targetallocator/config.go" | awk '{print $1}')" = "2e0fc072d27e07d94d515b0bb24a7254705b9e15857ae77492238f0545429731" \
    && test "$(sha256sum "$module_dir/targetallocator/manager.go" | awk '{print $1}')" = "1cdebdd672a05532b7595576092825202a97fda651b5d43e0f67f9115877fe5e" \
    && test "$(sha256sum /opt/cloudwatch-patches/targetallocator-tls-field.patch | awk '{print $1}')" = "1a9a9b67eafc139031f08512255cc7cba413d7138ec2a40d53734d81292a85b8" \
    && patch --dry-run --batch --fuzz=0 -d "$module_dir" -p1 < /opt/cloudwatch-patches/targetallocator-tls-field.patch \
    && patch --batch --fuzz=0 -d "$module_dir" -p1 < /opt/cloudwatch-patches/targetallocator-tls-field.patch \
    && test "$(sha256sum "$module_dir/metrics_receiver.go" | awk '{print $1}')" = "0300f81650a05684ff378d81d15668c394d43fd14dcb784d7a308e4809f8ea82" \
    && test "$(sha256sum /opt/cloudwatch-patches/prometheus-new-api.patch | awk '{print $1}')" = "87e993a6869906cb14ef642f9f46f3b26c9f7ee99a342bb7b60a3b19b5e35a2d" \
    && patch --dry-run --batch --fuzz=0 -d "$module_dir" -p1 < /opt/cloudwatch-patches/prometheus-new-api.patch \
    && patch --batch --fuzz=0 -d "$module_dir" -p1 < /opt/cloudwatch-patches/prometheus-new-api.patch \
    && test "$(grep -c 'Metric:' "$module_dir/internal/metadata.go")" -eq 0 \
    && test "$(grep -c 'MetricFamily:' "$module_dir/internal/metadata.go")" -eq 6 \
    && test "$(grep -c 'metadata.Metric+metricSuffixCreated' "$module_dir/internal/metricfamily.go")" -eq 0 \
    && test "$(grep -c 'metadata.MetricFamily+metricSuffixCreated' "$module_dir/internal/metricfamily.go")" -eq 3 \
    && test "$(grep -c 'target.DiscoveredLabels()' "$module_dir/internal/transaction.go")" -eq 0 \
    && test "$(grep -c 'target.DiscoveredLabels(labels.NewBuilder(labels.EmptyLabels()))' "$module_dir/internal/transaction.go")" -eq 1 \
    && grep -F 'func (t *transaction) initTransaction(seriesLabels labels.Labels)' "$module_dir/internal/transaction.go" \
    && grep -F 'rKey, err := t.getJobAndInstance(seriesLabels)' "$module_dir/internal/transaction.go" \
    && test "$(grep -c 'AlwaysScrapeClassicHistograms = true' "$module_dir/targetallocator/manager.go")" -eq 0 \
    && test "$(grep -c 'AlwaysScrapeClassicHistograms = &alwaysScrapeClassicHistograms' "$module_dir/targetallocator/manager.go")" -eq 1 \
    && GOTOOLCHAIN=local go mod download github.com/amazon-contributing/opentelemetry-collector-contrib/receiver/jmxreceiver@v0.0.0-20260717191209-ee093fbfffbd \
    && jmx_module_dir="$(go env GOMODCACHE)/github.com/amazon-contributing/opentelemetry-collector-contrib/receiver/jmxreceiver@v0.0.0-20260717191209-ee093fbfffbd" \
    && test -d "$jmx_module_dir" \
    && test "$(sha256sum "$jmx_module_dir/receiver.go" | awk '{print $1}')" = "9737f7f30b1fd0e3fa003ba8cdf68f39352932d1323641e38998360b25bc5ebe" \
    && test "$(sha256sum /opt/cloudwatch-patches/jmxreceiver-configoptional.patch | awk '{print $1}')" = "093728a3d68de9f20d6bb7e21c5366548391abaa74e4f023b01e7d3297ea914f" \
    && sh /opt/cloudwatch-tests/verify-jmxreceiver-configoptional-patch.sh "$jmx_module_dir/receiver.go" /opt/cloudwatch-patches/jmxreceiver-configoptional.patch \
    && patch --dry-run --batch --fuzz=0 -d "$jmx_module_dir" -p1 < /opt/cloudwatch-patches/jmxreceiver-configoptional.patch \
    && patch --batch --fuzz=0 -d "$jmx_module_dir" -p1 < /opt/cloudwatch-patches/jmxreceiver-configoptional.patch \
    && grep -F 'if err := insertDefault(&config.GRPC); err != nil {' "$jmx_module_dir/receiver.go" \
    && grep -F 'config.GRPC.Get().NetAddr = confignet.AddrConfig{Endpoint: endpoint, Transport: confignet.TransportTypeTCP}' "$jmx_module_dir/receiver.go" \
    && ! grep -F 'config.HTTP = nil' "$jmx_module_dir/receiver.go" \
    && cp /opt/cloudwatch-tests/jmxreceiver_configoptional_behavior_test.go "$jmx_module_dir/configoptional_compatibility_test.go" \
    && GOTOOLCHAIN=local GOFLAGS=-mod=mod go list -deps -f '{{with .Module}}{{.Path}} {{.Version}}{{end}}' \
      github.com/aws/amazon-cloudwatch-agent/cmd/amazon-cloudwatch-agent \
      github.com/aws/amazon-cloudwatch-agent/cmd/start-amazon-cloudwatch-agent \
      github.com/aws/amazon-cloudwatch-agent/cmd/config-translator > /production-modules-before-cohort.raw \
    && awk 'NF == 2' /production-modules-before-cohort.raw | LC_ALL=C sort -u > /production-core-before-cohort.txt \
    && test "$(sha256sum /opt/cloudwatch-otel/versions.yaml | awk '{print $1}')" = "8a132206547abb244d1781f625cc337971b5e87e1871c0f0bcee82c8ba05b1fb" \
    && sh /opt/cloudwatch-scripts/otel-core-cohort.sh emit /opt/cloudwatch-otel/versions.yaml 8a132206547abb244d1781f625cc337971b5e87e1871c0f0bcee82c8ba05b1fb /opt/cloudwatch-legacy/expandconverter.lock 19681f3395929434cc5eea397f1bf73089cdd33c4f2be257b702735895549772 /production-core-before-cohort.txt > /otel-core-go-get.txt \
    && set -- $(cat /otel-core-go-get.txt) \
    && test "$#" -gt 0 \
    && GOTOOLCHAIN=local go get "$@" \
    && GOTOOLCHAIN=local GOFLAGS=-mod=mod go list -deps -f '{{with .Module}}{{.Path}} {{.Version}}{{end}}' \
      github.com/aws/amazon-cloudwatch-agent/cmd/amazon-cloudwatch-agent \
      github.com/aws/amazon-cloudwatch-agent/cmd/start-amazon-cloudwatch-agent \
      github.com/aws/amazon-cloudwatch-agent/cmd/config-translator > /production-modules-after-cohort.raw \
    && awk 'NF == 2' /production-modules-after-cohort.raw | LC_ALL=C sort -u > /production-core-modules.txt \
    && sh /opt/cloudwatch-scripts/otel-core-cohort.sh verify /opt/cloudwatch-otel/versions.yaml 8a132206547abb244d1781f625cc337971b5e87e1871c0f0bcee82c8ba05b1fb /opt/cloudwatch-legacy/expandconverter.lock 19681f3395929434cc5eea397f1bf73089cdd33c4f2be257b702735895549772 /production-core-modules.txt \
    && GOTOOLCHAIN=local go list -m all > /resolved-modules.txt \
    && cp go.mod /resolved-go.mod \
    && cp go.sum /resolved-go.sum \
    && grep -Fx 'golang.org/x/crypto v0.56.0' /resolved-modules.txt \
    && grep -Fx 'golang.org/x/net v0.57.0' /resolved-modules.txt \
    && grep -Fx 'golang.org/x/text v0.41.0' /resolved-modules.txt \
    && grep -Fx 'google.golang.org/grpc v1.83.1' /resolved-modules.txt \
    && grep -Fx 'github.com/prometheus/prometheus v0.305.3' /resolved-modules.txt \
    && grep -Fx 'github.com/apache/thrift v0.24.0' /resolved-modules.txt \
    && grep -Fx 'github.com/klauspost/compress v1.18.7' /resolved-modules.txt \
    && legacy_module_dir="$(go env GOMODCACHE)/go.opentelemetry.io/collector/confmap/converter/expandconverter@v0.113.0" \
    && sh /opt/cloudwatch-scripts/verify-legacy-expandconverter.sh /opt/cloudwatch-legacy/expandconverter.lock 19681f3395929434cc5eea397f1bf73089cdd33c4f2be257b702735895549772 "$legacy_module_dir"

# Export the resolved graph independently of compilation for diagnosis and SCA.
FROM scratch AS dependency-evidence
COPY --from=dependencies /resolved-go.mod /go.mod
COPY --from=dependencies /resolved-go.sum /go.sum
COPY --from=dependencies /resolved-modules.txt /modules.txt
COPY --from=dependencies /production-core-modules.txt /production-modules.txt

FROM dependencies AS builder
ARG TARGETARCH
COPY patches/agent-otel-translators.patch /opt/cloudwatch-patches/agent-otel-translators.patch
# These imports already belong to the locked production graph. Apply after
# dependency resolution so API-only corrections do not redownload the graph.
RUN test "$(sha256sum translator/translate/otel/exporter/otlphttp/translator.go | awk '{print $1}')" = "f9ebe6105d57b83c8861f32d276d6de9d3b1001d98710c9ceb139b28f5c7a67f" \
    && test "$(sha256sum translator/translate/otel/exporter/prometheusremotewrite/translator.go | awk '{print $1}')" = "07020b847fc14fca3120440e08553a8bb273ab35d94452233182101d8e548662" \
    && test "$(sha256sum translator/translate/otel/receiver/otlp/translator.go | awk '{print $1}')" = "14844f5c0be24ba58ba9619cb94242e1e8e11d3d660c8583462c733be1c6363f" \
    && test "$(sha256sum translator/translate/otel/receiver/prometheus/translator.go | awk '{print $1}')" = "0716816ef98fe82522990414c9b5dc4d9d496b5fe108b0f202c1b7d96b38eb8d" \
    && test "$(sha256sum /opt/cloudwatch-patches/agent-otel-translators.patch | awk '{print $1}')" = "d7a5022563217e495d4be1b56c4eca9fe6a9652e00531413c9a575813619549b" \
    && patch --dry-run --batch --fuzz=0 -p1 < /opt/cloudwatch-patches/agent-otel-translators.patch \
    && patch --batch --fuzz=0 -p1 < /opt/cloudwatch-patches/agent-otel-translators.patch
# This uses the Agent's GetSettings resolver chain, not a string-substitution
# fixture. It protects the documented legacy compatibility behavior before the
# three production binaries compile.
# Retain only the compiler cache across local retries. Do not persist the
# patched module directory: every build must recheck pristine source hashes.
RUN --mount=type=cache,id=node-operator-cwa-go1271-amd64,target=/root/.cache/go-build,sharing=locked \
    cp /opt/cloudwatch-tests/legacy_expandconverter_resolver_test.go service/configprovider/legacy_expandconverter_resolver_test.go \
    && GOTOOLCHAIN=local GOFLAGS=-mod=readonly go build github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver \
    && GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS='-mod=readonly -trimpath' go build ./plugins/inputs/prometheus \
    && GOTOOLCHAIN=local GOFLAGS=-mod=readonly go test github.com/open-telemetry/opentelemetry-collector-contrib/receiver/jmxreceiver -run '^TestConfigOptionalGRPCPreservesJMXEndpointAndDisablesHTTP$' -count=1 \
    && GOFLAGS=-mod=readonly go test ./service/configprovider -run '^TestLegacyExpandConverterResolver$' -count=1

# Upstream's Make target builds precisely these three Linux executables: agent,
# entrypoint wrapper, and configuration translator. The upstream Makefile does
# not set GOFLAGS, so readonly mode is explicit here: compilation may not alter
# the graph already captured above.
RUN --mount=type=cache,id=node-operator-cwa-go1271-amd64,target=/root/.cache/go-build,sharing=locked \
    GOFLAGS=-mod=readonly make NPROCS=2 VERSION=1.300071.0 build-for-docker-${TARGETARCH}

FROM scratch
ARG TARGETARCH
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /src/cloudwatch-agent/build/bin/linux_${TARGETARCH}/ /opt/aws/amazon-cloudwatch-agent/bin/
COPY --from=builder /src/cloudwatch-agent/CWAGENT_VERSION /opt/aws/amazon-cloudwatch-agent/bin/CWAGENT_VERSION
COPY --from=builder /resolved-go.mod /opt/aws/amazon-cloudwatch-agent/build-metadata/resolved-go.mod
COPY --from=builder /resolved-go.sum /opt/aws/amazon-cloudwatch-agent/build-metadata/resolved-go.sum
COPY --from=builder /resolved-modules.txt /opt/aws/amazon-cloudwatch-agent/build-metadata/resolved-modules.txt
COPY --from=builder /production-core-modules.txt /opt/aws/amazon-cloudwatch-agent/build-metadata/production-core-modules.txt
ENV RUN_IN_CONTAINER=True
ENTRYPOINT ["/opt/aws/amazon-cloudwatch-agent/bin/start-amazon-cloudwatch-agent"]

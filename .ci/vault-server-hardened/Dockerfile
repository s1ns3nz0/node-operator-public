FROM golang@sha256:1a9c10cf505a9e6b1e96ea77ebdbfe79a0f10380181faf88bc3b51d7e4315fae AS build
WORKDIR /src
RUN test "$(go version)" = 'go version go1.26.6 linux/amd64' && \
    wget -q -O /tmp/vault.tar.gz https://github.com/hashicorp/vault/archive/cb6a54face072e372480d7cc2e64a3110b84756f.tar.gz && \
    echo '1e5cca418c6bc51c2a73d8fc056c2022f64dbbf806eb049e0d88651aa550daa7  /tmp/vault.tar.gz' | sha256sum -c - && \
    tar -xzf /tmp/vault.tar.gz --strip-components=1 && test "$(cat version/VERSION)" = 2.1.0
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOOS=linux GOARCH=amd64
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    go mod edit -require=golang.org/x/crypto@v0.56.0 -require=github.com/apache/thrift@v0.24.0 -require=google.golang.org/grpc@v1.83.2 && \
    go mod download golang.org/x/crypto@v0.56.0 github.com/apache/thrift@v0.24.0 google.golang.org/grpc@v1.83.2 && \
    echo '0377034eba756738494bdc0c0f1ff0fef524846398a5f96aa977049331c5d6b2  go.mod' | sha256sum -c - && \
    echo '3f06f5ebaed07dc186567fa3a48f0d310e505b090c386ddad77a76ceba72d303  go.sum' | sha256sum -c - && \
    go mod verify && \
    go test -mod=readonly -p 2 -count=1 -timeout=10m ./command -run '^(TestOperatorGenerateRootCommand_Run|TestOperatorRaftSnapshotInspect.*)$' && \
    go build -mod=readonly -p 2 -trimpath -buildvcs=false \
      -ldflags='-s -w -X github.com/hashicorp/vault/version.GitCommit=cb6a54face072e372480d7cc2e64a3110b84756f -X github.com/hashicorp/vault/version.BuildDate=2026-08-31T19:29:27Z' \
      -o /out/vault . && \
    go version -m /out/vault > /out/buildinfo.txt && \
    go list -mod=readonly -deps . > /out/dependencies.txt && \
    go list -mod=readonly -m -json all > /out/modules.json && cp go.mod go.sum /out/

FROM alpine@sha256:79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f
RUN apk add --no-cache ca-certificates && apk upgrade --no-cache libcrypto3 libssl3 && \
    mkdir -p /home/vault /vault/config /vault/file /vault/logs && chown -R 100:1000 /home/vault /vault
LABEL org.opencontainers.image.source="https://github.com/hashicorp/vault" \
      org.opencontainers.image.revision="cb6a54face072e372480d7cc2e64a3110b84756f" \
      org.opencontainers.image.version="2.1.0-hardened"
COPY --from=build --chown=0:0 --chmod=0555 /out/vault /bin/vault
COPY --from=build /out/buildinfo.txt /out/dependencies.txt /out/modules.json /out/go.mod /out/go.sum /usr/share/vault/
COPY --from=build /src/LICENSE /usr/share/vault/LICENSE
ENV HOME=/home/vault
USER 100:1000
ENTRYPOINT ["/bin/vault"]

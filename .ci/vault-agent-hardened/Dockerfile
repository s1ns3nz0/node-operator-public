FROM golang@sha256:1a9c10cf505a9e6b1e96ea77ebdbfe79a0f10380181faf88bc3b51d7e4315fae AS build

WORKDIR /src

RUN test "$(go version)" = 'go version go1.26.6 linux/amd64' \
    && wget -q -O /tmp/vault.tar.gz \
      "https://github.com/hashicorp/vault/archive/cb6a54face072e372480d7cc2e64a3110b84756f.tar.gz" \
    && printf '%s  %s\n' 1e5cca418c6bc51c2a73d8fc056c2022f64dbbf806eb049e0d88651aa550daa7 /tmp/vault.tar.gz \
      | sha256sum -c -s \
    && tar -xzf /tmp/vault.tar.gz --strip-components=1 \
    && test "$(cat version/VERSION)" = 2.1.0

COPY agent-main.go /src/agent-main.go

RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    go mod edit \
      -require=golang.org/x/crypto@v0.56.0 \
      -require=github.com/apache/thrift@v0.24.0 \
      -require=google.golang.org/grpc@v1.83.2 \
    && go mod download \
      golang.org/x/crypto@v0.56.0 \
      github.com/apache/thrift@v0.24.0 \
      google.golang.org/grpc@v1.83.2 \
    && printf '%s  %s\n' \
      0377034eba756738494bdc0c0f1ff0fef524846398a5f96aa977049331c5d6b2 go.mod \
      3f06f5ebaed07dc186567fa3a48f0d310e505b090c386ddad77a76ceba72d303 go.sum \
      | sha256sum -c -s \
    && test "$(go list -m -f '{{.Version}}' golang.org/x/crypto)" = v0.56.0 \
    && test "$(go list -m -f '{{.Version}}' github.com/apache/thrift)" = v0.24.0 \
    && go mod verify \
    && CGO_ENABLED=0 GOTOOLCHAIN=local \
      go test -count=1 ./command/agent/... \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local \
      go build -buildvcs=false -mod=readonly -trimpath -tags=minimal \
      -ldflags="-s -w -buildid= \
        -X github.com/hashicorp/vault/version.GitCommit=cb6a54face072e372480d7cc2e64a3110b84756f \
        -X github.com/hashicorp/vault/version.BuildDate=2026-08-31T19:29:27Z" \
      -o /out/vault ./agent-main.go \
    && test "$(go version -m /out/vault | awk '$1 == "build" && $2 == "CGO_ENABLED=0" {print $2}')" = CGO_ENABLED=0

# Optional evidence export only. The normal runtime target and its binary are
# unchanged. Bind this closure to a frozen runtime by comparing binary hashes.
FROM build AS dependency-evidence-build
RUN --network=none --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    mkdir /evidence \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local GOPROXY=off \
      go list -mod=readonly -tags=minimal -deps ./agent-main.go > /evidence/dependencies.txt \
    && test "$(wc -l < /evidence/dependencies.txt)" -gt 100 \
    && ! grep -Eq '^golang.org/x/crypto/openpgp(/|$)' /evidence/dependencies.txt \
    && go version -m /out/vault > /evidence/buildinfo.txt \
    && sha256sum /out/vault > /evidence/binary.sha256 \
    && cp go.mod go.sum agent-main.go /evidence/

FROM scratch AS dependency-evidence
COPY --from=dependency-evidence-build /evidence/ /

FROM golang@sha256:1a9c10cf505a9e6b1e96ea77ebdbfe79a0f10380181faf88bc3b51d7e4315fae AS mock-build
WORKDIR /src
COPY test-mock-vault.go /src/test-mock-vault.go
RUN test "$(go version)" = 'go version go1.26.6 linux/amd64' \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local \
      go build -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
      -o /out/mock-vault ./test-mock-vault.go

FROM alpine@sha256:79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f AS mock-vault
COPY --from=mock-build --chown=0:0 --chmod=0555 /out/mock-vault /mock-vault
USER 100:1000
ENTRYPOINT ["/mock-vault"]

FROM alpine@sha256:79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f

# Keep the APK database so scanners can identify every installed package.
RUN apk add --no-cache \
      ca-certificates=20260611-r0 \
      libcrypto3=3.5.8-r0 \
      libssl3=3.5.8-r0 \
    && addgroup -g 1000 -S vault \
    && adduser -u 100 -S -D -h /home/vault -G vault vault \
    && install -d -o 100 -g 1000 -m 0750 \
      /home/vault /vault /vault/config /vault/file /vault/logs \
    && test "$(id -u vault)" = 100 \
    && test "$(id -g vault)" = 1000 \
    && test "$(apk info -e libcrypto3)" = libcrypto3 \
    && test "$(apk info -e libssl3)" = libssl3

COPY --from=build --chown=0:0 --chmod=0555 /out/vault /usr/local/bin/vault

ENV HOME=/home/vault \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

LABEL org.opencontainers.image.source="https://github.com/hashicorp/vault" \
      org.opencontainers.image.version="2.1.0-agent-only" \
      org.opencontainers.image.revision="cb6a54face072e372480d7cc2e64a3110b84756f" \
      io.node-operator.vault-agent-only="true"

USER 100:1000
ENTRYPOINT ["vault"]
CMD ["agent", "-help"]

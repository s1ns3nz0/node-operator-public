FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
RUN apk add --no-cache git build-base linux-headers
ENV CGO_ENABLED=1 GOTOOLCHAIN=local CGO_CFLAGS="-O2 -D__BLST_PORTABLE__"
WORKDIR /src
RUN git init . && git remote add origin https://github.com/OffchainLabs/prysm.git && \
    git fetch --depth=1 origin 51b5a75ebbadf05af22bd2601b5baf7a9e99b66d && \
    git checkout --detach FETCH_HEAD && \
    test "$(git rev-parse HEAD)" = 51b5a75ebbadf05af22bd2601b5baf7a9e99b66d
COPY .ci/prysm-mtls/patches/0001-web3signer-http-mtls.patch /tmp/mtls.patch
RUN echo '05fd3fa777abc99d5f0f66c192dfcca64922f1f1b0b2c35aa337dcb0c60970be  /tmp/mtls.patch' | sha256sum -c - && \
    git apply --check /tmp/mtls.patch && git apply /tmp/mtls.patch && git diff --check
COPY .ci/prysm-mtls/patches/0002-security-dependencies.patch /tmp/security.patch
RUN echo 'ff4f2db3b57b8d5d2756bfdf03e4d16ee12b62f218beb12a56e6c60f342a4b91  /tmp/security.patch' | sha256sum -c - && \
    git apply --check /tmp/security.patch && git apply /tmp/security.patch && git diff --check
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go mod download && go mod verify && \
    go test -mod=readonly -count=1 ./cmd/beacon-chain/flags ./cmd/beacon-chain/jwt ./beacon-chain/core/blocks && \
    go build -mod=readonly -trimpath -buildvcs=false -ldflags='-X github.com/OffchainLabs/prysm/v7/runtime/version.gitCommit=51b5a75ebbadf05af22bd2601b5baf7a9e99b66d -X github.com/OffchainLabs/prysm/v7/runtime/version.gitTag=v7.1.8 -X github.com/OffchainLabs/prysm/v7/runtime/version.buildDate=2026-07-23T16:30:54+00:00 -X github.com/OffchainLabs/prysm/v7/runtime/version.buildDateUnix=1784825754' -o /out/beacon-chain ./cmd/beacon-chain && \
    go list -mod=readonly -deps ./cmd/beacon-chain > /out/beacon-chain-dependencies.txt && \
    go list -mod=readonly -m -json all > /out/beacon-chain-go-modules.json && \
    go version -m /out/beacon-chain > /out/beacon-chain-buildinfo.txt
RUN if grep -Eq '^golang.org/x/crypto/openpgp(/|$)' /out/beacon-chain-dependencies.txt; then \
      echo 'FAIL: unmaintained OpenPGP package is a beacon dependency' >&2; exit 1; \
    fi && echo 'PASS: GO-2026-5932 affected OpenPGP packages absent from beacon dependencies'

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
RUN apk upgrade --no-cache libcrypto3 libssl3 && apk add --no-cache libstdc++ ca-certificates
LABEL org.opencontainers.image.source="https://github.com/OffchainLabs/prysm" \
      org.opencontainers.image.revision="51b5a75ebbadf05af22bd2601b5baf7a9e99b66d" \
      io.node-operator.prysm-security-patch-sha256="ff4f2db3b57b8d5d2756bfdf03e4d16ee12b62f218beb12a56e6c60f342a4b91"
COPY --from=build /out/beacon-chain /beacon-chain
COPY --from=build /out/beacon-chain-dependencies.txt /usr/share/beacon-chain-dependencies.txt
COPY --from=build /out/beacon-chain-go-modules.json /usr/share/beacon-chain-go-modules.json
COPY --from=build /out/beacon-chain-buildinfo.txt /usr/share/beacon-chain-buildinfo.txt
USER 1000:1000
ENTRYPOINT ["/beacon-chain"]

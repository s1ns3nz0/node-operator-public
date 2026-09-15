FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
RUN apk add --no-cache git build-base linux-headers
ENV CGO_ENABLED=1
ENV GOTOOLCHAIN=local
# BLST's documented portable build avoids CPU-specific SIGILL under emulation
# and on deployment hosts with a different instruction set baseline.
ENV CGO_CFLAGS="-O2 -D__BLST_PORTABLE__"
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
    go test -mod=readonly ./validator/keymanager/remote-web3signer/internal && \
    go test -mod=readonly ./validator/keymanager/remote-web3signer && \
    go test -mod=readonly ./validator/node -run TestWeb3SignerConfig -count=1 && \
    go build -mod=readonly -trimpath -buildvcs=false -o /out/validator ./cmd/validator
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go list -mod=readonly -deps ./cmd/validator > /out/validator-dependencies.txt && \
    if grep -Eq '^golang.org/x/crypto/openpgp(/|$)' /out/validator-dependencies.txt; then \
      echo 'FAIL: unmaintained OpenPGP package is a validator dependency' >&2; exit 1; \
    fi && echo 'PASS: GO-2026-5932 affected OpenPGP packages absent from validator dependencies'

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
RUN apk upgrade --no-cache libcrypto3 libssl3 && \
    apk add --no-cache libstdc++ ca-certificates
LABEL org.opencontainers.image.source="https://github.com/OffchainLabs/prysm" \
      org.opencontainers.image.revision="51b5a75ebbadf05af22bd2601b5baf7a9e99b66d" \
      io.node-operator.prysm-mtls-patch-sha256="05fd3fa777abc99d5f0f66c192dfcca64922f1f1b0b2c35aa337dcb0c60970be" \
      io.node-operator.prysm-security-patch-sha256="ff4f2db3b57b8d5d2756bfdf03e4d16ee12b62f218beb12a56e6c60f342a4b91"
COPY --from=build /out/validator /validator
COPY --from=build /out/validator-dependencies.txt /usr/share/validator-dependencies.txt
USER 1000:1000
ENTRYPOINT ["/validator"]

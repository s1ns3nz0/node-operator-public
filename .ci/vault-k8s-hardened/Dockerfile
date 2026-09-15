FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
RUN apk add --no-cache git
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOOS=linux GOARCH=amd64
WORKDIR /src
RUN git init . && git remote add origin https://github.com/hashicorp/vault-k8s.git && \
    git fetch --depth=1 origin fbc5b1f0cd4d1c7dd5a8830e32c8ed636d7318d7 && \
    git checkout --detach FETCH_HEAD && \
    test "$(git rev-parse HEAD)" = fbc5b1f0cd4d1c7dd5a8830e32c8ed636d7318d7
RUN apk add --no-cache openssl
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go mod edit -require=golang.org/x/crypto@v0.56.0 && \
    go mod tidy && go mod download && go mod verify && \
    go test -mod=readonly -count=1 ./... && \
    go build -mod=readonly -trimpath -buildvcs=false \
      -ldflags='-X github.com/hashicorp/vault-k8s/version.Version=v1.7.6' -o /out/vault-k8s . && \
    go list -mod=readonly -deps . > /out/dependencies.txt && \
    go list -mod=readonly -m -json all > /out/modules.json && \
    go version -m /out/vault-k8s > /out/buildinfo.txt && \
    cp go.mod go.sum /out/ && git diff -- go.mod go.sum > /out/dependency.patch
RUN echo '523d4663f46016c0913a5965b5b3c73a3e5778ca3361bcdd3dfe889f299ef860  /out/go.mod' | sha256sum -c - && \
    echo 'db40b881228158570efbbde9e291d1a45c4abf2c0fc970d036d3f5d7bcd566e4  /out/go.sum' | sha256sum -c - && \
    if grep -Eq '^golang.org/x/crypto/openpgp(/|$)' /out/dependencies.txt; then \
      echo 'FAIL: affected unmaintained OpenPGP package entered injector dependencies' >&2; exit 1; \
    fi

FROM alpine@sha256:79ff19e9084a00eece421b2523fb93e22d730e2c0e525905de047e848e56d95f
RUN apk add --no-cache ca-certificates && apk upgrade --no-cache libcrypto3 libssl3
LABEL org.opencontainers.image.source="https://github.com/hashicorp/vault-k8s" \
      org.opencontainers.image.revision="fbc5b1f0cd4d1c7dd5a8830e32c8ed636d7318d7" \
      org.opencontainers.image.version="1.7.6-hardened"
COPY --from=build --chown=0:0 --chmod=0555 /out/vault-k8s /bin/vault-k8s
COPY --from=build /out/dependencies.txt /out/modules.json /out/buildinfo.txt /out/go.mod /out/go.sum /out/dependency.patch /usr/share/vault-k8s/
COPY --from=build /src/LICENSE /usr/share/vault-k8s/LICENSE
USER 1000:1000
ENTRYPOINT ["/bin/vault-k8s"]

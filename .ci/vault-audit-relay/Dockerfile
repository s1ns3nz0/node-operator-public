FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build

ARG RELAY_INPUT_SHA
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64
WORKDIR /src
COPY go.mod ./
COPY cmd/vault-audit-relay/ ./cmd/vault-audit-relay/
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go test ./cmd/vault-audit-relay
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build -trimpath -buildvcs=false -ldflags='-s -w' -o /out/vault-audit-relay ./cmd/vault-audit-relay

FROM scratch
ARG RELAY_INPUT_SHA
LABEL io.node-operator.vault-audit-relay-input-sha="${RELAY_INPUT_SHA}"
COPY --from=build /out/vault-audit-relay /vault-audit-relay
USER 100:1000
ENTRYPOINT ["/vault-audit-relay"]

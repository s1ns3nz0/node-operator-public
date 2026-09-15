FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
ARG FENCE_INPUT_SHA
WORKDIR /src
COPY go.mod ./
COPY cmd/validator-signing-fence/main.go ./cmd/validator-signing-fence/main.go
COPY cmd/validator-signing-fence/main_test.go ./cmd/validator-signing-fence/main_test.go
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go test ./cmd/validator-signing-fence && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags='-s -w' -o /out/validator-signing-fence ./cmd/validator-signing-fence

FROM scratch
ARG FENCE_INPUT_SHA
LABEL io.node-operator.validator-signing-fence-input-sha="${FENCE_INPUT_SHA}"
COPY --from=build /out/validator-signing-fence /validator-signing-fence
USER 65532:65532
ENTRYPOINT ["/validator-signing-fence"]

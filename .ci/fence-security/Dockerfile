# Same reviewed Go builder base as the fence release build. The runtime image is
# a test fixture only: it contains no kubeconfig, cloud credentials, or socket.
FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd/validator-signing-fence/main.go ./cmd/validator-signing-fence/main.go
COPY .ci/fence-security/blackbox.go ./.ci/fence-security/blackbox.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -o /out/fence ./cmd/validator-signing-fence && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -o /out/blackbox ./.ci/fence-security/blackbox.go

FROM scratch
COPY --from=build /out/fence /usr/local/bin/fence
COPY --from=build /out/blackbox /usr/local/bin/blackbox
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/blackbox", "-binary", "/usr/local/bin/fence"]

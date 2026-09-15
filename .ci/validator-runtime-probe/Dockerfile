FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64
WORKDIR /src
COPY go.mod ./
COPY cmd/validator-runtime-probe/ cmd/validator-runtime-probe/
RUN go test ./cmd/validator-runtime-probe && go build -trimpath -buildvcs=false -ldflags='-s -w' -o /out/validator-runtime-probe ./cmd/validator-runtime-probe
FROM scratch
COPY --from=build /out/validator-runtime-probe /validator-runtime-probe
USER 65532:65532
ENTRYPOINT ["/validator-runtime-probe"]

# Candidate only: unbuilt and not an approval, publication, or vulnerability-fix claim.
ARG GO_IMAGE=docker.io/library/golang@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG KYVERNO_COMMIT=40ec788d48bb28d83dbf85538e962a59db9d45c6
WORKDIR /src
RUN git init . && git remote add origin https://github.com/kyverno/kyverno.git \
 && git fetch --depth=1 origin "$KYVERNO_COMMIT" && git checkout --detach FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$KYVERNO_COMMIT" && mkdir -p /artifacts
COPY scripts/update-etcd.sh /usr/local/bin/update-etcd
RUN chmod 0555 /usr/local/bin/update-etcd && mkdir -p /artifacts/metadata \
 && update-etcd /src > /artifacts/metadata/resolved-modules.json \
 && cp go.mod /tmp/go.mod.resolved && cp go.sum /tmp/go.sum.resolved \
 && GOTOOLCHAIN=local GOMAXPROCS=2 GOMEMLIMIT=2GiB GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH=amd64 make build-cli VERSION=v1.19.1 \
 && cmp /tmp/go.mod.resolved go.mod && cmp /tmp/go.sum.resolved go.sum \
 && test -f cmd/cli/kubectl-kyverno/kubectl-kyverno \
 && go version -m cmd/cli/kubectl-kyverno/kubectl-kyverno > /buildinfo.txt \
 && cp go.mod go.sum /buildinfo.txt /artifacts/metadata/ \
 && cp cmd/cli/kubectl-kyverno/kubectl-kyverno /artifacts/kubectl-kyverno

FROM reg.kyverno.io/kyverno/kyverno-cli@sha256:2fc27b9b52bc976781462b7f4db741fd73d03db39ef29923c2b5d131950751df
COPY --from=build /artifacts/kubectl-kyverno /ko-app/kubectl-kyverno
COPY --from=build /artifacts/metadata /build-metadata

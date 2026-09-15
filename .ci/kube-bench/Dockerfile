# Candidate only: local recipe, not an approved, scanned, or published image.
ARG GO_IMAGE=docker.io/library/golang@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG KUBE_BENCH_COMMIT=5c6c22d51b926020e7414e1f1e051851d1a2feff
WORKDIR /src
RUN git init . \
 && git remote add origin https://github.com/aquasecurity/kube-bench.git \
 && git fetch --depth=1 origin "$KUBE_BENCH_COMMIT" \
 && git checkout --detach FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$KUBE_BENCH_COMMIT" \
 && printf '%s  %s\n' \
      '351ae14938c2cec98e1d0c05b3a0d12ca71e79af048aafb6de392133155597df' go.mod \
      'b9bb74a6b3661413e6378edc132ad2274983a24899c85828a27c29bb4fb4b980' go.sum \
      '18d59f216f679c2732e409f3c4a9e377add285df32f97f1afa115bb52d6d20c6' cfg/config.yaml \
      '5f3d3ab77fe97620b746a72d6a93579f483ba40f229e9aa0d08226be1e5c6e3b' cfg/eks-1.5.0/config.yaml \
      'b813b18cf94d752928a9d05a2072b9a56d0dab792f099e51b37c8a262b0d0511' cfg/eks-1.5.0/node.yaml \
      '9802c86b58d6fbf3a4fa4f1294f52a70db0b88fb5fddd780c24c29b0518049db' main.go \
      | sha256sum -c - \
 && test "$(grep -Ec '^      - id: 3[.][12][.][0-9]+$' cfg/eks-1.5.0/node.yaml)" = 13
RUN mkdir -p /tmp/go-mod /tmp/go-build /out \
 && cp go.mod /tmp/go.mod.locked && cp go.sum /tmp/go.sum.locked \
 && test "$(go env GOVERSION)" = go1.27.1 \
 && GOTOOLCHAIN=local GOMAXPROCS=2 GOMEMLIMIT=2GiB GOMODCACHE=/tmp/go-mod GOCACHE=/tmp/go-build go mod download \
 && GOTOOLCHAIN=local GOMODCACHE=/tmp/go-mod GOCACHE=/tmp/go-build go mod verify \
 && GOTOOLCHAIN=local GOMAXPROCS=2 GOMEMLIMIT=2GiB GOMODCACHE=/tmp/go-mod GOCACHE=/tmp/go-build GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags '-X github.com/aquasecurity/kube-bench/cmd.KubeBenchVersion=v0.16.0' -o /out/kube-bench . \
 && cmp /tmp/go.mod.locked go.mod && cmp /tmp/go.sum.locked go.sum

FROM --platform=linux/amd64 alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
WORKDIR /opt/kube-bench
# Node controls require BusyBox sh, cat, and stat plus procps /bin/ps with -fC.
# This exact closure was observed in the prior local candidate; a rebuilt image
# still requires a new SBOM and vulnerability scan before approval.
RUN apk add --no-cache \
      alpine-baselayout=3.7.2-r1 \
      alpine-baselayout-data=3.7.2-r1 \
      alpine-keys=2.6-r0 \
      alpine-release=3.24.1-r0 \
      apk-tools=3.0.8-r0 \
      busybox=1.37.0-r31 \
      busybox-binsh=1.37.0-r31 \
      ca-certificates-bundle=20260611-r0 \
      libapk=3.0.8-r0 \
      libcrypto3=3.5.8-r0 \
      libintl=1.0-r0 \
      libncursesw=6.6_p20260516-r0 \
      libproc2=4.0.6-r0 \
      libssl3=3.5.8-r0 \
      musl=1.2.6-r2 \
      musl-utils=1.2.6-r2 \
      ncurses-terminfo-base=6.6_p20260516-r0 \
      procps-ng=4.0.6-r0 \
      scanelf=1.3.9-r1 \
      skalibs-libs=2.15.0.0-r0 \
      ssl_client=1.37.0-r31 \
      utmps-libs=0.1.3.3-r0 \
      zlib=1.3.2-r0
COPY --from=build /out/kube-bench /usr/local/libexec/kube-bench.real
COPY --from=build /src/cfg/config.yaml ./cfg/config.yaml
COPY --from=build /src/cfg/eks-1.5.0/config.yaml ./cfg/eks-1.5.0/config.yaml
COPY --from=build /src/cfg/eks-1.5.0/node.yaml ./cfg/eks-1.5.0/node.yaml
RUN printf '%s\n' \
  '#!/bin/sh' \
  'set -eu' \
  'if [ "$#" -ne 6 ] || [ "$1" != run ] || [ "$2" != --targets ] || [ "$3" != node ] || [ "$4" != --benchmark ] || [ "$5" != eks-1.5.0 ] || [ "$6" != --json ]; then' \
  '  echo "usage: kube-bench run --targets node --benchmark eks-1.5.0 --json" >&2' \
  '  exit 64' \
  'fi' \
  'exec env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/nonexistent /usr/local/libexec/kube-bench.real "$@"' \
  > /usr/local/bin/kube-bench \
 && chmod 0555 /usr/local/bin/kube-bench /usr/local/libexec/kube-bench.real \
 && test -x /bin/sh && test -x /bin/cat && test -x /bin/stat && test -x /bin/ps
ENTRYPOINT ["/usr/local/bin/kube-bench"]
CMD ["run", "--targets", "node", "--benchmark", "eks-1.5.0", "--json"]

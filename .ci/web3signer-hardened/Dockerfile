FROM eclipse-temurin:21-jdk-noble@sha256:75ce56643243c3db632be2ef259625fb42ee3be1334389659f7a1a61acb78783 AS build
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git init . && git remote add origin https://github.com/Consensys/web3signer.git && \
    git fetch --depth=1 origin tag 26.4.2 && git checkout --detach 26.4.2 && \
    test "$(git rev-parse HEAD)" = 221996a5ddf6ab7648a8102ee029d9723762c116
COPY .ci/web3signer-hardened/patches/0001-security-dependencies.patch /tmp/security.patch
RUN echo 'a90f4a526417d3185b22ee3dce1bf21b1ab90e903fe2c2e564834594153b2062  /tmp/security.patch' | sha256sum -c - && \
    git apply --check /tmp/security.patch && git apply /tmp/security.patch && git diff --check
COPY .ci/web3signer-hardened/patches/0002-signing-audit-metadata.patch /tmp/signing-audit.patch
RUN echo '582fb3dab2673fef1108954641e04adb69c38b2a11532c5b7c2b5e4c5667f04e  /tmp/signing-audit.patch' | sha256sum -c - && \
    git apply --check /tmp/signing-audit.patch && git apply /tmp/signing-audit.patch && git diff --check
RUN useradd --uid 10001 --create-home --home-dir /build-home builder && chown -R 10001:10001 /src
USER 10001:10001
ENV GRADLE_USER_HOME=/build-home/.gradle
# The upstream filesystem-denial tests must execute without root privileges.
RUN --mount=type=cache,id=web3signer-gradle-nonroot,target=/build-home/.gradle,uid=10001,gid=10001 \
    ./gradlew --no-daemon --max-workers=2 :core:test :signing:test :keystorage:test :slashing-protection:test installDist

FROM eclipse-temurin:25-jre-noble@sha256:b4c93a50fc67612798db73d68ca3b0ee4ebdd51736e59cca370e689b9797037e
LABEL org.opencontainers.image.source="https://github.com/Consensys/web3signer" \
      org.opencontainers.image.revision="221996a5ddf6ab7648a8102ee029d9723762c116" \
      io.node-operator.web3signer-security-patch-sha256="a90f4a526417d3185b22ee3dce1bf21b1ab90e903fe2c2e564834594153b2062" \
      io.node-operator.web3signer-audit-patch-sha256="582fb3dab2673fef1108954641e04adb69c38b2a11532c5b7c2b5e4c5667f04e"
ENV WEB3SIGNER_HTTP_LISTEN_HOST=0.0.0.0 WEB3SIGNER_METRICS_HOST=0.0.0.0
COPY --from=build --chown=999:999 /src/build/install/web3signer /opt/web3signer
USER 999:999
WORKDIR /opt/web3signer
ENTRYPOINT ["/opt/web3signer/bin/web3signer"]

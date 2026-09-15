FROM ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517

ARG NODE_VERSION=22.16.0
ARG NODE_SHA256=f4cb75bb036f0d0eddf6b79d9596df1aaab9ddccd6a20bf489be5abe9467e84e
ARG KUBECTL_VERSION=1.35.0
ARG KUBECTL_SHA256=a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989
ARG SYFT_VERSION=1.37.0
ARG SYFT_SHA256=b81a0dc81b92265f4597659bba5509e014c78228182804bb1bc97856af26e326
ARG TOOLCHAIN_INPUT_SHA

LABEL io.node-operator.toolchain-input-sha="${TOOLCHAIN_INPUT_SHA}"
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git jq perl python3 ripgrep tar xz-utils zip && rm -rf /var/lib/apt/lists/*
RUN curl --fail --location --silent --show-error --output /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
 && echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum --check --status \
 && tar -xJf /tmp/node.tar.xz -C /opt \
 && ln -s "/opt/node-v${NODE_VERSION}-linux-x64/bin/node" /usr/local/bin/node \
 && ln -s "/opt/node-v${NODE_VERSION}-linux-x64/bin/npm" /usr/local/bin/npm \
 && rm /tmp/node.tar.xz
RUN curl --fail --location --silent --show-error --output /usr/local/bin/kubectl "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
 && echo "${KUBECTL_SHA256}  /usr/local/bin/kubectl" | sha256sum --check --status \
 && chmod 0755 /usr/local/bin/kubectl
RUN curl --fail --location --silent --show-error --output /tmp/syft.tar.gz "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
 && echo "${SYFT_SHA256}  /tmp/syft.tar.gz" | sha256sum --check --status \
 && tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft \
 && rm /tmp/syft.tar.gz

WORKDIR /workspace

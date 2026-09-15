FROM ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517

ARG HELM_VERSION=3.17.3
ARG HELM_SHA256=ee88b3c851ae6466a3de507f7be73fe94d54cbf2987cbaa3d1a3832ea331f2cd
ARG AWSCLI_VERSION=2.17.3
ARG AWSCLI_SHA256=24ee65f82f5c074a326ac749df7703305190a19e96920c3a834381e49df7bc6e
ARG KUBECTL_VERSION=1.35.0
ARG KUBECTL_SHA256=a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989
ARG TOOLCHAIN_INPUT_SHA

LABEL io.node-operator.toolchain-input-sha="${TOOLCHAIN_INPUT_SHA}"
ENV DEBIAN_FRONTEND=noninteractive

# This image is built in GitHub and subsequently copied into private ECR. The
# CodeBuild runtime has no route to a public package mirror or registry.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl tar unzip && rm -rf /var/lib/apt/lists/*
RUN curl --fail --location --silent --show-error --output /tmp/awscliv2.zip "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-${AWSCLI_VERSION}.zip" \
 && echo "${AWSCLI_SHA256}  /tmp/awscliv2.zip" | sha256sum --check --status \
 && unzip -q /tmp/awscliv2.zip -d /tmp \
 && /tmp/aws/install --bin-dir /usr/local/bin --install-dir /opt/aws-cli \
 && rm -rf /tmp/aws /tmp/awscliv2.zip
RUN curl --fail --location --silent --show-error --output /tmp/helm.tar.gz "https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz" \
 && echo "${HELM_SHA256}  /tmp/helm.tar.gz" | sha256sum --check --status \
 && tar -xzf /tmp/helm.tar.gz -C /tmp linux-amd64/helm \
 && install -m 0755 /tmp/linux-amd64/helm /usr/local/bin/helm \
 && rm -rf /tmp/helm.tar.gz /tmp/linux-amd64
RUN curl --fail --location --silent --show-error --output /usr/local/bin/kubectl "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
 && echo "${KUBECTL_SHA256}  /usr/local/bin/kubectl" | sha256sum --check --status \
 && chmod 0755 /usr/local/bin/kubectl

# The values are non-secret deployment input and are deliberately embedded so
# NO_SOURCE CodeBuild cannot fetch or substitute a mutable external file.
COPY docs/gitops/argocd-private-values.example.yaml /opt/node-operator/argocd-private-values.yaml
COPY docs/gitops/cert-manager-values.example.yaml /opt/node-operator/cert-manager-values.yaml
COPY docs/gitops/vault-tls-internal-ca.example.yaml /opt/node-operator/vault-tls-internal-ca.yaml

WORKDIR /workspace

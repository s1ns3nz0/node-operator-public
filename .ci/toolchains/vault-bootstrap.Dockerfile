FROM ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517

ARG HELM_VERSION=3.17.3
ARG HELM_SHA256=ee88b3c851ae6466a3de507f7be73fe94d54cbf2987cbaa3d1a3832ea331f2cd
ARG AWSCLI_VERSION=2.17.3
ARG AWSCLI_SHA256=24ee65f82f5c074a326ac749df7703305190a19e96920c3a834381e49df7bc6e
ARG KUBECTL_VERSION=1.35.0
ARG KUBECTL_SHA256=a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989
ARG CA_CERTIFICATES_VERSION=20260601~24.04.1
ARG CURL_VERSION=8.5.0-2ubuntu10.13
ARG TAR_VERSION=1.35+dfsg-3ubuntu0.4
ARG UNZIP_VERSION=6.0-28ubuntu4.1
ARG JQ_VERSION=1.7.1-3ubuntu0.24.04.2
ARG TOOLCHAIN_INPUT_SHA

LABEL io.node-operator.toolchain-input-sha="${TOOLCHAIN_INPUT_SHA}"
ENV DEBIAN_FRONTEND=noninteractive

# Public downloads occur only while the reviewed toolchain is built. The
# private CodeBuild runtime has no public egress and receives this image only
# from ECR after an approved digest-preserving mirror.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates=${CA_CERTIFICATES_VERSION} \
      curl=${CURL_VERSION} \
      tar=${TAR_VERSION} \
      unzip=${UNZIP_VERSION} \
      jq=${JQ_VERSION} \
 && rm -rf /var/lib/apt/lists/*
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

# This is non-secret deployment input. The KMS key ARN is rendered by the
# Terraform-owned NO_SOURCE buildspec and never written back to Git.
COPY docs/gitops/vault-values.example.yaml /opt/node-operator/vault-values.template.yaml
COPY scripts/ops/verify-hoodi-vault-readiness.sh /opt/node-operator/verify-hoodi-vault-readiness.sh
COPY docs/gitops/vault-gp3-encrypted-storageclass.yaml /opt/node-operator/vault-gp3-encrypted-storageclass.yaml
COPY scripts/ops/ensure-vault-encrypted-storageclass.sh /opt/node-operator/ensure-vault-encrypted-storageclass.sh
RUN chmod 0755 /opt/node-operator/verify-hoodi-vault-readiness.sh /opt/node-operator/ensure-vault-encrypted-storageclass.sh

WORKDIR /workspace

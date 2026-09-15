FROM ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517

ARG VAULT_VERSION=1.20.4
ARG VAULT_SHA256=fc5fb5d01d192f1216b139fb5c6af17e3af742aaeffc289fd861920ec55f2c9c
ARG TOOLCHAIN_INPUT_SHA

LABEL io.node-operator.toolchain-input-sha="${TOOLCHAIN_INPUT_SHA}"
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl jq unzip && rm -rf /var/lib/apt/lists/*
RUN curl --fail --location --silent --show-error --output /tmp/vault.zip "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip" \
 && echo "${VAULT_SHA256}  /tmp/vault.zip" | sha256sum --check --status \
 && unzip -q /tmp/vault.zip -d /usr/local/bin \
 && vault version | grep -Eq "^Vault v${VAULT_VERSION}( |$)" \
 && rm /tmp/vault.zip

WORKDIR /workspace

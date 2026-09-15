FROM ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517

ARG TERRAFORM_VERSION=1.5.7
ARG TERRAFORM_SHA256=c0ed7bc32ee52ae255af9982c8c88a7a4c610485cf1d55feeb037eab75fa082c
ARG AWS_PROVIDER_VERSION=5.100.0
ARG AWS_PROVIDER_SHA256=1589a2266af699cbd5d80737a0fe02e54ec9cf2ca54e7e00ac51c7359056f274
ARG TOOLCHAIN_INPUT_SHA

LABEL io.node-operator.toolchain-input-sha="${TOOLCHAIN_INPUT_SHA}"
ENV DEBIAN_FRONTEND=noninteractive
ENV TF_CLI_CONFIG_FILE=/etc/terraformrc

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git jq unzip && rm -rf /var/lib/apt/lists/*
RUN curl --fail --location --silent --show-error --output /tmp/terraform.zip "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" \
 && echo "${TERRAFORM_SHA256}  /tmp/terraform.zip" | sha256sum --check --status \
 && unzip -q /tmp/terraform.zip -d /usr/local/bin \
 && rm /tmp/terraform.zip
RUN mkdir -p "/opt/terraform-plugin-mirror/registry.terraform.io/hashicorp/aws/${AWS_PROVIDER_VERSION}/linux_amd64" \
 && curl --fail --location --silent --show-error --output /tmp/aws-provider.zip "https://releases.hashicorp.com/terraform-provider-aws/${AWS_PROVIDER_VERSION}/terraform-provider-aws_${AWS_PROVIDER_VERSION}_linux_amd64.zip" \
 && echo "${AWS_PROVIDER_SHA256}  /tmp/aws-provider.zip" | sha256sum --check --status \
 && unzip -q /tmp/aws-provider.zip -d "/opt/terraform-plugin-mirror/registry.terraform.io/hashicorp/aws/${AWS_PROVIDER_VERSION}/linux_amd64" \
 && rm /tmp/aws-provider.zip
RUN printf '%s\n' \
  'provider_installation {' \
  '  filesystem_mirror { path = "/opt/terraform-plugin-mirror" }' \
  '  direct { exclude = ["*/*"] }' \
  '}' > /etc/terraformrc

WORKDIR /workspace

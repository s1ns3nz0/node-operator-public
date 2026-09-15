FROM ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517

ARG TOOLCHAIN_INPUT_SHA

LABEL io.node-operator.toolchain-input-sha="${TOOLCHAIN_INPUT_SHA}"
ENV DEBIAN_FRONTEND=noninteractive

# skopeo copies both OCI manifests and every referenced blob. It is kept in a
# dedicated, digest-pinned CI image so mirror jobs do not install it at runtime.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates skopeo && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["skopeo"]

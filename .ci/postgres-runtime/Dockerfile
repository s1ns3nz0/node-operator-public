FROM postgres@sha256:bb3e1a57e5407e0a5280b4211980a5e537f4abd234a87014ac979849a78dd825 AS upstream

FROM ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517

ARG DEBIAN_FRONTEND=noninteractive

# Keep dpkg metadata intact so image scans cover every installed package.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    mkdir -p /etc/postgresql-common \
    && printf 'create_main_cluster = false\n' > /etc/postgresql-common/createcluster.conf \
    && apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        locales \
        libpq5=16.15-0ubuntu0.24.04.1 \
        postgresql-client-16=16.15-0ubuntu0.24.04.1 \
        postgresql-16=16.15-0ubuntu0.24.04.1 \
    && sed -i 's/^# *\(en_US.UTF-8 UTF-8\)$/\1/' /etc/locale.gen \
    && locale-gen en_US.UTF-8 \
    && groupmod --gid 999 postgres \
    && usermod --uid 999 --gid 999 postgres \
    && mkdir -p /docker-entrypoint-initdb.d /var/lib/postgresql/data /var/run/postgresql \
    && chown -R 999:999 /var/lib/postgresql /var/run/postgresql \
    && test ! -e /var/lib/postgresql/16/main/PG_VERSION \
    && /usr/lib/postgresql/16/bin/postgres --version

COPY --from=upstream /usr/local/bin/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN printf '%s  %s\n' \
      9c440299ae04a0a79d55b8bf03307036d890a40979d2fb698073c9050d4b20a5 \
      /usr/local/bin/docker-entrypoint.sh \
    | sha256sum --check --strict -

ENV LANG=en_US.UTF-8 \
    PATH=/usr/lib/postgresql/16/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PGDATA=/var/lib/postgresql/data/pgdata

VOLUME ["/var/lib/postgresql/data"]
USER 999:999
STOPSIGNAL SIGINT
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["postgres"]

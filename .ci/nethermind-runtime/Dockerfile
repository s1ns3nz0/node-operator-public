# Preserve the upstream 1.39.3 framework-dependent application unchanged.
FROM nethermind/nethermind@sha256:ec5f6c8158dbf82d4ddbd5500f895c930f52aa3b4c998148d9e1b452793d828e AS application

FROM mcr.microsoft.com/dotnet/aspnet:10.0.11-resolute-chiseled@sha256:95fe45615d8ca4de2aa15206a827ce9383b67e8e34cc0aba58cb3261fb52c40c
WORKDIR /nethermind
COPY --from=application /nethermind /nethermind
LABEL org.opencontainers.image.source="https://github.com/NethermindEth/nethermind" \
      org.opencontainers.image.version="1.39.3-runtime-10.0.11" \
      org.opencontainers.image.revision="28cbe2a0ae28373f66abdc584f3eaf21516e84b3" \
      io.node-operator.application-source-digest="sha256:ec5f6c8158dbf82d4ddbd5500f895c930f52aa3b4c998148d9e1b452793d828e"
VOLUME /nethermind/keystore /nethermind/logs /nethermind/nethermind_db
EXPOSE 8545 8551 30303
USER app
ENTRYPOINT ["./nethermind"]

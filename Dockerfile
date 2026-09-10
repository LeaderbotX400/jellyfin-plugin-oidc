# To bump digest: curl -sSL -D - https://mcr.microsoft.com/v2/dotnet/sdk/manifests/10.0 -H "Accept: application/vnd.docker.distribution.manifest.v2+json" | grep docker-content-digest
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:4ea6fe75dd36706bb6d8c3c293d4c4315840f5d76ea28ac97def77e3ec487fa5 AS build

WORKDIR /src
COPY . .
RUN dotnet restore
RUN dotnet publish Jellyfin.Plugin.OIDC/Jellyfin.Plugin.OIDC.csproj \
    -c Release \
    -o /out \
    --no-restore

# Build the installable zip package
RUN apt-get update && apt-get install -y --no-install-recommends zip \
    && cd /out \
    && zip /oidc-rbac.zip *.dll meta.json \
    && rm -rf /var/lib/apt/lists/*

FROM scratch AS artifact
COPY --from=build /out/*.dll /out/meta.json /
COPY --from=build /oidc-rbac.zip /

FROM scratch AS package
COPY --from=build /oidc-rbac.zip /

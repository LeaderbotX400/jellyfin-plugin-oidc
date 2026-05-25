# To bump digest: curl -sSL -D - https://mcr.microsoft.com/v2/dotnet/sdk/manifests/9.0 -H "Accept: application/vnd.docker.distribution.manifest.v2+json" | grep docker-content-digest
FROM mcr.microsoft.com/dotnet/sdk:9.0@sha256:0d2d99c1f384a6b9c8f37aaea952937b2ffff20aa150c7eb4fdeb0a968797d31 AS build

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

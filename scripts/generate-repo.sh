#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$REPO_ROOT/dist"
REPO_DIR="$REPO_ROOT/repo"
ZIP_FILE="$BUILD_DIR/oidc-rbac.zip"
PLUGIN_VERSION="$(sed -n 's/^version: *"\(.*\)"/\1/p' "$REPO_ROOT/build.yaml")"
TARGET_ABI="$(sed -n 's/^targetAbi: *"\(.*\)"/\1/p' "$REPO_ROOT/build.yaml")"

REPO_URL="${1:-}"

if [ ! -f "$ZIP_FILE" ]; then
    echo "Error: $ZIP_FILE not found. Run 'make package' first." >&2
    exit 1
fi

mkdir -p "$REPO_DIR"
cp "$ZIP_FILE" "$REPO_DIR/"

CHECKSUM=$(md5sum "$ZIP_FILE" | cut -d' ' -f1)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if [ -n "$REPO_URL" ]; then
    SOURCE_URL="${REPO_URL%/}/oidc-rbac.zip"
else
    SOURCE_URL=""
fi

cat > "$REPO_DIR/manifest.json" <<EOF
[
  {
    "guid": "eea268ef-ea57-4462-91c4-44833ae08510",
    "name": "OIDC-Auth",
    "description": "Advanced OIDC authentication with role-based library access control",
    "overview": "OpenID Connect SSO with role-to-library mapping, multi-provider support, and admin UI.",
    "owner": "LeaderbotX400",
    "category": "Authentication",
    "versions": [
      {
        "version": "$PLUGIN_VERSION",
        "changelog": "Release $PLUGIN_VERSION",
        "targetAbi": "$TARGET_ABI",
        "sourceUrl": "$SOURCE_URL",
        "checksum": "$CHECKSUM",
        "timestamp": "$TIMESTAMP"
      }
    ]
  }
]
EOF

echo "Repository generated in $REPO_DIR/"
echo "  manifest.json  - add this URL to Jellyfin > Plugins > Repositories"
echo "  oidc-rbac.zip  - plugin package"
echo ""
if [ -n "$REPO_URL" ]; then
    echo "Repository URL for Jellyfin: ${REPO_URL%/}/manifest.json"
else
    echo "To serve locally:"
    echo "  cd $REPO_DIR && python3 -m http.server 8080"
    echo "  Then add http://YOUR_HOST:8080/manifest.json to Jellyfin"
fi

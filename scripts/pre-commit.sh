#!/usr/bin/env bash
# Pre-commit guard: build + run full test suite. Fails the commit if either fails.
# Install:  ln -sf "$(pwd)/scripts/pre-commit.sh" .git/hooks/pre-commit
# Bypass (use sparingly): git commit --no-verify

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# Project uses devenv (Nix) for dotnet 10. Prefer direct dotnet if it works,
# otherwise wrap in devenv shell.
if command -v dotnet >/dev/null 2>&1 && dotnet --list-sdks 2>/dev/null | grep -q '^10\.'; then
  RUN=""
else
  RUN="devenv shell --"
fi

echo "[pre-commit] dotnet build…"
$RUN dotnet build jellyfin-plugin-oidc.sln --nologo -clp:NoSummary >/tmp/precommit-build.log 2>&1 || {
  tail -40 /tmp/precommit-build.log
  echo "[pre-commit] BUILD FAILED — commit aborted"
  exit 1
}

echo "[pre-commit] dotnet test…"
$RUN dotnet test jellyfin-plugin-oidc.sln --no-build --nologo >/tmp/precommit-test.log 2>&1 || {
  tail -60 /tmp/precommit-test.log
  echo "[pre-commit] TESTS FAILED — commit aborted"
  exit 1
}

echo "[pre-commit] OK"

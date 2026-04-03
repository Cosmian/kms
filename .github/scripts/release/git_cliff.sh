#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
VERSION=$("$SCRIPT_DIR/get_version.sh")

git cliff -w "$REPO_ROOT" -u -p "$REPO_ROOT/CHANGELOG.md" -t "$VERSION"

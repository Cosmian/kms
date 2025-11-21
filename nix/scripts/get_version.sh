#!/usr/bin/env bash
# Extract version from workspace Cargo.toml
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CARGO_TOML="$REPO_ROOT/Cargo.toml"

if [ ! -f "$CARGO_TOML" ]; then
  echo "Error: Cargo.toml not found at $CARGO_TOML" >&2
  exit 1
fi

# Extract version from [workspace.package] section
# Look for: version = "x.y.z"
VERSION=$(grep -A 20 '^\[workspace\.package\]' "$CARGO_TOML" | grep '^version' | head -1 | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')

if [ -z "$VERSION" ]; then
  echo "Error: Could not extract version from $CARGO_TOML" >&2
  exit 1
fi

echo "$VERSION"

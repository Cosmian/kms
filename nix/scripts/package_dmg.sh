#!/usr/bin/env bash
set -euo pipefail
set -x

# Build DMG package for macOS (FIPS or non-FIPS based on FEATURES env variable)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")

[ "$(uname)" != "Darwin" ] && {
  echo "Error: DMG packages can only be built on macOS" >&2
  exit 1
}

# DMG packages should always be built in release mode
: "${DEBUG_OR_RELEASE:=release}"
export DEBUG_OR_RELEASE

init_build_env

echo "Building ${VARIANT_NAME} DMG package for macOS..."

# Install packaging tool (only if not already at the correct version)
cargo packager --version 2>/dev/null | grep -q "0.11.7" || cargo install --version 0.11.7 cargo-packager --force

bash "$SCRIPT_DIR/build.sh"

cd "$REPO_ROOT/crate/server"
cargo packager --verbose --formats dmg

cd "$REPO_ROOT"
find target/release -name "*.dmg" -type f 2>/dev/null || echo "DMG file should be in target/release/bundle/"
echo "${VARIANT_NAME} DMG package build completed successfully."

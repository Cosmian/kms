#!/usr/bin/env bash
set -euo pipefail
set -x

# Build DEB package (FIPS or non-FIPS based on FEATURES env variable)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")

# DEB packages should always be built in release mode
: "${DEBUG_OR_RELEASE:=debug}"
export DEBUG_OR_RELEASE

init_build_env

echo "Building ${VARIANT_NAME} DEB package..."

prepare_openssl_staging "$REPO_ROOT"
rm -rf target/debian

# Install packaging tool
cargo deb --version 2>/dev/null | grep -q "2.4.0" || cargo install --version 2.4.0 cargo-deb --force

bash "$SCRIPT_DIR/build.sh"

cd "$REPO_ROOT/crate/server"
BUILD_VARIANT=""
[ -z "$FEATURES" ] && BUILD_VARIANT="--variant fips"
# shellcheck disable=SC2086
cargo deb $BUILD_VARIANT

cd "$REPO_ROOT"

DEB_FILES=$(find "$REPO_ROOT/target/debian" -name "*.deb" -type f)
[ -z "$DEB_FILES" ] && {
  echo "Error: No .deb package found in $REPO_ROOT/target/debian" >&2
  exit 1
}
echo "$DEB_FILES"
echo "${VARIANT_NAME} DEB package build completed successfully."

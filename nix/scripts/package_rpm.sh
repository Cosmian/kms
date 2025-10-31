#!/usr/bin/env bash
set -euo pipefail
set -x

# Build RPM package (FIPS or non-FIPS based on FEATURES env variable)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")

init_build_env

echo "Building ${VARIANT_NAME} RPM package..."

prepare_openssl_staging "$REPO_ROOT"
rm -rf target/generate-rpm

# Install packaging tool
cargo generate-rpm --version 0.16.0 2>/dev/null | grep -q "0.16.0" ||
  cargo install --version 0.16.0 cargo-generate-rpm --force

DEBUG_OR_RELEASE=release bash "$SCRIPT_DIR/build.sh"

cd "$REPO_ROOT"
cargo generate-rpm -p crate/server --metadata-overwrite=pkg/rpm/scriptlets.toml

RPM_FILES=$(find "$REPO_ROOT/target/generate-rpm" -name "*.rpm" -type f)
[ -z "$RPM_FILES" ] && {
  echo "Error: No .rpm package found in target/generate-rpm" >&2
  exit 1
}
echo "$RPM_FILES"
echo "${VARIANT_NAME} RPM package build completed successfully."

#!/usr/bin/env bash
set -euo pipefail
set -x

# Discover repo root (works inside nix-shell)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

# Resolve inputs with defaults inside the nix environment
: "${DEBUG_OR_RELEASE:=release}"
: "${TARGET:=x86_64-unknown-linux-gnu}"
: "${FEATURES:=}"

# Using nix-shell OpenSSL toolchain provided by the environment (no external import)

if [ "$DEBUG_OR_RELEASE" != "release" ]; then
  echo "Error: Packaging requires DEBUG_OR_RELEASE=release" >&2
  exit 1
fi

FEATURES_FLAG=()
if [ -n "$FEATURES" ]; then
  FEATURES_FLAG=(--features "$FEATURES")
fi

# Clean previous packaging artifacts
rm -rf target/"$TARGET"/debian
rm -rf target/"$TARGET"/generate-rpm

# Install packaging tools
cargo install --version 2.4.0 cargo-deb --force
cargo install --version 0.16.0 cargo-generate-rpm --force

# Red Hat/Fedora/CentOS: Build RPM package
echo "Building RPM package for Red Hat-based system..."

# Build with non-fips features for RPM
cd crate/server
cargo build --features non-fips --release --target "$TARGET"
cd "$REPO_ROOT"

cargo generate-rpm --target "$TARGET" -p crate/server --metadata-overwrite=pkg/rpm/scriptlets.toml

echo "RPM package built successfully."

# Debian/Ubuntu: Build DEB package
echo "Building DEB package for Debian-based system..."

if [ -n "$FEATURES" ]; then
  # Non-FIPS variant
  cargo deb --target "$TARGET" -p cosmian_kms_server "${FEATURES_FLAG[@]}"
else
  # FIPS variant
  cargo deb --target "$TARGET" -p cosmian_kms_server --variant fips
fi

echo "DEB package built successfully."

# Display package location
if [ -f /etc/redhat-release ]; then
  find target/"$TARGET"/generate-rpm -name "*.rpm" -type f
elif [ -f /etc/debian_version ]; then
  find target/"$TARGET"/debian -name "*.deb" -type f
fi

echo "Package build completed successfully."

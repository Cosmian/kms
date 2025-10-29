#!/usr/bin/env bash
set -euo pipefail
set -x

# Google CSE tests - requires Google OAuth credentials
# This script is called from nix.sh inside a nix-shell environment

# Discover repo root (works inside nix-shell)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

# Resolve inputs with defaults inside the nix environment
: "${DEBUG_OR_RELEASE:=debug}"
: "${FEATURES:=}"

RELEASE_FLAG=""
if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  RELEASE_FLAG="--release"
fi

FEATURES_FLAG=()
if [ -n "$FEATURES" ]; then
  FEATURES_FLAG=(--features "$FEATURES")
fi

export RUST_LOG="cosmian_kms_cli=error,cosmian_kms_server=error,cosmian_kmip=error,test_kms_server=error"

echo "========================================="
echo "Running Google CSE tests"
echo "========================================="

# Google CSE tests (if credentials are available)
if [ -z "${TEST_GOOGLE_OAUTH_CLIENT_ID:-}" ] ||
  [ -z "${TEST_GOOGLE_OAUTH_CLIENT_SECRET:-}" ] ||
  [ -z "${TEST_GOOGLE_OAUTH_REFRESH_TOKEN:-}" ] ||
  [ -z "${GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY:-}" ]; then
  echo "Error: Google CSE credentials not provided" >&2
  echo "Required environment variables:" >&2
  echo "  - TEST_GOOGLE_OAUTH_CLIENT_ID" >&2
  echo "  - TEST_GOOGLE_OAUTH_CLIENT_SECRET" >&2
  echo "  - TEST_GOOGLE_OAUTH_REFRESH_TOKEN" >&2
  echo "  - GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY" >&2
  exit 1
fi

echo "Running Google CSE tests..."
cargo test --workspace --lib $RELEASE_FLAG "${FEATURES_FLAG[@]}" -- --nocapture test_google_cse --ignored

echo "Google CSE tests completed successfully."

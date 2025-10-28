#!/usr/bin/env bash
# Unified entrypoint to run nix-shell commands: build, test, or packages
set -euo pipefail

# Display usage information
usage() {
  cat <<EOF
Usage: $0 <command>

Commands:
  build      Build the KMS server inside nix-shell
  test       Run tests inside nix-shell with multi-database support
  packages   Build Debian/RPM packages inside nix-shell

Environment variables:
  DEBUG_OR_RELEASE   debug or release (default: debug for build, release for packages)
  TARGET             Target architecture (default: x86_64-unknown-linux-gnu)
  FEATURES           Cargo features (e.g., "non-fips")

  For testing, also supports:
  REDIS_HOST, REDIS_PORT
  MYSQL_HOST, MYSQL_PORT
  POSTGRES_HOST, POSTGRES_PORT
  TEST_GOOGLE_OAUTH_CLIENT_ID, TEST_GOOGLE_OAUTH_CLIENT_SECRET
  TEST_GOOGLE_OAUTH_REFRESH_TOKEN, GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY

Examples:
  $0 build
  DEBUG_OR_RELEASE=release FEATURES=non-fips $0 build
  $0 test
  DEBUG_OR_RELEASE=release $0 packages
EOF
  exit 1
}

# Check for command argument
if [ $# -eq 0 ]; then
  echo "Error: No command specified" >&2
  usage
fi

COMMAND="$1"
shift

# Determine repository root
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"

# Validate command and corresponding script
case "$COMMAND" in
build)
  SCRIPT="$REPO_ROOT/nix/build.sh"
  KEEP_VARS="--keep DEBUG_OR_RELEASE --keep TARGET --keep FEATURES"
  ;;
test)
  SCRIPT="$REPO_ROOT/nix/test.sh"
  KEEP_VARS="--keep DEBUG_OR_RELEASE --keep TARGET --keep FEATURES \
      --keep REDIS_HOST --keep REDIS_PORT \
      --keep MYSQL_HOST --keep MYSQL_PORT \
      --keep POSTGRES_HOST --keep POSTGRES_PORT \
      --keep TEST_GOOGLE_OAUTH_CLIENT_ID \
      --keep TEST_GOOGLE_OAUTH_CLIENT_SECRET \
      --keep TEST_GOOGLE_OAUTH_REFRESH_TOKEN \
      --keep GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY"
  ;;
packages)
  SCRIPT="$REPO_ROOT/nix/packages.sh"
  KEEP_VARS="--keep DEBUG_OR_RELEASE --keep TARGET --keep FEATURES"
  ;;
*)
  echo "Error: Unknown command '$COMMAND'" >&2
  usage
  ;;
esac

# Check if script exists
[ -f "$SCRIPT" ] || {
  echo "Missing $SCRIPT" >&2
  exit 1
}

# Check if shell.nix exists
[ -f "$REPO_ROOT/shell.nix" ] || {
  echo "Error: No shell.nix found at $REPO_ROOT" >&2
  exit 1
}

# Ensure <nixpkgs> lookups work even if NIX_PATH is unset (common on CI)
# Pin to the same nixpkgs as shell.nix to keep environments consistent
PINNED_NIXPKGS_URL="https://github.com/NixOS/nixpkgs/archive/24.05.tar.gz"
if [ -z "${NIX_PATH:-}" ]; then
  export NIX_PATH="nixpkgs=${PINNED_NIXPKGS_URL}"
fi

# Run the appropriate script inside nix-shell
# shellcheck disable=SC2086
nix-shell -I "nixpkgs=${PINNED_NIXPKGS_URL}" "$REPO_ROOT/shell.nix" --pure \
  $KEEP_VARS \
  --run "bash '$SCRIPT' $*"

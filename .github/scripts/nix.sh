#!/usr/bin/env bash
# Unified entrypoint to run nix-shell commands: build, test, or packages
set -euo pipefail

# Display usage information
usage() {
  cat <<EOF
Usage: $0 <command> [subcommand]

Commands:
  build              Build the KMS server inside nix-shell
  test <type>        Run specific tests inside nix-shell
    sqlite           Run SQLite tests (default, always available)
    mysql            Run MySQL tests (requires MySQL server)
    psql             Run PostgreSQL tests (requires PostgreSQL server)
    redis            Run Redis-findex tests (requires Redis server, non-FIPS only)
    google_cse       Run Google CSE tests (requires credentials)
    hsm              Run HSM tests (Linux only, requires Utimaco and SoftHSM2)
  package <type>     Build a specific package type inside nix-shell
    deb              Build Debian package (FIPS or non-FIPS based on FEATURES)
    rpm              Build RPM package (FIPS or non-FIPS based on FEATURES)
    dmg              Build macOS DMG package (FIPS or non-FIPS based on FEATURES)

Environment variables:
  DEBUG_OR_RELEASE   debug or release (default: debug for build, release for packages)
  FEATURES           Cargo features (e.g., "non-fips")
                     - If set: builds non-FIPS variant
                     - If empty/unset: builds FIPS variant

  For testing, also supports:
  REDIS_HOST, REDIS_PORT
  MYSQL_HOST, MYSQL_PORT
  POSTGRES_HOST, POSTGRES_PORT
  TEST_GOOGLE_OAUTH_CLIENT_ID, TEST_GOOGLE_OAUTH_CLIENT_SECRET
  TEST_GOOGLE_OAUTH_REFRESH_TOKEN, GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY

Examples:
  $0 build
  DEBUG_OR_RELEASE=release FEATURES=non-fips $0 build
  $0 test sqlite
  $0 test mysql
  FEATURES=non-fips $0 test redis
  $0 package deb                          # FIPS variant
  FEATURES=non-fips $0 package deb        # non-FIPS variant
  FEATURES=non-fips $0 package rpm        # non-FIPS variant
  FEATURES=non-fips $0 package dmg        # non-FIPS variant
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

# Handle test subcommand
TEST_TYPE=""
if [ "$COMMAND" = "test" ]; then
  if [ $# -eq 0 ]; then
    echo "Error: test command requires a test type (sqlite, mysql, psql, redis, google_cse, hsm)" >&2
    usage
  fi
  TEST_TYPE="$1"
  shift
fi

# Handle package subcommand
PACKAGE_TYPE=""
if [ "$COMMAND" = "package" ]; then
  if [ $# -eq 0 ]; then
    echo "Error: package command requires a package type (deb, rpm, or dmg)" >&2
    usage
  fi
  PACKAGE_TYPE="$1"
  shift
fi

# Extra nix packages to include in the nix-shell environment
# Ensure wget is available for tests that need to fetch external resources
EXTRA_NIX_PKGS=""
if [ "$COMMAND" = "test" ]; then
  EXTRA_NIX_PKGS="-p wget"
fi

# Determine repository root
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"

# Validate command and corresponding script
case "$COMMAND" in
build)
  SCRIPT="$REPO_ROOT/nix/build.sh"
  KEEP_VARS="--keep DEBUG_OR_RELEASE --keep FEATURES"
  ;;
test)
  case "$TEST_TYPE" in
  sqlite)
    SCRIPT="$REPO_ROOT/nix/test_sqlite.sh"
    ;;
  mysql)
    SCRIPT="$REPO_ROOT/nix/test_mysql.sh"
    ;;
  psql)
    SCRIPT="$REPO_ROOT/nix/test_psql.sh"
    ;;
  redis)
    SCRIPT="$REPO_ROOT/nix/test_redis.sh"
    ;;
  google_cse)
    SCRIPT="$REPO_ROOT/nix/test_google_cse.sh"
    ;;
  hsm)
    SCRIPT="$REPO_ROOT/nix/test_hsm.sh"
    ;;
  *)
    echo "Error: Unknown test type '$TEST_TYPE'" >&2
    echo "Valid types: sqlite, mysql, psql, redis, google_cse, hsm" >&2
    usage
    ;;
  esac
  KEEP_VARS="--keep DEBUG_OR_RELEASE --keep FEATURES \
      --keep REDIS_HOST --keep REDIS_PORT \
      --keep MYSQL_HOST --keep MYSQL_PORT \
      --keep POSTGRES_HOST --keep POSTGRES_PORT \
      --keep TEST_GOOGLE_OAUTH_CLIENT_ID \
      --keep TEST_GOOGLE_OAUTH_CLIENT_SECRET \
      --keep TEST_GOOGLE_OAUTH_REFRESH_TOKEN \
      --keep GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY"
  ;;
package)
  case "$PACKAGE_TYPE" in
  deb)
    SCRIPT="$REPO_ROOT/nix/package_deb.sh"
    ;;
  rpm)
    SCRIPT="$REPO_ROOT/nix/package_rpm.sh"
    ;;
  dmg)
    SCRIPT="$REPO_ROOT/nix/package_dmg.sh"
    ;;
  *)
    echo "Error: Unknown package type '$PACKAGE_TYPE'" >&2
    echo "Valid types: deb, rpm, dmg" >&2
    usage
    ;;
  esac
  KEEP_VARS="--keep DEBUG_OR_RELEASE --keep FEATURES"
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
# On macOS, DMG packaging requires system utilities (sw_vers, etc.) that aren't available in pure mode
# So we skip --pure for DMG packages on Darwin
if [ "$COMMAND" = "package" ] && [ "$PACKAGE_TYPE" = "dmg" ] && [ "$(uname)" = "Darwin" ]; then
  echo "Note: Running without --pure mode on macOS for DMG packaging (requires system utilities)"
  # shellcheck disable=SC2086
  nix-shell -I "nixpkgs=${PINNED_NIXPKGS_URL}" "$REPO_ROOT/shell.nix" \
    $KEEP_VARS \
    --run "bash '$SCRIPT' $*"
else
  # shellcheck disable=SC2086
  nix-shell -I "nixpkgs=${PINNED_NIXPKGS_URL}" $EXTRA_NIX_PKGS "$REPO_ROOT/shell.nix" --pure \
    $KEEP_VARS \
    --run "bash '$SCRIPT' $*"
fi

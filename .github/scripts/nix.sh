#!/usr/bin/env bash
# Unified entrypoint to run nix-shell commands: build, test, or packages
set -euo pipefail

# Display usage information
usage() {
  cat <<EOF
Usage: $0 <command> [subcommand]

Commands:
  build              Build the KMS server inside nix-shell
  test [type] [args] Run specific tests inside nix-shell
    sqlite                 Run SQLite tests (default; used when no type is provided)
    mysql                  Run MySQL tests (requires MySQL server)
    psql                   Run PostgreSQL tests (requires PostgreSQL server)
    redis                  Run Redis-findex tests (requires Redis server, non-FIPS only)
    google_cse             Run Google CSE tests (requires credentials)
    hsm [backend]          Run HSM tests (Linux only)
                           backend: softhsm2 | utimaco | all (default)
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
  $0 test                    # defaults to sqlite
  $0 test sqlite
  $0 test mysql
  FEATURES=non-fips $0 test redis
  $0 test hsm                 # both SoftHSM2 + Utimaco
  $0 test hsm softhsm2        # SoftHSM2 only
  $0 test hsm utimaco         # Utimaco only
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
    # Default to sqlite when no type is provided
    TEST_TYPE="sqlite"
  else
    TEST_TYPE="$1"
    shift
  fi
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

# Flag extra tools for nix-shell through environment (avoids mixing -p with shell.nix)
if [ "$COMMAND" = "test" ]; then
  export WITH_WGET=1
fi

# Determine repository root
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"

# Validate command and corresponding script
case "$COMMAND" in
build)
  SCRIPT="$REPO_ROOT/nix/scripts/build.sh"
  KEEP_VARS="--keep DEBUG_OR_RELEASE --keep FEATURES"
  ;;
test)
  case "$TEST_TYPE" in
  sqlite)
    SCRIPT="$REPO_ROOT/nix/scripts/test_sqlite.sh"
    ;;
  mysql)
    SCRIPT="$REPO_ROOT/nix/scripts/test_mysql.sh"
    ;;
  psql)
    SCRIPT="$REPO_ROOT/nix/scripts/test_psql.sh"
    ;;
  redis)
    SCRIPT="$REPO_ROOT/nix/scripts/test_redis.sh"
    ;;
  google_cse)
    SCRIPT="$REPO_ROOT/nix/scripts/test_google_cse.sh"
    # Validate required Google OAuth credentials before entering nix-shell
    for var in TEST_GOOGLE_OAUTH_CLIENT_ID TEST_GOOGLE_OAUTH_CLIENT_SECRET \
      TEST_GOOGLE_OAUTH_REFRESH_TOKEN GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY; do
      if [ -z "${!var:-}" ]; then
        echo "Error: Required environment variable $var is not set" >&2
        echo "Google CSE tests require valid OAuth credentials." >&2
        echo "Please set the following environment variables:" >&2
        echo "  - TEST_GOOGLE_OAUTH_CLIENT_ID" >&2
        echo "  - TEST_GOOGLE_OAUTH_CLIENT_SECRET" >&2
        echo "  - TEST_GOOGLE_OAUTH_REFRESH_TOKEN" >&2
        echo "  - GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY" >&2
        exit 1
      fi
    done
    ;;
  hsm)
    # Optional backend argument: softhsm2 | utimaco | all (default)
    HSM_BACKEND="${1:-all}"
    case "$HSM_BACKEND" in
    all | both)
      SCRIPT="$REPO_ROOT/nix/scripts/test_hsm.sh"
      ;;
    softhsm2)
      SCRIPT="$REPO_ROOT/nix/scripts/test_hsm_softhsm2.sh"
      shift
      ;;
    utimaco)
      SCRIPT="$REPO_ROOT/nix/scripts/test_hsm_utimaco.sh"
      shift
      ;;
    *)
      echo "Error: Unknown HSM backend '$HSM_BACKEND'" >&2
      echo "Valid backends for 'hsm': softhsm2, utimaco, all" >&2
      usage
      ;;
    esac
    ;;
  *)
    echo "Error: Unknown test type '$TEST_TYPE'" >&2
    echo "Valid types: sqlite, mysql, psql, redis, google_cse, hsm [softhsm2|utimaco|all]" >&2
    usage
    ;;
  esac
  # Signal to shell.nix to include extra tools for tests (wget, softhsm2, psmisc)
  if [ "$TEST_TYPE" = "hsm" ]; then
    export WITH_HSM=1
  fi
  KEEP_VARS="--keep DEBUG_OR_RELEASE --keep FEATURES \
      --keep REDIS_HOST --keep REDIS_PORT \
      --keep MYSQL_HOST --keep MYSQL_PORT \
      --keep POSTGRES_HOST --keep POSTGRES_PORT \
      --keep TEST_GOOGLE_OAUTH_CLIENT_ID \
      --keep TEST_GOOGLE_OAUTH_CLIENT_SECRET \
      --keep TEST_GOOGLE_OAUTH_REFRESH_TOKEN \
      --keep GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY \
      --keep WITH_WGET \
      --keep WITH_HSM"
  ;;
package)
  case "$PACKAGE_TYPE" in
  deb)
    SCRIPT="$REPO_ROOT/nix/scripts/package_deb.sh"
    ;;
  rpm)
    SCRIPT="$REPO_ROOT/nix/scripts/package_rpm.sh"
    ;;
  dmg)
    SCRIPT="$REPO_ROOT/nix/scripts/package_dmg.sh"
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
  nix-shell -I "nixpkgs=${PINNED_NIXPKGS_URL}" $KEEP_VARS "$REPO_ROOT/shell.nix" \
    --run "bash '$SCRIPT' $*"
else
  # For HSM tests we need access to system libraries (e.g., vendor PKCS#11, OpenSSL)
  # Run without --pure to allow system runtime resolution while keeping our pinned nix inputs
  if [ "$COMMAND" = "test" ] && [ "$TEST_TYPE" = "hsm" ]; then
    echo "Note: Running without --pure mode for HSM tests to allow system PKCS#11/runtime libraries"
    # shellcheck disable=SC2086
    nix-shell -I "nixpkgs=${PINNED_NIXPKGS_URL}" $KEEP_VARS "$REPO_ROOT/shell.nix" \
      --run "bash '$SCRIPT' $*"
  else
    # shellcheck disable=SC2086
    nix-shell -I "nixpkgs=${PINNED_NIXPKGS_URL}" --pure $KEEP_VARS "$REPO_ROOT/shell.nix" \
      --run "bash '$SCRIPT' $*"
  fi
fi

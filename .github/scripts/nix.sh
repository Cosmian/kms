#!/usr/bin/env bash
# Unified entrypoint to run nix-shell commands: build, test, or packages
set -euo pipefail

# Source shared helpers and unified pins
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

# Ensure SDKROOT is set on macOS for link steps.
ensure_macos_sdk_env

# Display usage information
usage() {
  cat <<EOF

  Commands:
    docker [--force] [--load] [--test]
                       Build Docker image tarball (static OpenSSL)
                       --force: Force rebuild image tarball, do not reuse cache
                       --load: Load image into Docker
                       --test: Run test_docker_image.sh after loading
    test [type] [args] Run tests inside nix-shell
      all                    Run all available tests (default)
      sqlite                 Run SQLite tests
      mysql                  Run MySQL tests (requires MySQL server)
      percona                Run Percona XtraDB Cluster tests (requires Percona server)
      mariadb                Run MariaDB tests (requires MariaDB server)
      psql                   Run PostgreSQL tests (requires PostgreSQL server)
      redis                  Run Redis-findex tests (requires Redis server, non-FIPS only)
      google_cse             Run Google CSE tests (requires credentials)
      pykmip                 Run PyKMIP client tests against a running KMS (non-FIPS)
      hsm [backend]          Run HSM tests (Linux only)
                             backend: softhsm2 | utimaco | proteccio | all (default)
    package [type]
                       Build package(s) via Nix
      deb              Build Debian package
      rpm              Build RPM package
      dmg              Build macOS DMG package
      (no type)        Build all supported packages on this platform
    sbom [options]     Generate comprehensive SBOM (Software Bill of Materials)
                       with full dependency graphs (runtime and buildtime)
                       Options:
                         --target <openssl|server>  Choose SBOM target (default: openssl)
    update-hashes [options]
               Update expected hashes for current platform (release profile mandatory)
      --variant <fips|non-fips>  Update specific variant (default: fips)
      --link <static|dynamic>    Limit to a specific server linkage (default: both)

  Global options:
    -p, --profile <debug|release>   Build/test profile (default: debug for build/test; release for package)
    -v, --variant <fips|non-fips>   Cryptographic variant (default: fips)
    -l, --link <static|dynamic>     OpenSSL linkage type (default: static)
                    static: statically link OpenSSL 3.6.0
                    dynamic: dynamically link system OpenSSL

  For testing, also supports environment variables:
    REDIS_HOST, REDIS_PORT
    MYSQL_HOST, MYSQL_PORT
    PERCONA_HOST, PERCONA_PORT
    MARIADB_HOST, MARIADB_PORT
    POSTGRES_HOST, POSTGRES_PORT
    TEST_GOOGLE_OAUTH_CLIENT_ID, TEST_GOOGLE_OAUTH_CLIENT_SECRET
    TEST_GOOGLE_OAUTH_REFRESH_TOKEN, GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY

  Examples:
    $0 docker --variant non-fips --load
    $0 docker --variant fips --load --test
    $0 --variant non-fips docker --force --load --test
    $0 test                    # defaults to all
    $0 test all
    $0 test sqlite
    $0 test mysql
    $0 test percona
    $0 test mariadb
    $0 --variant non-fips test redis
    $0 --variant non-fips test pykmip     # PyKMIP client tests
    $0 test hsm                 # both SoftHSM2 + Utimaco + Proteccio
    $0 test hsm softhsm2        # SoftHSM2 only
    $0 test hsm utimaco         # Utimaco only
    $0 test hsm proteccio       # Proteccio only
    $0 package                              # Build all packages for this OS
    $0 package deb                          # FIPS variant
    $0 --variant non-fips package deb       # non-FIPS variant
    $0 --variant non-fips package rpm       # non-FIPS variant
    $0 --variant non-fips package dmg       # non-FIPS variant
    $0 sbom                                 # Generate SBOM (OpenSSL by default)
    $0 sbom --target openssl                # SBOM for OpenSSL 3.1.2
    $0 sbom --target server                 # SBOM for KMS server (fips, static OpenSSL)
    $0 update-hashes                        # Update (server+ui, fips, static+dynamic)
EOF
  exit 1
}

# Default options
PROFILE="debug"
VARIANT="fips"
LINK="static"
# Hash update tuning flags removed (no longer used)

# Parse global options before the subcommand
while [ $# -gt 0 ]; do
  case "$1" in
  -p | --profile)
    PROFILE="${2:-}"
    shift 2 || true
    ;;
  -v | --variant)
    VARIANT="${2:-}"
    VARIANT_EXPLICIT=1
    shift 2 || true
    ;;
  -l | --link)
    LINK="${2:-}"
    LINK_EXPLICIT=1
    shift 2 || true
    ;;
  docker | test | package | sbom | update-hashes)
    COMMAND="$1"
    shift
    break
    ;;
  -h | --help)
    usage
    ;;
  *)
    # Stop at first non-option token if command already provided
    if [ -n "${COMMAND:-}" ]; then
      break
    fi
    echo "Unknown option: $1" >&2
    usage
    ;;
  esac
done

# Validate command argument
[ -z "${COMMAND:-}" ] && usage

# Export variables so they can be kept by nix-shell --keep
export PROFILE VARIANT LINK

# Handle test subcommand
TEST_TYPE=""
if [ "$COMMAND" = "test" ]; then
  if [ $# -eq 0 ]; then
    # Default to all when no type is provided
    TEST_TYPE="all"
  else
    TEST_TYPE="$1"
    shift
  fi
fi

# Handle package subcommand (type is optional; if omitted, build all for platform)
PACKAGE_TYPE=""
if [ "$COMMAND" = "package" ]; then
  if [ $# -ge 1 ]; then
    PACKAGE_TYPE="$1"
    shift
  fi
fi

# Flag extra tools for nix-shell through environment (avoids mixing -p with shell.nix)
if [ "$COMMAND" = "test" ]; then
  export WITH_WGET=1
fi

# Determine repository root
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO_ROOT"

# Compute a SHA-256 for a given file using the best available tool
compute_sha256() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

# Validate command and corresponding script
case "$COMMAND" in
docker)
  # Build Docker image(s) via Nix attributes; optionally docker load and/or test
  # Allow flags after subcommand: --variant/--load/--test (docker is always static-linked)
  DOCKER_VARIANT="$VARIANT"
  DOCKER_LINK="static"
  DOCKER_LOAD=false
  DOCKER_TEST=false
  DOCKER_FORCE=false
  while [ $# -gt 0 ]; do
    case "$1" in
    -v | --variant)
      DOCKER_VARIANT="${2:-}"
      shift 2 || true
      ;;
    --force)
      DOCKER_FORCE=true
      shift
      ;;
    --load)
      DOCKER_LOAD=true
      shift
      ;;
    --test)
      DOCKER_TEST=true
      DOCKER_LOAD=true # Testing requires loading the image
      shift
      ;;
    --)
      shift
      break
      ;;
    *)
      # Unrecognized; stop parsing for docker
      break
      ;;
    esac
  done

  case "$DOCKER_VARIANT" in
  fips | non-fips) : ;;
  *)
    echo "Error: --variant must be 'fips' or 'non-fips'" >&2
    exit 1
    ;;
  esac

  # Use unified pinned nixpkgs (from common.sh)

  # Map variant to attribute (docker is always static-linked)
  ATTR="docker-image-$DOCKER_VARIANT"

  # Extract version from Cargo.toml
  VERSION=$(bash "$REPO_ROOT/nix/scripts/get_version.sh")

  OUT_LINK="$REPO_ROOT/result-docker-$DOCKER_VARIANT-$DOCKER_LINK"
  # Backward compatibility: environment variable still honored if set
  if [ -n "${FORCE_REBUILD:-}" ]; then
    DOCKER_FORCE=true
  fi

  # Reuse existing tarball if present unless forced rebuild is requested
  if [ "$DOCKER_FORCE" != true ] && [ -L "$OUT_LINK" ] && REAL_OUT=$(readlink -f "$OUT_LINK" || true) && [ -f "$REAL_OUT" ]; then
    echo "Reusing existing Docker image tarball at: $REAL_OUT (use --force to rebuild)"
  else
    echo "Building Docker image: attr=$ATTR -> $OUT_LINK"
    nix-build -I "nixpkgs=${PIN_URL}" -A "$ATTR" -o "$OUT_LINK"
    REAL_OUT=$(readlink -f "$OUT_LINK" || echo "$OUT_LINK")
    echo "Built Docker image tarball: $REAL_OUT"
  fi

  if [ "$DOCKER_LOAD" = true ]; then
    if command -v docker >/dev/null 2>&1; then
      echo "Loading image into Docker (from $REAL_OUT)…"
      docker load <"$REAL_OUT"

      # Run tests if requested
      if [ "$DOCKER_TEST" = true ]; then
        echo "Running Docker image tests..."
        export DOCKER_IMAGE_NAME="cosmian-kms:${VERSION}-${DOCKER_VARIANT}"
        bash "$REPO_ROOT/.github/scripts/test_docker_image.sh"
      fi
    else
      echo "Warning: docker CLI not found; skipping --load" >&2
    fi
  fi

  exit 0
  ;;
test)
  case "$TEST_TYPE" in
  all)
    SCRIPT="$REPO_ROOT/.github/scripts/test_all.sh"
    ;;
  wasm)
    SCRIPT="$REPO_ROOT/.github/scripts/test_wasm.sh"
    ;;
  sqlite)
    SCRIPT="$REPO_ROOT/.github/scripts/test_sqlite.sh"
    ;;
  mysql)
    SCRIPT="$REPO_ROOT/.github/scripts/test_mysql.sh"
    ;;
  percona)
    SCRIPT="$REPO_ROOT/.github/scripts/test_percona.sh"
    ;;
  mariadb)
    SCRIPT="$REPO_ROOT/.github/scripts/test_maria.sh"
    ;;
  psql)
    SCRIPT="$REPO_ROOT/.github/scripts/test_psql.sh"
    ;;
  redis)
    SCRIPT="$REPO_ROOT/.github/scripts/test_redis.sh"
    ;;
  google_cse)
    SCRIPT="$REPO_ROOT/.github/scripts/test_google_cse.sh"
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
  pykmip)
    SCRIPT="$REPO_ROOT/.github/scripts/test_pykmip.sh"
    ;;
  hsm)
    # Optional backend argument: softhsm2 | utimaco | proteccio | all (default)
    HSM_BACKEND="${1:-all}"
    case "$HSM_BACKEND" in
    all)
      SCRIPT="$REPO_ROOT/.github/scripts/test_hsm.sh"
      ;;
    softhsm2)
      SCRIPT="$REPO_ROOT/.github/scripts/test_hsm_softhsm2.sh"
      shift
      ;;
    utimaco)
      SCRIPT="$REPO_ROOT/.github/scripts/test_hsm_utimaco.sh"
      shift
      ;;
    proteccio)
      SCRIPT="$REPO_ROOT/.github/scripts/test_hsm_proteccio.sh"
      shift
      ;;
    *)
      echo "Error: Unknown HSM backend '$HSM_BACKEND'" >&2
      echo "Valid backends for 'hsm': softhsm2, utimaco, proteccio, all" >&2
      usage
      ;;
    esac
    ;;
  *)
    echo "Error: Unknown test type '$TEST_TYPE'" >&2
    echo "Valid types: sqlite, mysql, psql, redis, google_cse, pykmip, hsm [softhsm2|utimaco|proteccio|all]" >&2
    usage
    ;;
  esac
  # Signal to shell.nix to include extra tools for tests (wget, softhsm2, psmisc)
  if [ "$TEST_TYPE" = "hsm" ] || [ "$TEST_TYPE" = "all" ]; then
    export WITH_HSM=1
  fi
  # For PyKMIP tests, ensure Python tooling is present inside the Nix shell
  if [ "$TEST_TYPE" = "pykmip" ]; then
    export WITH_PYTHON=1
  fi
  KEEP_VARS=" \
        --keep REDIS_HOST --keep REDIS_PORT \
        --keep MYSQL_HOST --keep MYSQL_PORT \
        --keep POSTGRES_HOST --keep POSTGRES_PORT \
      --keep VARIANT \
        --keep TEST_GOOGLE_OAUTH_CLIENT_ID \
        --keep TEST_GOOGLE_OAUTH_CLIENT_SECRET \
        --keep TEST_GOOGLE_OAUTH_REFRESH_TOKEN \
        --keep GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY \
        --keep WITH_WGET \
        --keep WITH_HSM \
          --keep WITH_PYTHON \
          --keep VARIANT \
          --keep LINK \
          --keep BUILD_PROFILE"
  ;;
package)
  # Prefer Nix derivations (nix/package.nix) over shell scripts
  case "$VARIANT" in
  fips | non-fips) : ;;
  *)
    echo "Error: --variant must be 'fips' or 'non-fips'" >&2
    exit 1
    ;;
  esac
  case "$PACKAGE_TYPE" in
  "" | deb | rpm | dmg)
    :
    ;;
  *)
    echo "Error: Unknown package type '$PACKAGE_TYPE'" >&2
    echo "Valid types: deb, rpm, dmg or leave empty to build all" >&2
    usage
    ;;
  esac

  # Special-case: On macOS, DMG packaging needs system tools (hdiutil, osascript).
  # Run inside nix-shell (non-pure) to keep access to system utilities and still use cargo-packager.
  if [ "$(uname)" = "Darwin" ]; then
    # Build only DMG on macOS when no type specified
    if [ -z "$PACKAGE_TYPE" ]; then
      PACKAGE_TYPE="dmg"
    fi
    if [ "$PACKAGE_TYPE" = "dmg" ]; then
      SCRIPT="$REPO_ROOT/nix/scripts/package_dmg.sh"
      KEEP_VARS=""
      echo "Note: Building DMG via nix-shell to allow macOS system tools (cargo-packager path)."
      # Run without --pure to preserve access to /usr/bin tools
      # Use unified pinned nixpkgs (from common.sh)
      # shellcheck disable=SC2086
      nix-shell -I "nixpkgs=${PIN_URL}" $KEEP_VARS --argstr variant "$VARIANT" "$REPO_ROOT/shell.nix" \
        --run "bash '$SCRIPT' --variant '$VARIANT' --link '$LINK'"
      # After packaging, compute checksum for the produced DMG (if present)
      OUT_DIR="$REPO_ROOT/result-dmg-$VARIANT-$LINK"
      dmg_file=$(find "$OUT_DIR" -maxdepth 1 -type f -name '*.dmg' | head -n1 || true)
      if [ -n "${dmg_file:-}" ] && [ -f "$dmg_file" ]; then
        if command -v shasum >/dev/null 2>&1; then
          sum=$(shasum -a 256 "$dmg_file" | awk '{print $1}')
        else
          sum=$(sha256sum "$dmg_file" | awk '{print $1}')
        fi
        echo "$sum  $(basename "$dmg_file")" >"$dmg_file.sha256"
        echo "Wrote checksum: $dmg_file.sha256 ($sum)"
      fi
      exit 0
    fi
  fi
  ;;
sbom)
  # SBOM generation using sbomnix - runs OUTSIDE nix-shell
  # sbomnix needs direct access to nix-store and nix commands
  SCRIPT="$REPO_ROOT/nix/scripts/generate_sbom.sh"
  echo "Running SBOM generation (not in nix-shell - sbomnix needs nix commands)..."
  # Pass resolved global flags so variant/link are honored
  bash "$SCRIPT" --variant "$VARIANT" --link "$LINK" "$@"
  exit $?
  ;;
update-hashes)
  # Run automated hash update across all variant/link combinations
  SCRIPT="$REPO_ROOT/.github/scripts/update_hashes.sh"
  [ -f "$SCRIPT" ] || {
    echo "Missing $SCRIPT" >&2
    exit 1
  }
  bash "$SCRIPT"
  exit $?
  ;;
*)
  echo "Error: Unknown command '$COMMAND'" >&2
  usage
  ;;
esac

# Ensure <nixpkgs> lookups work even if NIX_PATH is unset (common on CI)
# Pin to the same nixpkgs as shell.nix to keep environments consistent
PINNED_NIXPKGS_URL="$PIN_URL"
if [ -z "${NIX_PATH:-}" ]; then
  export NIX_PATH="nixpkgs=${PINNED_NIXPKGS_URL}"
fi

# Resolve pinned nixpkgs to a local store path so later -I uses do not hit the network.
resolve_pinned_nixpkgs_store() {
  # Try nix (new) first, fallback to nix-instantiate
  local path
  if path=$(nix eval --raw "(builtins.fetchTarball \"${PINNED_NIXPKGS_URL}\")" 2>/dev/null); then
    :
  else
    # nix-instantiate returns a quoted string; strip quotes
    path=$(nix-instantiate --eval -E "builtins.fetchTarball { url = \"${PINNED_NIXPKGS_URL}\"; }" | sed -e 's/\"//g') || path=""
  fi
  if [ -n "$path" ] && [ -e "$path" ]; then
    echo "$path"
    return 0
  fi
  return 1
}

# Optionally prewarm nixpkgs and smoke-test tools into the store (online phase)
prewarm_nixpkgs_and_tools() {
  # Skip if explicitly disabled
  if [ -n "${NO_PREWARM:-}" ]; then
    echo "Skipping prewarm (NO_PREWARM set)"
    return 0
  fi
  echo "Prewarming pinned nixpkgs into the store…"
  # Evaluate fetchTarball to realize nixpkgs tarball in store
  if ! resolve_pinned_nixpkgs_store >/dev/null; then
    # Trigger realization via eval to fetch the tarball
    nix-instantiate --eval -E "builtins.fetchTarball { url = \"${PINNED_NIXPKGS_URL}\"; }" >/dev/null
  fi
  local NIXPKGS_STORE
  NIXPKGS_STORE=$(resolve_pinned_nixpkgs_store || true)
  if [ -n "$NIXPKGS_STORE" ]; then
    export NIXPKGS_STORE
    echo "Pinned nixpkgs realized at: $NIXPKGS_STORE"
    # Prewarm tools used later by nix-shell -p during smoke tests so offline works
    if [ "$(uname)" = "Linux" ]; then
      echo "Prewarming dpkg/rpm/cpio/curl into the store…"
      # These may download from cache or build; okay during online prewarm
      nix-build -I "nixpkgs=${NIXPKGS_STORE}" -E 'with import <nixpkgs> {}; dpkg' --no-out-link >/dev/null 2>/dev/null || true
      nix-build -I "nixpkgs=${NIXPKGS_STORE}" -E 'with import <nixpkgs> {}; rpm' --no-out-link >/dev/null 2>/dev/null || true
      nix-build -I "nixpkgs=${NIXPKGS_STORE}" -E 'with import <nixpkgs> {}; cpio' --no-out-link >/dev/null 2>/dev/null || true
      nix-build -I "nixpkgs=${NIXPKGS_STORE}" -E 'with import <nixpkgs> {}; curl.bin' --no-out-link >/dev/null 2>/dev/null ||
        nix-build -I "nixpkgs=${NIXPKGS_STORE}" -E 'with import <nixpkgs> {}; curl' --no-out-link >/dev/null 2>/dev/null || true
    fi
  fi
}

# If packaging, build directly via Nix attributes and exit (no shell wrapper)
if [ "$COMMAND" = "package" ]; then
  # Determine which package types to build
  if [ -z "$PACKAGE_TYPE" ]; then
    if [ "$(uname)" = "Darwin" ]; then
      TYPES="dmg"
    else
      # Linux and others: DEB and RPM
      TYPES="deb rpm"
    fi
  else
    TYPES="$PACKAGE_TYPE"
  fi

  # Prewarm nixpkgs and base tools once per packaging invocation (if not disabled)
  prewarm_nixpkgs_and_tools || true
  NIXPKGS_STORE="${NIXPKGS_STORE:-}"
  # Prefer store path over URL for -I nixpkgs to avoid network usage offline
  NIXPKGS_ARG="$PINNED_NIXPKGS_URL"
  if [ -n "$NIXPKGS_STORE" ] && [ -e "$NIXPKGS_STORE" ]; then
    NIXPKGS_ARG="$NIXPKGS_STORE"
  fi

  # Build all combinations only when:
  # 1. No package type specified (packaging all types for the platform)
  # 2. User didn't explicitly override --variant or --link (used defaults)
  # To detect explicit user choice, we track if flags were actually provided
  VARIANTS_TO_BUILD=("$VARIANT")
  LINKS_TO_BUILD=("$LINK")

  # Only build all combinations if BOTH conditions are true:
  # - No specific package type requested
  # - User didn't override defaults (variant=fips AND link=static)
  # Note: This means "package" with no type builds all, but "package deb" builds only what's specified
  if [ -z "$PACKAGE_TYPE" ] && [ "$VARIANT" = "fips" ] && [ "$LINK" = "static" ] && [ -z "${VARIANT_EXPLICIT:-}" ] && [ -z "${LINK_EXPLICIT:-}" ]; then
    VARIANTS_TO_BUILD=("fips" "non-fips")
    LINKS_TO_BUILD=("static" "dynamic")
  fi

  for BUILD_VARIANT in "${VARIANTS_TO_BUILD[@]}"; do
    for BUILD_LINK in "${LINKS_TO_BUILD[@]}"; do
      echo "=========================================="
      echo "Building packages for variant=$BUILD_VARIANT, link=$BUILD_LINK"
      echo "=========================================="

      for TYPE in $TYPES; do
        case "$TYPE" in
        deb)
          if [ "$(uname)" = "Linux" ]; then
            SCRIPT_LINUX="$REPO_ROOT/nix/scripts/package_deb.sh"
            [ -f "$SCRIPT_LINUX" ] || {
              echo "Missing $SCRIPT_LINUX" >&2
              exit 1
            }
            # Ensure required tools are available via a minimal nix-shell; remove NO_PREWARM default
            nix-shell -I "nixpkgs=${NIXPKGS_ARG}" -p curl --run "bash '$SCRIPT_LINUX' --variant '$BUILD_VARIANT' --link '$BUILD_LINK'"
            REAL_OUT="$REPO_ROOT/result-deb-$BUILD_VARIANT-$BUILD_LINK"
            echo "Built deb ($BUILD_VARIANT-$BUILD_LINK): $REAL_OUT"

            # Run smoke test on the generated .deb package
            echo "=========================================="
            echo "Running smoke test on .deb package..."
            echo "=========================================="
            DEB_FILE=$(find "$REAL_OUT" -maxdepth 1 -type f -name '*.deb' | head -n1 || true)
            if [ -n "$DEB_FILE" ] && [ -f "$DEB_FILE" ]; then
              SMOKE_TEST_SCRIPT="$REPO_ROOT/.github/scripts/smoke_test_deb.sh"
              if [ -f "$SMOKE_TEST_SCRIPT" ]; then
                # Run smoke test in a clean nix-shell to ensure no previous builds affect the test
                nix-shell -I "nixpkgs=${NIXPKGS_ARG}" -p binutils file coreutils --run "bash '$SMOKE_TEST_SCRIPT' '$DEB_FILE'" || {
                  echo "ERROR: Smoke test failed for $DEB_FILE" >&2
                  exit 1
                }
              else
                echo "Warning: Smoke test script not found at $SMOKE_TEST_SCRIPT" >&2
              fi
            else
              echo "Warning: .deb file not found in $REAL_OUT" >&2
            fi
          else
            echo "DEB packaging is only supported on Linux in this flow." >&2
            exit 1
          fi
          ;;
        rpm)
          if [ "$(uname)" = "Linux" ]; then
            SCRIPT_LINUX="$REPO_ROOT/nix/scripts/package_rpm.sh"
            [ -f "$SCRIPT_LINUX" ] || {
              echo "Missing $SCRIPT_LINUX" >&2
              exit 1
            }
            nix-shell -I "nixpkgs=${NIXPKGS_ARG}" -p curl --run "bash '$SCRIPT_LINUX' --variant '$BUILD_VARIANT' --link '$BUILD_LINK'"
            REAL_OUT="$REPO_ROOT/result-rpm-$BUILD_VARIANT-$BUILD_LINK"
            echo "Built rpm ($BUILD_VARIANT-$BUILD_LINK): $REAL_OUT"

            # Run smoke test on the generated RPM package
            echo "=========================================="
            echo "Running smoke test on RPM package..."
            echo "=========================================="
            RPM_FILE=$(find "$REAL_OUT" -maxdepth 1 -type f -name '*.rpm' | head -n1 || true)
            if [ -n "$RPM_FILE" ] && [ -f "$RPM_FILE" ]; then
              SMOKE_TEST_SCRIPT="$REPO_ROOT/.github/scripts/smoke_test_rpm.sh"
              if [ -f "$SMOKE_TEST_SCRIPT" ]; then
                # Run smoke test in a clean nix-shell to ensure no previous builds affect the test
                nix-shell -I "nixpkgs=${NIXPKGS_ARG}" -p binutils file coreutils rpm cpio --run "bash '$SMOKE_TEST_SCRIPT' '$RPM_FILE'" || {
                  echo "ERROR: Smoke test failed for $RPM_FILE" >&2
                  exit 1
                }
              else
                echo "Warning: Smoke test script not found at $SMOKE_TEST_SCRIPT" >&2
              fi
            else
              echo "Warning: RPM file not found in $REAL_OUT" >&2
            fi
          else
            echo "RPM packaging is only supported on Linux in this flow." >&2
            exit 1
          fi
          ;;
        dmg)
          # DMG only supports static for now (check if dynamic variant exists)
          if [ "$BUILD_LINK" = "dynamic" ]; then
            # Check if dynamic DMG attribute exists
            if nix-instantiate -A "kms-server-${BUILD_VARIANT}-dmg-dynamic" >/dev/null 2>&1; then
              ATTR="kms-server-${BUILD_VARIANT}-dmg-dynamic"
              OUT_LINK="$REPO_ROOT/result-dmg-$BUILD_VARIANT-$BUILD_LINK"
            else
              echo "Skipping dmg ($BUILD_VARIANT-dynamic): attribute not available" >&2
              continue
            fi
          else
            ATTR="kms-server-${BUILD_VARIANT}-dmg"
            OUT_LINK="$REPO_ROOT/result-dmg-$BUILD_VARIANT-$BUILD_LINK"
          fi
          nix-build -A "$ATTR" -o "$OUT_LINK"
          REAL_OUT=$(readlink -f "$OUT_LINK" || echo "$OUT_LINK")
          echo "Built dmg ($BUILD_VARIANT-$BUILD_LINK): $REAL_OUT"

          # Invoke DMG smoke test via nix.sh (in addition to any internal calls)
          DMG_FILE=$(find "$REAL_OUT" -maxdepth 1 -type f -name '*.dmg' | head -n1 || true)
          SMOKE_TEST_SCRIPT="$REPO_ROOT/.github/scripts/smoke_test_dmg.sh"
          if [ -n "$DMG_FILE" ] && [ -f "$DMG_FILE" ]; then
            if [ -f "$SMOKE_TEST_SCRIPT" ]; then
              echo "Running DMG smoke test for $DMG_FILE..."
              # Ensure we have macOS system tools; run outside pure shell
              bash "$SMOKE_TEST_SCRIPT" "$DMG_FILE" || {
                echo "ERROR: DMG smoke test failed for $DMG_FILE" >&2
                exit 1
              }
            else
              echo "Warning: Smoke test script not found at $SMOKE_TEST_SCRIPT" >&2
            fi
          else
            echo "Warning: DMG file not found in $REAL_OUT" >&2
          fi
          ;;
        *)
          echo "Skipping unsupported package type: $TYPE" >&2
          continue
          ;;
        esac

        # After successful smoke test (already run above), generate a .sha256 checksum file next to the artifact
        case "$TYPE" in
        deb)
          deb_file=$(find "$REAL_OUT" -maxdepth 1 -type f -name '*.deb' | head -n1 || true)
          if [ -n "${deb_file:-}" ] && [ -f "$deb_file" ]; then
            sum=$(compute_sha256 "$deb_file")
            echo "$sum  $(basename "$deb_file")" >"$deb_file.sha256"
            echo "Wrote checksum: $deb_file.sha256 ($sum)"
          fi
          ;;
        rpm)
          rpm_file=$(find "$REAL_OUT" -maxdepth 1 -type f -name '*.rpm' | head -n1 || true)
          if [ -n "${rpm_file:-}" ] && [ -f "$rpm_file" ]; then
            sum=$(compute_sha256 "$rpm_file")
            echo "$sum  $(basename "$rpm_file")" >"$rpm_file.sha256"
            echo "Wrote checksum: $rpm_file.sha256 ($sum)"
          fi
          ;;
        dmg)
          dmg_file=$(find "$REAL_OUT" -maxdepth 1 -type f -name '*.dmg' | head -n1 || true)
          if [ -n "${dmg_file:-}" ] && [ -f "$dmg_file" ]; then
            sum=$(compute_sha256 "$dmg_file")
            echo "$sum  $(basename "$dmg_file")" >"$dmg_file.sha256"
            echo "Wrote checksum: $dmg_file.sha256 ($sum)"
          fi
          ;;
        esac
      done # for TYPE in $TYPES
    done   # for BUILD_LINK
  done     # for BUILD_VARIANT

  exit 0
fi

# Check if script exists (build/test flows)
[ -f "$SCRIPT" ] || {
  echo "Missing $SCRIPT" >&2
  exit 1
}

# Check if shell.nix exists
[ -f "$REPO_ROOT/shell.nix" ] || {
  echo "Error: No shell.nix found at $REPO_ROOT" >&2
  exit 1
}

# Run the appropriate script inside nix-shell
# Determine if we should use --pure mode
USE_PURE=true

# On macOS, DMG packaging requires system utilities (hdiutil, sw_vers) not available in pure mode
if [ "$COMMAND" = "package" ] && [ "$PACKAGE_TYPE" = "dmg" ] && [ "$(uname)" = "Darwin" ]; then
  USE_PURE=false
  echo "Note: Running without --pure mode on macOS for DMG packaging (requires system utilities)"
fi

{
  # Decide purity and extra packages once, then run a single nix-shell
  PURE_FLAG="--pure"
  KEEP_ARGS="$KEEP_VARS"
  EXTRA_PKGS=""
  SHELL_PATH="$REPO_ROOT/shell.nix"

  # sbom always uses pure shell with variant/link only
  if [ "$COMMAND" = "sbom" ]; then
    PURE_FLAG="--pure"
    KEEP_ARGS="$KEEP_VARS"
    EXTRA_PKGS=""
  else
    # For wasm tests: use non-pure shell and inject nodejs + wasm-pack (retain system cargo/rustup)
    if [ "$COMMAND" = "test" ] && [ "$TEST_TYPE" = "wasm" ]; then
      PURE_FLAG="" # non-pure
      KEEP_ARGS="" # avoid mixing --keep with -p
      EXTRA_PKGS="-p nodejs wasm-pack"
      SHELL_PATH="<nixpkgs>" # run a minimal shell when using -p packages
    else
      # Otherwise respect computed USE_PURE setting
      if [ "$USE_PURE" = true ]; then
        PURE_FLAG="--pure"
        KEEP_ARGS="$KEEP_VARS"
      else
        PURE_FLAG=""
        KEEP_ARGS="$KEEP_VARS"
      fi
    fi
  fi

  # Build command to run inside nix-shell
  # Export VARIANT, LINK, and BUILD_PROFILE before the command so shellHook can see them
  if [ "$COMMAND" = "sbom" ]; then
    CMD="export VARIANT='$VARIANT' LINK='$LINK' BUILD_PROFILE='$PROFILE'; bash '$SCRIPT' --variant '$VARIANT' --link '$LINK'"
  else
    CMD="export VARIANT='$VARIANT' LINK='$LINK' BUILD_PROFILE='$PROFILE'; bash '$SCRIPT' --profile '$PROFILE' --variant '$VARIANT' --link '$LINK'"
  fi

  ARGSTR_VARIANT=""
  if [ "$SHELL_PATH" = "$REPO_ROOT/shell.nix" ]; then
    ARGSTR_VARIANT="--argstr variant $VARIANT"
  fi
  # shellcheck disable=SC2086
  nix-shell -I "nixpkgs=${PINNED_NIXPKGS_URL}" $PURE_FLAG $KEEP_ARGS $EXTRA_PKGS $ARGSTR_VARIANT "$SHELL_PATH" --run "$CMD"
}

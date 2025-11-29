#!/usr/bin/env bash
# Unified entrypoint to run nix-shell commands: build, test, or packages
set -euo pipefail

# Source shared helpers and unified pins
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "$SCRIPT_DIR/common.sh"

# Display usage information
usage() {
  cat <<EOF

  Commands:
    build              Build the KMS server inside nix-shell
    docker [--load]    Build Docker image tarball (static OpenSSL; optional load)
    test [type] [args] Run tests inside nix-shell
      all                    Run all available tests (default)
      sqlite                 Run SQLite tests
      mysql                  Run MySQL tests (requires MySQL server)
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
    update-hashes [options]
                       Update expected hashes for current platform
      --vendor-only          Only update Cargo vendor hashes (server + UI)
      --npm-only             Only update NPM dependencies hash
      --binary-only          Only update binary hashes (after code changes)
      --variant <fips|non-fips>  Update specific variant (default: both)
      (no options)           Update all hashes (vendor + npm + binaries)

  Global options:
    -p, --profile <debug|release>   Build/test profile (default: debug for build/test; release for package)
    -v, --variant <fips|non-fips>   Cryptographic variant (default: fips)
    -l, --link <static|dynamic>     OpenSSL linkage type (default: static)
                                    static: statically link OpenSSL 3.1.2
                                    dynamic: dynamically link system OpenSSL

  For testing, also supports environment variables:
    REDIS_HOST, REDIS_PORT
    MYSQL_HOST, MYSQL_PORT
    POSTGRES_HOST, POSTGRES_PORT
    TEST_GOOGLE_OAUTH_CLIENT_ID, TEST_GOOGLE_OAUTH_CLIENT_SECRET
    TEST_GOOGLE_OAUTH_REFRESH_TOKEN, GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY

  Examples:
    $0 build --profile release --variant non-fips
    $0 docker --variant non-fips --load
    $0 test                    # defaults to all
    $0 test all
    $0 test sqlite
    $0 test mysql
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
    $0 sbom                                 # Generate SBOM for FIPS variant
    $0 --variant non-fips sbom              # Generate SBOM for non-FIPS variant
    $0 update-hashes                        # Update all hashes for current platform
    $0 update-hashes --vendor-only          # Update only Cargo vendor hashes (server + UI)
    $0 update-hashes --npm-only             # Update only NPM dependencies hash
    $0 update-hashes --binary-only          # Update only binary hashes
    $0 update-hashes --variant non-fips     # Update only non-FIPS variant hashes
EOF
  exit 1
}

# Default options
PROFILE="debug"
VARIANT="fips"
LINK="static"

# Parse global options before the subcommand
while [ $# -gt 0 ]; do
  case "$1" in
  -p | --profile)
    PROFILE="${2:-}"
    shift 2 || true
    ;;
  -v | --variant)
    VARIANT="${2:-}"
    shift 2 || true
    ;;
  -l | --link)
    LINK="${2:-}"
    shift 2 || true
    ;;
  build | docker | test | package | sbom | update-hashes)
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
build)
  SCRIPT="$REPO_ROOT/nix/scripts/build.sh"
  KEEP_VARS=""
  ;;
docker)
  # Build Docker image(s) via Nix attributes; optionally docker load
  # Allow flags after subcommand: --variant/--load (docker is always static-linked)
  DOCKER_VARIANT="$VARIANT"
  DOCKER_LINK="static"
  DOCKER_LOAD=false
  while [ $# -gt 0 ]; do
    case "$1" in
    -v|--variant)
      DOCKER_VARIANT="${2:-}"
      shift 2 || true
      ;;
    --load)
      DOCKER_LOAD=true
      shift
      ;;
    --)
      shift; break
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

  OUT_LINK="$REPO_ROOT/result-docker-$DOCKER_VARIANT-$DOCKER_LINK"
  # Reuse existing tarball if present unless FORCE_REBUILD is set
  if [ -z "${FORCE_REBUILD:-}" ] && [ -L "$OUT_LINK" ] && REAL_OUT=$(readlink -f "$OUT_LINK" || true) && [ -f "$REAL_OUT" ]; then
    echo "Reusing existing Docker image tarball at: $REAL_OUT (set FORCE_REBUILD=1 to rebuild)"
  else
    echo "Building Docker image: attr=$ATTR -> $OUT_LINK"
    nix-build -I "nixpkgs=${PIN_URL}" -A "$ATTR" -o "$OUT_LINK"
    REAL_OUT=$(readlink -f "$OUT_LINK" || echo "$OUT_LINK")
    echo "Built Docker image tarball: $REAL_OUT"
  fi

  if [ "$DOCKER_LOAD" = true ]; then
    if command -v docker >/dev/null 2>&1; then
      echo "Loading image into Docker (from $REAL_OUT)…"
      docker load < "$REAL_OUT"
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
  sqlite)
    SCRIPT="$REPO_ROOT/.github/scripts/test_sqlite.sh"
    ;;
  mysql)
    SCRIPT="$REPO_ROOT/.github/scripts/test_mysql.sh"
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
        --keep TEST_GOOGLE_OAUTH_CLIENT_ID \
        --keep TEST_GOOGLE_OAUTH_CLIENT_SECRET \
        --keep TEST_GOOGLE_OAUTH_REFRESH_TOKEN \
        --keep GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY \
        --keep WITH_WGET \
        --keep WITH_HSM \
        --keep WITH_PYTHON"
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
      nix-shell -I "nixpkgs=${PIN_URL}" $KEEP_VARS "$REPO_ROOT/shell.nix" \
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
  bash "$SCRIPT" --variant "$VARIANT" "$@"
  exit $?
  ;;
update-hashes)
  # Hash update - delegate to standalone script
  echo "Delegating to nix/scripts/update_all_hashes.sh..."
  SCRIPT="$REPO_ROOT/nix/scripts/update_all_hashes.sh"

  # Pass through variant flag and all arguments
  if [ "$VARIANT" != "fips" ]; then
    exec bash "$SCRIPT" --variant "$VARIANT" "$@"
  else
    exec bash "$SCRIPT" "$@"
  fi
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

  # When PACKAGE_TYPE is empty, build all variants (fips/non-fips) and all link modes (static/dynamic)
  # When PACKAGE_TYPE is specified, use the provided VARIANT and LINK from command-line
  VARIANTS_TO_BUILD=("$VARIANT")
  LINKS_TO_BUILD=("$LINK")

  if [ -z "$PACKAGE_TYPE" ]; then
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
          ;;
        *)
          echo "Skipping unsupported package type: $TYPE" >&2
          continue
          ;;
        esac

        # Mandatory smoke test (fail hard if any smoke test fails)
        if ! (
          set -euo pipefail
          echo "Running smoke test for $TYPE ($BUILD_VARIANT-$BUILD_LINK)…"
          tmpdir=$(mktemp -d)
          # Cleanup this temp dir when this subshell exits
          trap 'chmod -R u+w "$tmpdir" 2>/dev/null || true; rm -rf "$tmpdir" 2>/dev/null || true' EXIT

          case "$TYPE" in
          deb)
            deb_file=$(find "$REAL_OUT" -maxdepth 1 -type f -name '*.deb' | head -n1)
            if [ -z "$deb_file" ]; then
              echo "Error: no .deb found in $REAL_OUT" >&2
              exit 1
            fi
            echo "Extracting $deb_file to $tmpdir"
            nix-shell -I "nixpkgs=${NIXPKGS_ARG}" -p dpkg --run "dpkg-deb -x '$deb_file' '$tmpdir'"
            ;;
          rpm)
            rpm_file=$(find "$REAL_OUT" -maxdepth 1 -type f -name '*.rpm' | head -n1)
            if [ -z "$rpm_file" ]; then
              echo "Error: no .rpm found in $REAL_OUT" >&2
              exit 1
            fi
            echo "Extracting $rpm_file to $tmpdir"
            nix-shell -I "nixpkgs=${NIXPKGS_ARG}" -p rpm cpio --run "cd '$tmpdir' && rpm2cpio '$rpm_file' | cpio -idmv"
            ;;
          dmg)
            echo "Skipping DMG smoke test on macOS."
            exit 0
            ;;
          esac

          BIN_PATH="$tmpdir/usr/bin/cosmian_kms"
          if [ ! -x "$BIN_PATH" ]; then BIN_PATH="$tmpdir/usr/sbin/cosmian_kms"; fi
          if [ ! -x "$BIN_PATH" ]; then BIN_PATH=$(find "$tmpdir/usr" -type f -name cosmian_kms | head -n1 || true); fi
          if [ -z "$BIN_PATH" ] || [ ! -x "$BIN_PATH" ]; then
            echo "Error: expected server binary not found under /usr/bin or /usr/sbin" >&2
            exit 1
          fi

          echo "Running cosmian_kms --info from extracted package…"
          INFO_OUT="$($BIN_PATH --info 2>&1)"
          STATUS=$?
          echo "$INFO_OUT"
          if [ $STATUS -ne 0 ]; then
            echo "Smoke test failed: exit $STATUS" >&2
            exit $STATUS
          fi
          echo "$INFO_OUT" | grep -q "OpenSSL 3\.1\.2" || {
            echo "Smoke test failed: expected OpenSSL 3.1.2" >&2
            exit 1
          }
          echo "Smoke test PASS"
        ); then
          echo "Smoke test FAILED for $TYPE ($BUILD_VARIANT-$BUILD_LINK)" >&2
          exit 1
        fi

        # After a successful smoke test, generate a .sha256 checksum file next to the artifact
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

# For HSM tests we need access to system libraries (e.g., vendor PKCS#11, OpenSSL)
if [ "$COMMAND" = "test" ] && { [ "$TEST_TYPE" = "hsm" ] || [ "$TEST_TYPE" = "all" ]; }; then
  USE_PURE=false
  echo "Note: Running without --pure mode for HSM tests to allow system PKCS#11/runtime libraries"
fi

if [ "$USE_PURE" = true ]; then
  # shellcheck disable=SC2086
  if [ "$COMMAND" = "sbom" ]; then
    nix-shell -I "nixpkgs=${PINNED_NIXPKGS_URL}" --pure $KEEP_VARS "$REPO_ROOT/shell.nix" \
      --run "bash '$SCRIPT' --variant '$VARIANT' $*"
  else
    nix-shell -I "nixpkgs=${PINNED_NIXPKGS_URL}" --pure $KEEP_VARS "$REPO_ROOT/shell.nix" \
      --run "bash '$SCRIPT' ${PROFILE:+--profile "$PROFILE"} --variant '$VARIANT' $*"
  fi
else
  # shellcheck disable=SC2086
  if [ "$COMMAND" = "sbom" ]; then
    nix-shell -I "nixpkgs=${PINNED_NIXPKGS_URL}" $KEEP_VARS "$REPO_ROOT/shell.nix" \
      --run "bash '$SCRIPT' --variant '$VARIANT' $*"
  else
    nix-shell -I "nixpkgs=${PINNED_NIXPKGS_URL}" $KEEP_VARS "$REPO_ROOT/shell.nix" \
      --run "bash '$SCRIPT' ${PROFILE:+--profile "$PROFILE"} --variant '$VARIANT' $*"
  fi
fi

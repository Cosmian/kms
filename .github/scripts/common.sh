#!/usr/bin/env bash
# Minimal shared helpers for packaging scripts (nix build) and smoke tests

set -euo pipefail

# Ensure macOS SDK path is available for the linker.
# Some build steps (notably during Rust linking) invoke `xcrun --sdk macosx --show-sdk-path`.
# On machines where `xcrun` isn't found (or isn't on PATH), linking fails because the SDK
# location cannot be discovered.
ensure_macos_sdk_env() {
  # No-op on non-macOS
  if [ "$(uname -s)" != "Darwin" ]; then
    return 0
  fi

  # Prefer Command Line Tools as a consistent developer root.
  # This also makes it much more likely that `xcrun` is discoverable.
  : "${DEVELOPER_DIR:=/Library/Developer/CommandLineTools}"
  export DEVELOPER_DIR
  if [ -d "${DEVELOPER_DIR}/usr/bin" ]; then
    case ":${PATH}:" in
    *":${DEVELOPER_DIR}/usr/bin:"*)
      :
      ;;
    *)
      export PATH="${DEVELOPER_DIR}/usr/bin:${PATH}"
      ;;
    esac
  fi

  # Respect caller-provided SDKROOT
  if [ -n "${SDKROOT:-}" ] && [ -d "${SDKROOT}" ]; then
    :
  else
    # Prefer xcrun when available
    if command -v xcrun >/dev/null 2>&1; then
      local sdk
      sdk="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
      if [ -n "$sdk" ] && [ -d "$sdk" ]; then
        export SDKROOT="$sdk"
      fi
    fi

    # Fallback: Command Line Tools SDK location (common on CI and minimal macOS setups)
    if [ -z "${SDKROOT:-}" ]; then
      local clt_sdk="/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk"
      if [ -d "$clt_sdk" ]; then
        export SDKROOT="$clt_sdk"
      fi
    fi
  fi

  # If we have an SDKROOT, ensure native C builds use it.
  # This is important for build scripts invoking clang directly (e.g., aws-lc-sys),
  # otherwise system headers like CoreServices may not be found.
  if [ -n "${SDKROOT:-}" ] && [ -d "${SDKROOT}" ]; then
    # When building inside a Nix shell on macOS, Nix may inject headers from its own
    # libSystem (e.g. via NIX_CFLAGS_COMPILE/CPATH). That can conflict with the Apple SDK
    # headers (CoreFoundation uses API_AVAILABLE macros), causing compilation failures.
    # For this repository, prefer the Apple SDK headers consistently.
    unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH
    unset NIX_CFLAGS_COMPILE NIX_CFLAGS_LINK NIX_LDFLAGS

    local sysroot_flag
    sysroot_flag="-isysroot ${SDKROOT}"

    local framework_dir
    framework_dir="${SDKROOT}/System/Library/Frameworks"
    local framework_flags=""
    if [ -d "${framework_dir}" ]; then
      # Some C dependencies include Apple framework headers (e.g. <CoreServices/CoreServices.h>).
      # Ensure clang can resolve those by providing framework search paths.
      framework_flags="-F${framework_dir} -iframework ${framework_dir}"
    fi

    if [ -n "${CFLAGS:-}" ]; then
      export CFLAGS="${sysroot_flag} ${framework_flags} ${CFLAGS}"
    else
      export CFLAGS="${sysroot_flag} ${framework_flags}"
    fi

    if [ -n "${CPPFLAGS:-}" ]; then
      export CPPFLAGS="${sysroot_flag} ${framework_flags} ${CPPFLAGS}"
    else
      export CPPFLAGS="${sysroot_flag} ${framework_flags}"
    fi

    if [ -n "${CXXFLAGS:-}" ]; then
      export CXXFLAGS="${sysroot_flag} ${framework_flags} ${CXXFLAGS}"
    else
      export CXXFLAGS="${sysroot_flag} ${framework_flags}"
    fi

    return 0
  fi
}

# Unified nixpkgs pin (used by all scripts)
# Keep a single source of truth for the pinned nixpkgs URL.
export PIN_URL="https://github.com/NixOS/nixpkgs/archive/24.05.tar.gz"
# Backward-compatible alias used by some scripts
export PINNED_NIXPKGS_URL="$PIN_URL"

# Initialize build/test configuration from CLI args
# Usage: init_build_env "$@"
# Exports:
#   VARIANT            fips | non-fips
#   VARIANT_NAME       FIPS | non-FIPS (pretty)
#   BUILD_PROFILE      debug | release
#   RELEASE_FLAG       "" | --release
#   FEATURES_FLAG      cargo feature array (non-fips -> --features non-fips)
#   LINK               static | dynamic (OpenSSL linkage type)
init_build_env() {
  local profile="debug" variant="fips" link="static"
  local profile_set=0 variant_set=0 link_set=0

  # Parse only our known flags; ignore/keep others for callers
  local i=1
  while [ $i -le $# ]; do
    case "${!i}" in
    --profile)
      if [ $profile_set -eq 1 ]; then
        echo "Error: --profile specified multiple times" >&2
        exit 1
      fi
      profile_set=1
      i=$((i + 1))
      profile="${!i:-}"
      ;;
    --variant)
      if [ $variant_set -eq 1 ]; then
        echo "Error: --variant specified multiple times" >&2
        exit 1
      fi
      variant_set=1
      i=$((i + 1))
      variant="${!i:-}"
      ;;
    --link)
      if [ $link_set -eq 1 ]; then
        echo "Error: --link specified multiple times" >&2
        exit 1
      fi
      link_set=1
      i=$((i + 1))
      link="${!i:-}"
      ;;
    esac
    i=$((i + 1))
  done

  # If flags were not provided, inherit from existing environment (when available)
  if [ $profile_set -eq 0 ] && [ -n "${BUILD_PROFILE:-}" ]; then
    case "${BUILD_PROFILE}" in
    release | debug) profile="${BUILD_PROFILE}" ;;
    esac
  fi
  if [ $variant_set -eq 0 ] && [ -n "${VARIANT:-}" ]; then
    case "${VARIANT}" in
    fips | non-fips) variant="${VARIANT}" ;;
    esac
  fi
  if [ $link_set -eq 0 ] && [ -n "${LINK:-}" ]; then
    case "${LINK}" in
    static | dynamic) link="${LINK}" ;;
    esac
  fi

  case "$variant" in
  fips | non-fips) : ;;
  *)
    echo "Error: --variant must be 'fips' or 'non-fips'" >&2
    exit 1
    ;;
  esac
  VARIANT="$variant"
  VARIANT_NAME=$([ "$VARIANT" = "non-fips" ] && echo "non-FIPS" || echo "FIPS")

  case "$link" in
  static | dynamic) : ;;
  *)
    echo "Error: --link must be 'static' or 'dynamic'" >&2
    exit 1
    ;;
  esac
  LINK="$link"

  # Default profile when not specified: debug
  case "${profile:-debug}" in
  release)
    BUILD_PROFILE="release"
    RELEASE_FLAG="--release"
    ;;
  debug | *)
    BUILD_PROFILE="debug"
    RELEASE_FLAG=""
    ;;
  esac

  # FEATURES_FLAG derived strictly from variant
  # FIPS is the default mode (no extra flags needed)
  # non-fips requires explicit feature flag
  FEATURES_FLAG=()
  if [ "$VARIANT" = "non-fips" ]; then
    FEATURES_FLAG=(--features non-fips)
  fi

  ensure_macos_sdk_env
  export VARIANT VARIANT_NAME BUILD_PROFILE RELEASE_FLAG LINK
}

# Require a command to be available (gentle helper for running outside Nix)
require_cmd() {
  local cmd="$1"
  shift || true
  local msg="${*:-Required command $cmd not found. Please install it and retry.}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: $msg" >&2
    exit 1
  fi
}

# Resolve repository root directory.
# Usage: get_repo_root [hint_path]
# Tries git first; falls back to walking up until Cargo.toml and crate/ are found;
# as a last resort, returns hint/../.. (suitable for scripts under .github/scripts).
get_repo_root() {
  local hint="${1:-$(pwd)}"

  # Try git if available
  if command -v git >/dev/null 2>&1; then
    local root
    if root=$(git -C "$hint" rev-parse --show-toplevel 2>/dev/null); then
      echo "$root"
      return 0
    fi
  fi

  # Walk up until we find clear markers of the repo root
  local dir="$hint"
  while [ "$dir" != "/" ]; do
    if [ -f "$dir/Cargo.toml" ] && [ -d "$dir/crate" ]; then
      echo "$dir"
      return 0
    fi
    dir="$(dirname "$dir")"
  done

  # Fallback: assume scripts live in .github/scripts -> go up two levels
  (cd "$hint/../.." >/dev/null 2>&1 && pwd)
}

# Note: legacy packaging helpers removed; packaging smoke tests now live in nix.sh

# ------------------------------
# Test helpers (used by test_*.sh)
# ------------------------------

# Setup concise logging for tests unless caller overrides RUST_LOG
setup_test_logging() {
  : "${RUST_LOG:=cosmian_kms_cli=error,cosmian_kms_server=error,cosmian_kmip=error,test_kms_server=error}"
  export RUST_LOG
}

# Export OpenSSL FIPS runtime variables to match the locally built static OpenSSL
# Only for FIPS variant and when not running inside Nix (Nix sets these via derivations)
setup_fips_openssl_env() {
  # In non-FIPS variant, ensure no FIPS provider is enforced by env vars (Nix shells may set these)
  if [ "${VARIANT:-}" != "fips" ]; then
    # Clear any FIPS-enforcing variables inherited from the environment/shell.
    unset OPENSSL_CONF OPENSSL_MODULES || true

    # Always provide a lightweight non-FIPS config enabling default + legacy providers,
    # so legacy algorithms (e.g., PKCS12KDF) are available in non-fips test runs.
    local repo_root non_fips_conf
    repo_root="$(get_repo_root "${SCRIPT_DIR:-$(pwd)}")"
    mkdir -p "${repo_root}/target" || true
    non_fips_conf="${repo_root}/target/openssl-nonfips-legacy.cnf"
    if [ ! -f "${non_fips_conf}" ]; then
      cat >"${non_fips_conf}" <<'EOF'
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
EOF
    fi
    export OPENSSL_CONF="${non_fips_conf}"

    # If a custom OpenSSL is present, help OpenSSL find its provider modules.
    if [ -n "${OPENSSL_DIR:-}" ] && [ -d "${OPENSSL_DIR}/lib/ossl-modules" ]; then
      export OPENSSL_MODULES="${OPENSSL_DIR}/lib/ossl-modules"
    fi

    # Retain OPENSSL_DIR so build scripts can locate headers/libs.
    return 0
  fi

  # For FIPS variant, if running inside Nix, derivations provide correct env; nothing to set here
  if [ -n "${IN_NIX_SHELL:-}" ]; then
    return 0
  fi

  # If OPENSSL_DIR is already set and has FIPS artifacts, use it
  if [ -n "${OPENSSL_DIR:-}" ]; then
    local mod_ext
    if [ "$(uname -s)" = "Darwin" ]; then
      mod_ext="dylib"
    else
      mod_ext="so"
    fi

    if [ -f "${OPENSSL_DIR}/lib/ossl-modules/fips.${mod_ext}" ] && [ -f "${OPENSSL_DIR}/ssl/fipsmodule.cnf" ]; then
      export OPENSSL_CONF="${OPENSSL_DIR}/ssl/openssl.cnf"
      export OPENSSL_MODULES="${OPENSSL_DIR}/lib/ossl-modules"
      return 0
    fi
  fi

  local repo_root
  repo_root="$(get_repo_root "${SCRIPT_DIR:-$(pwd)}")"

  # Map platform to the same os/arch scheme used by build.rs
  local os arch
  case "$(uname -s)" in
  Darwin) os="macos" ;;
  Linux) os="linux" ;;
  *) os="unknown-os" ;;
  esac
  case "$(uname -m)" in
  arm64 | aarch64) arch="aarch64" ;;
  x86_64 | amd64) arch="x86_64" ;;
  *) arch="unknown-arch" ;;
  esac

  local prefix
  prefix="${repo_root}/target/openssl-fips-3.1.2-${os}-${arch}"

  # Determine module extension
  local mod_ext
  if [ "$os" = "macos" ]; then
    mod_ext="dylib"
  else
    mod_ext="so"
  fi

  # Check if FIPS OpenSSL already built locally; if not and we're outside Nix,
  # avoid forcing a local build that breaks CI without FIPS toolchain.
  if [ ! -f "${prefix}/lib/ossl-modules/fips.${mod_ext}" ] || [ ! -f "${prefix}/ssl/fipsmodule.cnf" ]; then
    if [ -n "${CI:-}" ] || [ -z "${IN_NIX_SHELL:-}" ]; then
      echo "WARN: FIPS OpenSSL not found at ${prefix} and not in Nix; proceeding with system OpenSSL via pkg-config (non-FIPS)." >&2
      # Allow rust-openssl to discover system OpenSSL if available
      unset OPENSSL_NO_PKG_CONFIG || true
      # No OPENSSL_CONF/OPENSSL_MODULES set, so FIPS provider won't be enforced.
      return 0
    fi
    echo "FIPS OpenSSL not found at ${prefix}; triggering build via cargo..." >&2
    (
      unset OPENSSL_DIR OPENSSL_INCLUDE_DIR OPENSSL_LIB_DIR PKG_CONFIG_PATH
      export OPENSSL_NO_PKG_CONFIG=1
      cd "$repo_root/crate/server" && cargo build --lib
    ) || {
      echo "Error: Failed to build OpenSSL FIPS automatically." >&2
      echo "" >&2
      echo "FIPS tests require a FIPS-compliant OpenSSL 3.1.2 build." >&2
      echo "The recommended way to run FIPS tests is through Nix:" >&2
      echo "" >&2
      echo "  bash .github/scripts/nix.sh test          # Run all FIPS tests" >&2
      echo "  bash .github/scripts/nix.sh test sqlite   # Run SQLite FIPS tests" >&2
      echo "" >&2
      echo "Alternatively, set OPENSSL_DIR to a valid FIPS OpenSSL installation." >&2
      exit 1
    }
  fi

  # Verify FIPS artifacts were successfully built
  if [ ! -f "${prefix}/lib/ossl-modules/fips.${mod_ext}" ] || [ ! -f "${prefix}/ssl/fipsmodule.cnf" ]; then
    echo "Error: FIPS OpenSSL build completed but required files not found:" >&2
    echo "  Expected: ${prefix}/lib/ossl-modules/fips.${mod_ext}" >&2
    echo "  Expected: ${prefix}/ssl/fipsmodule.cnf" >&2
    echo "" >&2
    echo "FIPS tests require a FIPS-compliant OpenSSL 3.1.2 build." >&2
    echo "The recommended way to run FIPS tests is through Nix:" >&2
    echo "" >&2
    echo "  bash .github/scripts/nix.sh test          # Run all FIPS tests" >&2
    echo "  bash .github/scripts/nix.sh test sqlite   # Run SQLite FIPS tests" >&2
    exit 1
  fi

  # Point OpenSSL to our patched config and provider modules
  export OPENSSL_CONF="${prefix}/ssl/openssl.cnf"
  export OPENSSL_MODULES="${prefix}/lib/ossl-modules"
}

# Internal: run the Rust workspace tests for a given DB selector
# Usage: _run_workspace_tests <db>
_run_workspace_tests() {
  local db="$1"
  # Ensure cargo is available when running outside Nix
  require_cmd cargo "Cargo is required to run the Rust test workspace. Install Rust (rustup) and retry."
  # Export the selector understood by the test harness
  case "$db" in
  sqlite | postgresql | mysql | redis-findex)
    export KMS_TEST_DB="$db"
    ;;
  redis)
    export KMS_TEST_DB="redis-findex"
    ;;
  *)
    echo "Unknown DB '$db'" >&2
    return 1
    ;;
  esac

  # Provide sensible defaults matching repo docs when applicable
  case "$KMS_TEST_DB" in
  sqlite)
    : "${KMS_SQLITE_PATH:=data/shared}"
    export KMS_SQLITE_PATH
    ;;
  postgresql)
    : "${KMS_POSTGRES_URL:=postgresql://kms:kms@127.0.0.1:5432/kms}"
    export KMS_POSTGRES_URL
    ;;
  mysql)
    : "${KMS_MYSQL_URL:=mysql://kms:kms@127.0.0.1:3306/kms}"
    export KMS_MYSQL_URL
    ;;
  esac

  # Database tests are marked with #[ignore] so they need --ignored flag
  # We run only database-specific tests to avoid running other ignored tests (e.g., HSM, Google CSE)
  local test_filter=""
  local test_args="--nocapture"
  case "$KMS_TEST_DB" in
  postgresql)
    test_filter="tests::test_db_postgresql test_validate_with_certificates"
    test_args="$test_args --ignored"
    ;;
  mysql)
    test_filter="tests::test_db_mysql test_validate_with_certificates"
    test_args="$test_args --ignored"
    ;;
  redis-findex)
    test_filter="tests::test_db_redis_with_findex test_validate_with_certificates"
    test_args="$test_args --ignored"
    ;;
  esac

  # shellcheck disable=SC2086
  cargo test --workspace --lib $RELEASE_FLAG ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} -- $test_args $test_filter

  # For database backends (postgresql, mysql, redis), also run the regular non-ignored tests
  # For sqlite, skip this step since all non-ignored tests already ran above
  if [ "$KMS_TEST_DB" != "sqlite" ]; then
    # shellcheck disable=SC2086
    cargo test --workspace --lib $RELEASE_FLAG ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} --
  fi
}

# Public: run DB-specific tests with optional service checks
# Usage: run_db_tests <sqlite|postgresql|mysql|redis|redis-findex>
run_db_tests() {
  local db="$1"
  _run_workspace_tests "$db"
}

# Wait for a TCP host:port to be reachable (best-effort, small timeout)
_wait_for_port() {
  local host="$1" port="$2" timeout="${3:-10}"
  local start now
  start=$(date +%s)
  while true; do
    if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
      exec 3>&- 3<&-
      return 0
    fi
    now=$(date +%s)
    [ $((now - start)) -ge "$timeout" ] && return 1
    sleep 1
  done
}

# Check that a DB service is up, then run tests for that DB
# Usage: check_and_test_db <PrettyName> <db-key> <HOST_VAR> <PORT_VAR>
check_and_test_db() {
  local pretty="$1" dbkey="$2" host_var="$3" port_var="$4"
  local host="${!host_var:-127.0.0.1}" port="${!port_var:-}"
  case "$dbkey" in
  postgresql) : "${port:=5432}" ;;
  mysql) : "${port:=3306}" ;;
  redis | redis-findex) : "${port:=6379}" ;;
  esac

  echo "Checking $pretty at $host:$port..."
  if _wait_for_port "$host" "$port" 10; then
    echo "$pretty is reachable. Running tests..."
  else
    echo "Error: $pretty at $host:$port not reachable after timeout; skipping $pretty tests." >&2
    # Respect repo guidance: only run DB-backed suites when the service is available.
    # Return success to allow the overall orchestrator to continue to other suites.
    return 0
  fi

  case "$dbkey" in
  redis) dbkey="redis-findex" ;;
  esac
  run_db_tests "$dbkey"
}

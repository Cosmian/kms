#!/usr/bin/env bash
# .mise/lib/common.sh — Shared helpers for all MISE tasks.
#
# Source this from any task file:
#   source "${MISE_CONFIG_ROOT:-.}/.mise/lib/common.sh"
#
# Provides:
#   Colors & printing:  RED GREEN YELLOW BLUE NC, print_header/status/warning/error/success/info
#   Environment:        kms_init_env, get_repo_root, require_cmd, ensure_macos_sdk_env,
#                       ensure_macos_frameworks_ldflags, setup_test_logging, run_isolated,
#                       wait_for_port, compute_sha256
#   Test helpers:       build_test_deps, run_db_tests, check_and_test_db

# ── Guard against double-sourcing ─────────────────────────────────────────────
[ -n "${_MISE_COMMON_SH_LOADED:-}" ] && return 0
_MISE_COMMON_SH_LOADED=1

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
# shellcheck disable=SC2034  # CYAN is exported for use by sourcing scripts
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
  echo -e "${BLUE}================================${NC}"
  echo -e "${BLUE}  $*  ${NC}"
  echo -e "${BLUE}================================${NC}"
  echo
}

print_status() { echo -e "${GREEN}[INFO]${NC} $*"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $*"; }
print_error() {
  echo -e "${RED}[ERROR]${NC} $*" >&2
  exit 1
}
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
print_info() { echo -e "${BLUE}[i]${NC} $*"; }

# ── Nixpkgs pin ───────────────────────────────────────────────────────────────
export PIN_URL="https://package.cosmian.com/nixpkgs/8b27c1239e5c421a2bbc2c65d52e4a6fbf2ff296.tar.gz"
export PINNED_NIXPKGS_URL="$PIN_URL"

# ── macOS SDK helpers ─────────────────────────────────────────────────────────

ensure_macos_sdk_env() {
  if [ "$(uname -s)" != "Darwin" ]; then return 0; fi

  : "${DEVELOPER_DIR:=/Library/Developer/CommandLineTools}"
  export DEVELOPER_DIR
  if [ -d "${DEVELOPER_DIR}/usr/bin" ]; then
    case ":${PATH}:" in
      *":${DEVELOPER_DIR}/usr/bin:"*) : ;;
      *) export PATH="${DEVELOPER_DIR}/usr/bin:${PATH}" ;;
    esac
  fi

  if [ -n "${SDKROOT:-}" ] && [ -d "${SDKROOT}" ]; then
    :
  else
    if command -v xcrun >/dev/null 2>&1; then
      local sdk
      sdk="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
      if [ -n "$sdk" ] && [ -d "$sdk" ]; then
        export SDKROOT="$sdk"
      fi
    fi
    if [ -z "${SDKROOT:-}" ]; then
      local clt_sdk="/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk"
      if [ -d "$clt_sdk" ]; then
        export SDKROOT="$clt_sdk"
      fi
    fi
  fi

  if [ -n "${SDKROOT:-}" ] && [ -d "${SDKROOT}" ]; then
    unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH
    unset NIX_CFLAGS_COMPILE NIX_CFLAGS_LINK NIX_LDFLAGS

    local sysroot_flag="-isysroot ${SDKROOT}"
    local framework_dir="${SDKROOT}/System/Library/Frameworks"
    local framework_flags=""
    if [ -d "${framework_dir}" ]; then
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
  fi
}

ensure_macos_frameworks_ldflags() {
  if [ "$(uname -s)" != "Darwin" ]; then return 0; fi
  if [ -z "${SDKROOT:-}" ] || [ ! -d "${SDKROOT}" ]; then
    ensure_macos_sdk_env || true
  fi
  if [ -z "${SDKROOT:-}" ] || [ ! -d "${SDKROOT}" ]; then return 0; fi

  local frameworks_dir="${SDKROOT}/System/Library/Frameworks"
  if [ ! -d "${frameworks_dir}" ]; then return 0; fi

  local fw_ldflags="-F${frameworks_dir} -Wl,-F,${frameworks_dir}"
  if [ -n "${LDFLAGS:-}" ]; then
    export LDFLAGS="${fw_ldflags} ${LDFLAGS}"
  else
    export LDFLAGS="${fw_ldflags}"
  fi
  if [ -n "${RUSTFLAGS:-}" ]; then
    export RUSTFLAGS="-C link-arg=-F${frameworks_dir} -C link-arg=-Wl,-F,${frameworks_dir} ${RUSTFLAGS}"
  else
    export RUSTFLAGS="-C link-arg=-F${frameworks_dir} -C link-arg=-Wl,-F,${frameworks_dir}"
  fi
}

# ── Core helpers ──────────────────────────────────────────────────────────────

# Initialize build/test configuration from MISE #USAGE variables.
# Usage: kms_init_env <variant> <link>
# Exports: VARIANT, VARIANT_NAME, FEATURES_FLAG[], LINK
kms_init_env() {
  local variant="${1:-fips}" link="${2:-static}"

  case "$variant" in
    fips | non-fips) : ;;
    *) print_error "--variant must be 'fips' or 'non-fips', got: $variant" ;;
  esac
  VARIANT="$variant"
  VARIANT_NAME=$([ "$VARIANT" = "non-fips" ] && echo "non-FIPS" || echo "FIPS")

  case "$link" in
    static | dynamic) : ;;
    *) print_error "--link must be 'static' or 'dynamic', got: $link" ;;
  esac
  LINK="$link"

  FEATURES_FLAG=()
  if [ "$VARIANT" = "non-fips" ]; then
    FEATURES_FLAG=(--features non-fips)
  fi

  ensure_macos_sdk_env
  ensure_macos_frameworks_ldflags
  _warn_system_kms_conf

  export VARIANT VARIANT_NAME LINK
}

require_cmd() {
  local cmd="$1"
  shift || true
  # shellcheck disable=SC2016  # $cmd intentionally not expanded inside default — see actual usage
  local msg="${*:-Required command '$cmd' not found. Please install it and retry.}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    print_error "$msg"
  fi
}

get_repo_root() {
  local hint="${1:-$(pwd)}"
  if command -v git >/dev/null 2>&1; then
    local root
    if root=$(git -C "$hint" rev-parse --show-toplevel 2>/dev/null); then
      echo "$root"
      return 0
    fi
  fi
  local dir="$hint"
  while [ "$dir" != "/" ]; do
    if [ -f "$dir/Cargo.toml" ] && [ -d "$dir/crate" ]; then
      echo "$dir"
      return 0
    fi
    dir="$(dirname "$dir")"
  done
  (cd "$hint/../.." >/dev/null 2>&1 && pwd)
}

setup_test_logging() {
  : "${RUST_LOG:=cosmian_kms_cli_actions=error,cosmian_kms_server=error,cosmian_kmip=error,test_kms_server=error}"
  export RUST_LOG
}

# Run a command with FIPS OpenSSL env vars stripped (for pnpm, Python, curl, etc.)
run_isolated() {
  env -u LD_PRELOAD -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES "$@"
}

# Wait for a TCP port to become reachable.
# Usage: wait_for_port <host> <port> [timeout_sec]
wait_for_port() {
  local host="$1" port="$2" timeout="${3:-30}"
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

# Compute SHA-256 of a file (cross-platform)
compute_sha256() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

# ── Test helpers ──────────────────────────────────────────────────────────────

build_test_deps() {
  if [ "${KMS_SKIP_BUILD:-}" = "1" ]; then
    echo "Skipping build (KMS_SKIP_BUILD=1)"
    return 0
  fi
  require_cmd cargo "Cargo is required to build test dependencies."
  cargo build -p ckms "${FEATURES_FLAG[@]}"
  if [ "${VARIANT:-fips}" = "non-fips" ]; then
    cargo build -p cosmian_pkcs11 "${FEATURES_FLAG[@]}"
  fi
}

_run_workspace_tests() {
  local db="$1"
  require_cmd cargo
  case "$db" in
    sqlite | postgresql | mysql | redis) ;;
    *)
      echo "Unknown DB '$db'. Accepted: sqlite, postgresql, mysql, redis" >&2
      return 1
      ;;
  esac
  export KMS_TEST_DB="$db"
  case "$db" in
    postgresql)
      : "${KMS_POSTGRES_URL:=postgresql://kms:kms@127.0.0.1:${KMS_SLOT_POSTGRES_PORT:-5432}/kms}"
      export KMS_POSTGRES_URL
      ;;
    mysql)
      : "${KMS_MYSQL_URL:=mysql://kms:kms@127.0.0.1:${KMS_SLOT_MYSQL_PORT:-3306}/kms}"
      export KMS_MYSQL_URL
      ;;
    redis)
      : "${REDIS_HOST:=127.0.0.1}"
      : "${REDIS_PORT:=${KMS_SLOT_REDIS_PORT:-6379}}"
      export REDIS_HOST REDIS_PORT
      ;;
  esac
  if [ "$db" != "sqlite" ]; then
    cargo test -p cosmian_kms_server_database --lib "${FEATURES_FLAG[@]}" \
      -- --ignored --nocapture "test_db_${db}" test_certificate_validate
  fi
  cargo test --workspace --lib "${FEATURES_FLAG[@]}" -- --nocapture
}

run_db_tests() {
  local db="$1"
  build_test_deps
  _run_workspace_tests "$db"
}

# Export KMS_TEST_DB and matching connection URL env vars for a given DB backend.
# Usage: setup_db_env <db>
#   db: sqlite | postgresql | mysql | percona | maria | redis
# Percona and MariaDB use KMS_TEST_DB=mysql with different default ports.
# This function is idempotent — existing env vars are not overwritten (uses :=).
setup_db_env() {
  local db="$1"
  case "$db" in
    sqlite)
      export KMS_TEST_DB="sqlite"
      ;;
    postgresql)
      export KMS_TEST_DB="postgresql"
      : "${KMS_POSTGRES_URL:=postgresql://kms:kms@127.0.0.1:${KMS_SLOT_POSTGRES_PORT:-5432}/kms}"
      export KMS_POSTGRES_URL
      ;;
    mysql)
      export KMS_TEST_DB="mysql"
      : "${KMS_MYSQL_URL:=mysql://kms:kms@127.0.0.1:${KMS_SLOT_MYSQL_PORT:-3306}/kms}"
      export KMS_MYSQL_URL
      ;;
    percona)
      export KMS_TEST_DB="mysql"
      : "${KMS_MYSQL_URL:=mysql://kms:kms@127.0.0.1:${KMS_SLOT_PERCONA_PORT:-3307}/kms}"
      export KMS_MYSQL_URL
      ;;
    maria)
      export KMS_TEST_DB="mysql"
      : "${KMS_MYSQL_URL:=mysql://kms:kms@127.0.0.1:${KMS_SLOT_MARIADB_PORT:-3308}/kms}"
      export KMS_MYSQL_URL
      ;;
    redis)
      export KMS_TEST_DB="redis"
      : "${REDIS_HOST:=127.0.0.1}"
      : "${REDIS_PORT:=${KMS_SLOT_REDIS_PORT:-6379}}"
      export REDIS_HOST REDIS_PORT
      ;;
    *)
      echo "setup_db_env: unknown db '$db'. Accepted: sqlite, postgresql, mysql, percona, maria, redis" >&2
      return 1
      ;;
  esac
}

# Wait for a TCP port to accept connections.
# Usage: _wait_for_port <host> <port> [<timeout_secs>]
_wait_for_port() {
  local host="$1" port="$2" timeout="${3:-30}"
  local _i
  echo "Waiting for $host:$port (timeout ${timeout}s)..."
  for _i in $(seq 1 "$timeout"); do
    if (echo >/dev/tcp/"$host"/"$port") 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

check_and_test_db() {
  local pretty="$1" dbkey="$2" host_var="$3" port_var="$4"
  local host="${!host_var:-127.0.0.1}" port="${!port_var:-}"
  case "$dbkey" in
    postgresql) : "${port:=${KMS_SLOT_POSTGRES_PORT:-5432}}" ;;
    mysql) : "${port:=${KMS_SLOT_MYSQL_PORT:-3306}}" ;;
    redis) : "${port:=${KMS_SLOT_REDIS_PORT:-6379}}" ;;
  esac

  echo "Checking $pretty at $host:$port..."
  if _wait_for_port "$host" "$port" 30; then
    echo "$pretty is reachable. Running tests..."
  else
    echo "Error: $pretty at $host:$port not reachable after timeout; failing test run." >&2
    return 1
  fi

  run_db_tests "$dbkey"
}

# ── Internal helpers ──────────────────────────────────────────────────────────

_warn_system_kms_conf() {
  local default_conf="/etc/cosmian/kms.toml"
  if [ -f "$default_conf" ]; then
    echo "WARNING: ${default_conf} exists on this system." >&2
    echo "         The KMS server will load this file and ignore CLI args" >&2
    echo "         when started without an explicit --config flag." >&2
  fi
}

# Wait for a running KMS server to accept HTTP requests.
# Usage: kms_wait_ready <probe_url> <kms_pid> <log_file> [<timeout_secs>]
kms_wait_ready() {
  local probe_url="$1" kms_pid="$2" log_file="$3" timeout="${4:-60}"
  require_cmd curl "curl is required for kms_wait_ready"
  local _i
  for _i in $(seq 1 "$timeout"); do
    if env -u LD_PRELOAD -u LD_LIBRARY_PATH \
      curl -sS --max-time 2 -o /dev/null -w "%{http_code}" \
      -X POST -H "Content-Type: application/json" -d '{}' "$probe_url" 2>/dev/null |
      grep -Eq '^[0-9]{3}$'; then
      return 0
    fi
    sleep 1
    if ! kill -0 "$kms_pid" 2>/dev/null; then
      echo "ERROR: KMS server process exited early; log:" >&2
      cat "$log_file" >&2
      exit 1
    fi
  done
  echo "ERROR: KMS server did not start in ${timeout}s; log:" >&2
  cat "$log_file" >&2
  exit 1
}

# Scan pkcs11-tool output for unexpected CKR_ATTRIBUTE_* warnings.
pkcs11_check_warnings() {
  local pkcs11_output="$1" exclude="${2:-}"
  local warnings
  if [ -n "$exclude" ]; then
    warnings=$(echo "$pkcs11_output" | grep "failed: rv = CKR_ATTRIBUTE_" | grep -v "$exclude" || true)
  else
    warnings=$(echo "$pkcs11_output" | grep "failed: rv = CKR_ATTRIBUTE_" || true)
  fi
  if [ -n "$warnings" ]; then
    echo "FAIL: pkcs11-tool reported unexpected attribute warnings:" >&2
    echo "$warnings" >&2
    return 1
  fi
  return 0
}

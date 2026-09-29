#!/usr/bin/env bash
# .mise/lib/kms_server.sh — KMS server lifecycle helpers.
#
# Extracts the common pattern of writing a temp config, starting a KMS server,
# waiting for readiness, and cleaning up on EXIT. Used by 10+ test tasks.
#
# Source this from a task file:
#   source "${MISE_CONFIG_ROOT:-.}/.mise/lib/kms_server.sh"
#
# Provides:
#   kms_write_config <port> <sqlite_path> [extra_toml_lines...]
#   kms_start [port] [sqlite_path] [extra_cargo_args...]
#   kms_start_from_bin <binary> [--config <path>] [extra_bin_args...]
#   kms_stop
#   kms_write_ckms_conf [url]
#
# Globals set:
#   KMS_PID, KMS_CONFIG_FILE, KMS_LOG_FILE, KMS_PORT, KMS_URL, KMS_CKMS_CONF

# ── Guard ─────────────────────────────────────────────────────────────────────
[ -n "${_MISE_KMS_SERVER_SH_LOADED:-}" ] && return 0
_MISE_KMS_SERVER_SH_LOADED=1

# ── Require common.sh and kms_build.sh ────────────────────────────────────────
_KMS_SERVER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "${_MISE_COMMON_SH_LOADED:-}" ]; then
  # shellcheck source=.mise/lib/common.sh
  source "${_KMS_SERVER_DIR}/common.sh"
fi
if [ -z "${_MISE_KMS_BUILD_SH_LOADED:-}" ]; then
  # shellcheck source=.mise/lib/kms_build.sh
  source "${_KMS_SERVER_DIR}/kms_build.sh"
fi

# ── State ─────────────────────────────────────────────────────────────────────
KMS_PID=""
KMS_CONFIG_FILE=""
KMS_LOG_FILE=""
KMS_PORT=""
KMS_URL=""
KMS_CKMS_CONF=""
_KMS_SQLITE_DIR=""
_KMS_TMP_DIR=""

# Pick a free TCP port on localhost. Uses Python to bind to port 0 and read
# back the OS-assigned port — same strategy as Rust's allocate_dynamic_port().
# Collision-free even when multiple KMS repos run tests concurrently.
# Usage: port=$(kms_pick_free_port)
kms_pick_free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

# Write a minimal KMS server TOML config for testing.
# Usage: kms_write_config <port> <sqlite_path> [extra_lines...]
# Sets: KMS_CONFIG_FILE, KMS_PORT, KMS_URL, _KMS_SQLITE_DIR
kms_write_config() {
  local port="$1" sqlite_path="$2"
  shift 2

  KMS_PORT="$port"
  KMS_URL="http://127.0.0.1:${KMS_PORT}"
  _KMS_SQLITE_DIR="$sqlite_path"

  mkdir -p "$_KMS_SQLITE_DIR"
  _KMS_TMP_DIR="${_KMS_TMP_DIR:-$(mktemp -d /tmp/kms-test-XXXXXX)}"
  KMS_CONFIG_FILE="${_KMS_TMP_DIR}/kms.toml"
  KMS_LOG_FILE="${_KMS_TMP_DIR}/kms.log"

  cat >"${KMS_CONFIG_FILE}" <<EOF
default_username = "admin"

[db]
database_type = "sqlite"
sqlite_path = "${_KMS_SQLITE_DIR}"
clear_database = true

[http]
hostname = "127.0.0.1"
port = ${KMS_PORT}

[logging]
rust_log = "info,cosmian_kms=info"
ansi_colors = false
EOF

  # Append any extra TOML lines the caller wants
  local line
  for line in "$@"; do
    echo "$line" >>"${KMS_CONFIG_FILE}"
  done
}

# Start the KMS server in the background and wait for it to accept requests.
# Builds the server first if needed.
# Usage: kms_start [port] [sqlite_path] [extra_cargo_args...]
# Requires: FEATURES_FLAG to be set (from kms_init_env)
# Sets: KMS_PID
kms_start() {
  local port="${1:-$(kms_pick_free_port)}" sqlite_path="${2:-$(mktemp -d /tmp/kms-sqlite-XXXXXX)}"
  shift
  shift 2>/dev/null || true

  # Write config if not already written for this port
  if [ -z "${KMS_CONFIG_FILE:-}" ] || [ "${KMS_PORT}" != "$port" ]; then
    kms_write_config "$port" "$sqlite_path"
  fi

  # Build the server
  kms_build_server "$@"

  # Start from the built binary
  kms_start_from_bin "$(get_kms_bin)"
}

# Start the KMS server from a pre-built binary.
# Assumes kms_write_config has already been called (or a --config arg is given).
# Usage: kms_start_from_bin <binary> [extra_bin_args...]
# Sets: KMS_PID
kms_start_from_bin() {
  local kms_bin="$1"
  shift

  if [ ! -x "$kms_bin" ]; then
    print_error "KMS binary not found or not executable: $kms_bin"
  fi

  # If no --config was passed and we have a KMS_CONFIG_FILE, inject it.
  local has_config=false
  for arg in "$@"; do
    case "$arg" in --config | -c)
      has_config=true
      break
      ;;
    esac
  done

  local args=()
  if [ "$has_config" = "false" ] && [ -n "${KMS_CONFIG_FILE:-}" ]; then
    args+=(--config "${KMS_CONFIG_FILE}")
  fi
  args+=("$@")

  echo "Starting KMS server on port ${KMS_PORT}..."
  "${kms_bin}" "${args[@]}" >"${KMS_LOG_FILE}" 2>&1 &
  KMS_PID=$!

  kms_wait_ready "${KMS_URL}/kmip/2_1" "${KMS_PID}" "${KMS_LOG_FILE}" 120
  echo "KMS server ready (PID=${KMS_PID}, port=${KMS_PORT})"
}

# Write a ckms.toml config file pointing to the running server.
# Usage: kms_write_ckms_conf [url]
# Sets: KMS_CKMS_CONF
# Returns the path to the written file.
kms_write_ckms_conf() {
  local url="${1:-${KMS_URL:-http://127.0.0.1:${KMS_PORT}}}"
  _KMS_TMP_DIR="${_KMS_TMP_DIR:-$(mktemp -d /tmp/kms-test-XXXXXX)}"
  KMS_CKMS_CONF="${_KMS_TMP_DIR}/ckms.toml"
  cat >"${KMS_CKMS_CONF}" <<EOF
[http_config]
server_url = "${url}"
EOF
  echo "${KMS_CKMS_CONF}"
}

# Stop the KMS server and clean up temp files. Idempotent.
# Safe to use in `trap kms_stop EXIT`.
kms_stop() {
  if [ -n "${KMS_PID:-}" ]; then
    kill "${KMS_PID}" 2>/dev/null || true
    wait "${KMS_PID}" 2>/dev/null || true
    KMS_PID=""
  fi
  if [ -n "${_KMS_TMP_DIR:-}" ]; then rm -rf "${_KMS_TMP_DIR}" 2>/dev/null || true; fi
  if [ -n "${_KMS_SQLITE_DIR:-}" ]; then rm -rf "${_KMS_SQLITE_DIR}" 2>/dev/null || true; fi
  KMS_CONFIG_FILE=""
  KMS_LOG_FILE=""
  KMS_CKMS_CONF=""
  _KMS_TMP_DIR=""
  _KMS_SQLITE_DIR=""
}

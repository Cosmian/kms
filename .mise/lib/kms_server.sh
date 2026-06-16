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
#   kms_stop
#
# Globals set:
#   KMS_PID, KMS_CONFIG_FILE, KMS_LOG_FILE, KMS_PORT, KMS_URL

# ── Guard ─────────────────────────────────────────────────────────────────────
[ -n "${_MISE_KMS_SERVER_SH_LOADED:-}" ] && return 0
_MISE_KMS_SERVER_SH_LOADED=1

# ── Require common.sh ─────────────────────────────────────────────────────────
if [ -z "${_MISE_COMMON_SH_LOADED:-}" ]; then
  source "${MISE_CONFIG_ROOT:-.}/.mise/lib/common.sh"
fi

# ── State ─────────────────────────────────────────────────────────────────────
KMS_PID=""
KMS_CONFIG_FILE=""
KMS_LOG_FILE=""
KMS_PORT=""
KMS_URL=""
_KMS_SQLITE_DIR=""

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
  KMS_CONFIG_FILE="$(mktemp /tmp/kms-test-XXXXXX.toml)"
  KMS_LOG_FILE="$(mktemp /tmp/kms-test-XXXXXX.log)"

  cat >"${KMS_CONFIG_FILE}" <<EOF
[db]
database_type = "sqlite"
sqlite_path = "${_KMS_SQLITE_DIR}"

[http]
hostname = "0.0.0.0"
port = ${KMS_PORT}
EOF

  # Append any extra TOML lines the caller wants
  local line
  for line in "$@"; do
    echo "$line" >>"${KMS_CONFIG_FILE}"
  done
}

# Start the KMS server in the background and wait for it to accept requests.
# Usage: kms_start [port] [sqlite_path] [extra_cargo_args...]
# Requires: FEATURES_FLAG to be set (from kms_init_env)
# Sets: KMS_PID
kms_start() {
  local port="${1:-$(kms_pick_free_port)}" sqlite_path="${2:-$(mktemp -d /tmp/kms-sqlite-XXXXXX)}"
  shift
  shift 2>/dev/null || true

  require_cmd cargo "Cargo is required to build the KMS server."

  # Write config if not already written for this port
  if [ -z "${KMS_CONFIG_FILE:-}" ] || [ "${KMS_PORT}" != "$port" ]; then
    kms_write_config "$port" "$sqlite_path"
  fi

  # Build the server
  cargo build -p cosmian_kms_server ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} "$@"

  local kms_bin
  kms_bin="$(get_repo_root)/target/debug/cosmian_kms"

  echo "Starting KMS server on port ${KMS_PORT}..."
  "${kms_bin}" --config "${KMS_CONFIG_FILE}" >"${KMS_LOG_FILE}" 2>&1 &
  KMS_PID=$!

  kms_wait_ready "${KMS_URL}/kmip/2_1" "${KMS_PID}" "${KMS_LOG_FILE}" 60
  echo "KMS server ready (PID=${KMS_PID}, port=${KMS_PORT})"
}

# Stop the KMS server and clean up temp files. Idempotent.
# Safe to use in `trap kms_stop EXIT`.
kms_stop() {
  if [ -n "${KMS_PID:-}" ]; then
    kill "${KMS_PID}" 2>/dev/null || true
    wait "${KMS_PID}" 2>/dev/null || true
    KMS_PID=""
  fi
  [ -n "${KMS_CONFIG_FILE:-}" ] && rm -f "${KMS_CONFIG_FILE}" 2>/dev/null || true
  [ -n "${KMS_LOG_FILE:-}" ] && rm -f "${KMS_LOG_FILE}" 2>/dev/null || true
  [ -n "${_KMS_SQLITE_DIR:-}" ] && rm -rf "${_KMS_SQLITE_DIR}" 2>/dev/null || true
  KMS_CONFIG_FILE=""
  KMS_LOG_FILE=""
  _KMS_SQLITE_DIR=""
}

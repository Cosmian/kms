#!/usr/bin/env bash
# .mise/lib/spire_test.sh — Shared helpers for SPIRE integration test suites.
#
# Provides:
#   spire_listener_pids     — find PIDs listening on a TCP port via lsof
#   spire_port_listening    — test if a TCP port is currently listening
#   spire_wait_port_closed  — wait until a TCP port is no longer listening
#   spire_stop_port         — terminate any listener on a TCP port
#   spire_reset_state       — wipe SPIRE containers, volumes, temp DB and configs
#   spire_ensure_certs      — generate test TLS certificates if missing
#   spire_build_auth_verifier — build auth_verifier binary and return path
#
# Requires:
#   .mise/lib/common.sh (sourced automatically if needed)

# ── Guard against double-sourcing ─────────────────────────────────────────────
[ -n "${_MISE_SPIRE_TEST_SH_LOADED:-}" ] && return 0
_MISE_SPIRE_TEST_SH_LOADED=1

_SPIRE_TEST_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "${_MISE_COMMON_SH_LOADED:-}" ]; then
  # shellcheck disable=SC1091
  source "${_SPIRE_TEST_LIB_DIR}/common.sh"
fi

# Find PIDs listening on a TCP port using lsof (cross-platform macOS + Linux).
spire_listener_pids() {
  local port="$1"
  lsof -ti tcp:"${port}" 2>/dev/null | sort -u || true
}

# Check if a TCP port is currently listening.
spire_port_listening() {
  local port="$1"
  lsof -i tcp:"${port}" -sTCP:LISTEN 2>/dev/null | grep -q . 2>/dev/null
}

# Wait until a TCP port is closed.
spire_wait_port_closed() {
  local port="$1" timeout_secs="${2:-10}" elapsed=0
  while spire_port_listening "${port}"; do
    if [[ "${elapsed}" -ge "${timeout_secs}" ]]; then
      return 1
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
}

# Terminate any listener on a given port. Tries SIGTERM, then SIGKILL.
spire_stop_port() {
  local port="$1" label="${2:-listener}" pids pid
  pids="$(spire_listener_pids "${port}")"
  pids="$(echo "${pids}" | tr -d ' ' | grep -v '^$' || true)"
  [[ -z "${pids}" ]] && return 0

  local pid_list
  pid_list="$(echo "${pids}" | tr '\n' ',' | sed 's/,$//')"
  print_info "Stopping stale ${label} on port ${port}: ${pid_list}"
  while IFS= read -r pid; do
    [[ -n "${pid}" ]] && kill "${pid}" 2>/dev/null || true
  done <<<"${pids}"

  if spire_wait_port_closed "${port}" 10; then
    return 0
  fi

  print_info "Port ${port} still busy after SIGTERM; forcing down..."
  while IFS= read -r pid; do
    [[ -n "${pid}" ]] && kill -9 "${pid}" 2>/dev/null || true
  done <<<"${pids}"

  spire_wait_port_closed "${port}" 5 ||
    print_error "Port ${port} is still in use after stopping ${label}."
}

# Reset Docker containers, volumes, and temporary files created by SPIRE suites.
spire_reset_state() {
  local auth_db="${1:-/tmp/auth-verifier-spire.db}"
  local secrets_env="${2:-/tmp/spire-secrets.env}"

  spire_stop_port 8443 "auth-verifier"
  spire_stop_port 9998 "KMS"
  spire_stop_port 8088 "jwks-server"
  if ! docker ps >/dev/null 2>&1; then
    if [[ "$(uname -s)" == "Darwin" ]]; then
      open -a Docker 2>/dev/null || true
      for _ in $(seq 1 30); do
        docker ps >/dev/null 2>&1 && break
        sleep 1
      done
    fi
  fi

  docker compose --profile spire down --volumes --remove-orphans 2>/dev/null || true
  rm -f "${auth_db}" "${auth_db}-wal" "${auth_db}-shm" 2>/dev/null || true
  rm -f "${secrets_env}" /tmp/spire-join-token.txt 2>/dev/null || true
  rm -rf /tmp/spire-agent-config-* 2>/dev/null || true
  rm -f /tmp/spire-server-*.log 2>/dev/null || true
}

# Ensure TLS certificates exist in test_data/spire/certs.
spire_ensure_certs() {
  local test_data="$1"
  if [[ ! -f "${test_data}/certs/ca.crt" || ! -f "${test_data}/certs/jwt.key.pem" ]]; then
    print_info "Generating test TLS certificates..."
    bash "${test_data}/certs/generate-test-certs.sh"
  fi
}

# Build auth_verifier and echo the binary path.
spire_build_auth_verifier() {
  local repo_root="$1"
  cargo build --manifest-path "${repo_root}/authentication/Cargo.toml" --bin auth_verifier >&2
  local target_dir bin
  target_dir="$(cd "${repo_root}/authentication" && cargo metadata --no-deps --format-version 1 |
    python3 -c "import sys,json; m=json.load(sys.stdin); print(m['target_directory'])")"
  bin="${target_dir}/debug/auth_verifier"
  [[ -x "${bin}" ]] || print_error "auth-verifier binary not found after build: ${bin}"
  echo "${bin}"
}

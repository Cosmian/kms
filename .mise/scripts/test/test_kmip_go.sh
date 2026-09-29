#!/usr/bin/env bash
# Run Go-based KMIP compliance tests (ovh/kmip-go) against a locally launched Cosmian KMS.
#
# Mirrors the pattern of test_pykmip.sh:
#   1. Build the KMS server binary.
#   2. Free ports, start the server in the background.
#   3. Wait for the KMIP socket port to be ready.
#   4. cd into the Go test module and run `go test -v -count=1 ./...`.
#   5. Trap cleanup to kill the server on exit.
#
# Usage: bash test_kmip_go.sh [--variant non-fips|fips] [--link static|dynamic]

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")

init_build_env "$@"
setup_test_logging

# Go tests work with both fips and non-fips builds; default to non-fips so
# all operations (Covercrypt, etc.) are available, but respect the caller.
: "${VARIANT:=non-fips}"
FEATURES_FLAG=(--features non-fips)
if [ "$VARIANT" = "fips" ]; then
  FEATURES_FLAG=()
fi

# ── Paths ──────────────────────────────────────────────────────────────────────
KMIP_GO_DIR="${REPO_ROOT}/.mise/scripts/kmip-go"
KMS_CONF="${REPO_ROOT}/.mise/scripts/pykmip/kms.toml" # reuse pykmip config
KMS_PORT=9998
KMIP_PORT=15696

# ── Prerequisites ──────────────────────────────────────────────────────────────
require_cmd go "Go is required. Install with: mise use go@latest  OR  set WITH_GO=1 for nix-shell."

go_version=$(go version 2>/dev/null || true)
print_status "Using Go: ${go_version}"

if [ ! -f "${KMIP_GO_DIR}/go.mod" ]; then
  print_error "Go module not found at ${KMIP_GO_DIR}/go.mod"
fi

# ── Download Go dependencies ───────────────────────────────────────────────────
print_status "Downloading Go dependencies…"
(cd "${KMIP_GO_DIR}" && go mod download 2>&1) || {
  print_error "go mod download failed — check your internet connection."
}

# ── Build KMS server ───────────────────────────────────────────────────────────
print_status "Building KMS server (variant=${VARIANT})…"
pushd "${REPO_ROOT}" >/dev/null
cargo build --bin cosmian_kms "${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}"
popd >/dev/null

# ── Free ports ────────────────────────────────────────────────────────────────
free_port() {
  local port="$1"
  local pids=""
  if command -v ss >/dev/null 2>&1; then
    pids=$(ss -ltnp 2>/dev/null | awk -v p=":${port}" '$4 ~ p {gsub(/.*pid=([0-9]+).*/,"\\1",$NF); print $NF}')
  elif command -v lsof >/dev/null 2>&1; then
    pids=$(lsof -iTCP:"${port}" -sTCP:LISTEN -t 2>/dev/null || true)
  fi
  if [ -n "${pids:-}" ]; then
    print_warning "Freeing port ${port} (PIDs: ${pids})…"
    # shellcheck disable=SC2086
    kill $pids 2>/dev/null || true
    sleep 0.5
  fi
}

free_port "${KMS_PORT}"
free_port "${KMIP_PORT}"

# ── Start KMS server ───────────────────────────────────────────────────────────
print_status "Starting KMS server (HTTP=:${KMS_PORT} KMIP=:${KMIP_PORT})…"
RUST_LOG="${RUST_LOG:-warn}" COSMIAN_KMS_CONF="${KMS_CONF}" \
  "${REPO_ROOT}/target/debug/cosmian_kms" &
KMS_PID=$!

# shellcheck disable=SC2329
cleanup() {
  set +e
  if ps -p "${KMS_PID}" >/dev/null 2>&1; then
    print_status "Stopping KMS server (PID=${KMS_PID})…"
    kill "${KMS_PID}" 2>/dev/null || true
    sleep 1
    if ! ps -p "${KMS_PID}" >/dev/null 2>&1; then
      kill -9 "${KMS_PID}" 2>/dev/null || true
    fi
  fi
}
trap cleanup EXIT INT TERM

# ── Wait for KMIP socket port ─────────────────────────────────────────────────
if _wait_for_port 127.0.0.1 "${KMS_PORT}" 30 && _wait_for_port 127.0.0.1 "${KMIP_PORT}" 30; then
  print_success "KMS is up (HTTP=:${KMS_PORT}, KMIP=:${KMIP_PORT})"
else
  print_error "KMS failed to start on required ports within 30 s"
fi

# ── Run Go tests ───────────────────────────────────────────────────────────────
print_header "Running KMIP Go compliance tests (ovh/kmip-go)"

# Export repo root so helpers_test.go can locate certificates
export KMIP_GO_REPO_ROOT="${REPO_ROOT}"

cd "${KMIP_GO_DIR}"
go test -v -count=1 ./... -timeout 120s
GO_STATUS=$?

if [ "${GO_STATUS}" -eq 0 ]; then
  print_success "All KMIP Go compliance tests PASSED ✓"
else
  print_error "Some KMIP Go compliance tests FAILED — see output above"
fi

exit "${GO_STATUS}"

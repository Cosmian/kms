#!/usr/bin/env bash
# ============================================================================
# test_ui_hsm.sh – UI E2E tests for the Locate page with a real SoftHSM2
#                  KMS server.
#
# Usage (via nix.sh):
#   bash .github/scripts/nix.sh --variant non-fips test ui-hsm
# ============================================================================
set -euo pipefail

if [ "${VARIANT:-}" = "fips" ]; then
  echo "UI HSM E2E tests are skipped in FIPS mode." >&2
  exit 0
fi

if ! command -v softhsm2-util >/dev/null 2>&1; then
  echo "softhsm2-util not found; skipping UI HSM tests." >&2
  echo "Run inside nix-shell: bash .github/scripts/nix.sh --variant non-fips test ui-hsm" >&2
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=.github/scripts/common.sh
source "$SCRIPT_DIR/common.sh"

REPO_ROOT="$(get_repo_root "$SCRIPT_DIR")"
WASM_CRATE="${REPO_ROOT}/crate/wasm"
UI_DIR="${REPO_ROOT}/ui"

init_build_env "$@"

ensure_pnpm() {
  if ! command -v pnpm >/dev/null 2>&1; then
    npm install -g pnpm
  fi
}

run_ui() {
  (cd "${UI_DIR}" && "$@")
}

if [ "$(uname)" = "Darwin" ]; then
  _lib_path_var="DYLD_LIBRARY_PATH"
else
  _lib_path_var="LD_LIBRARY_PATH"
fi

echo "========================================="
echo "UI HSM E2E tests – SoftHSM2 setup"
echo "========================================="

export HSM_USER_PASSWORD="12345678"
export SOFTHSM2_HOME="${REPO_ROOT}/.softhsm2-ui-test"
mkdir -p "${SOFTHSM2_HOME}/tokens"
export SOFTHSM2_CONF="${SOFTHSM2_HOME}/softhsm2.conf"
echo "directories.tokendir = ${SOFTHSM2_HOME}/tokens" >"${SOFTHSM2_CONF}"

softhsm2-util --version

SOFTHSM2_BIN_PATH="$(command -v softhsm2-util || true)"
SOFTHSM2_LIB_DIR=""
if [ -n "${SOFTHSM2_BIN_PATH}" ]; then
  SOFTHSM2_PREFIX="$(dirname "$(dirname "${SOFTHSM2_BIN_PATH}")")"
  if [ -d "${SOFTHSM2_PREFIX}/lib/softhsm" ]; then
    SOFTHSM2_LIB_DIR="${SOFTHSM2_PREFIX}/lib/softhsm"
  elif [ -d "${SOFTHSM2_PREFIX}/lib" ]; then
    SOFTHSM2_LIB_DIR="${SOFTHSM2_PREFIX}/lib"
  fi
fi
SOFTHSM2_PKCS11_LIB_PATH="${SOFTHSM2_LIB_DIR:+${SOFTHSM2_LIB_DIR}/libsofthsm2.so}"

_LD="${SOFTHSM2_LIB_DIR:+${SOFTHSM2_LIB_DIR}:}${NIX_OPENSSL_OUT:+${NIX_OPENSSL_OUT}/lib:}${LD_LIBRARY_PATH:-}"
_DYLD="${SOFTHSM2_LIB_DIR:+${SOFTHSM2_LIB_DIR}:}${NIX_OPENSSL_OUT:+${NIX_OPENSSL_OUT}/lib:}${DYLD_LIBRARY_PATH:-}"

echo "==> Initialising SoftHSM2 token..."
INIT_OUT=$(softhsm2-util --init-token --free \
  --label "ui_hsm_test_token" \
  --so-pin "${HSM_USER_PASSWORD}" \
  --pin "${HSM_USER_PASSWORD}" 2>&1 | tee /dev/stderr)

SOFTHSM2_HSM_SLOT_ID=$(echo "${INIT_OUT}" | grep -o 'reassigned to slot [0-9]*' | awk '{print $4}')
if [ -z "${SOFTHSM2_HSM_SLOT_ID:-}" ]; then
  SOFTHSM2_HSM_SLOT_ID=$(softhsm2-util --show-slots |
    awk 'BEGIN{sid=""} /^Slot/ {sid=$2} /Token label/ && $0 ~ /ui_hsm_test_token/ {print sid; exit}')
fi
[ -n "${SOFTHSM2_HSM_SLOT_ID:-}" ] || {
  echo "Error: Could not determine SoftHSM2 slot id." >&2
  exit 1
}
echo "==> SoftHSM2 slot id: ${SOFTHSM2_HSM_SLOT_ID}"

# ── 1. Build WASM ─────────────────────────────────────────────────────────
echo "==> Building WASM (non-fips, web target)..."
(cd "${WASM_CRATE}" &&
  env PATH="${PATH}" \
    LD_LIBRARY_PATH="${_LD}" \
    DYLD_LIBRARY_PATH="${_DYLD}" \
    wasm-pack build --target web --features non-fips)

PKG_DST="${UI_DIR}/src/wasm/pkg"
mkdir -p "${PKG_DST}"
cp -r "${WASM_CRATE}/pkg/." "${PKG_DST}/"

# ── 2. Build KMS server + ckms CLI ────────────────────────────────────────
echo "==> Building KMS server and ckms CLI..."
env \
  PATH="${PATH}" \
  LD_LIBRARY_PATH="${_LD}" \
  DYLD_LIBRARY_PATH="${_DYLD}" \
  cargo build -p cosmian_kms_server -p ckms \
  ${FEATURES_FLAG[@]+${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}}

CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"
kms_bin="${CARGO_TARGET_DIR}/debug/cosmian_kms"
ckms_bin="${CARGO_TARGET_DIR}/debug/ckms"

# ── 3. Install JS deps and build UI ───────────────────────────────────────
ensure_pnpm

echo "==> Installing UI dependencies..."
rm -rf "${UI_DIR}/node_modules"
run_ui pnpm install --frozen-lockfile

echo "==> Building UI (VITE_KMS_URL=http://127.0.0.1:9998)..."
(cd "${UI_DIR}" && {
  chmod -R u+w dist >/dev/null 2>&1 || true
  rm -rf dist >/dev/null 2>&1 || true
})
(cd "${UI_DIR}" && VITE_KMS_URL="http://127.0.0.1:9998" pnpm run build)

# ── 4. Install Playwright Chromium ────────────────────────────────────────
echo "==> Installing Playwright Chromium browser..."
if command -v sudo >/dev/null 2>&1 || [ "$(id -u)" -eq 0 ]; then
  run_ui pnpm exec playwright install chromium --with-deps
else
  echo "    sudo not available; installing browser only (no system deps)..."
  run_ui pnpm exec playwright install chromium
fi

# ── 5. Start KMS server ───────────────────────────────────────────────────
SQLITE_DIR="$(mktemp -d)"
KMS_PID=""
PREVIEW_PID=""

cleanup() {
  echo "==> Cleaning up..."
  [ -n "${KMS_PID:-}" ] && { kill "${KMS_PID}" 2>/dev/null || true; }
  [ -n "${PREVIEW_PID:-}" ] && { kill "${PREVIEW_PID}" 2>/dev/null || true; }
  rm -rf "${SQLITE_DIR}"
  rm -rf "${SOFTHSM2_HOME}"
}
trap cleanup EXIT INT TERM

KMS_LOG="${SQLITE_DIR}/kms.log"
echo "==> Starting KMS server with SoftHSM2 (port 9998)..."
env \
  PATH="${PATH}" \
  LD_LIBRARY_PATH="${_LD}" \
  DYLD_LIBRARY_PATH="${_DYLD}" \
  SOFTHSM2_PKCS11_LIB="${SOFTHSM2_PKCS11_LIB_PATH:-}" \
  SOFTHSM2_CONF="${SOFTHSM2_CONF}" \
  RUST_LOG="cosmian_kms_server=info,cosmian_kms_server_database=info" \
  "${kms_bin}" \
  --database-type sqlite \
  --sqlite-path "${SQLITE_DIR}" \
  --port 9998 \
  --hostname "127.0.0.1" \
  --hsm-model softhsm2 \
  --hsm-admin admin \
  --hsm-slot "${SOFTHSM2_HSM_SLOT_ID}" \
  --hsm-password "${HSM_USER_PASSWORD}" \
  >"${KMS_LOG}" 2>&1 &
KMS_PID=$!

kms_wait_ready "http://127.0.0.1:9998/kmip/2_1" "${KMS_PID}" "${KMS_LOG}" 120

# ── 6. Pre-create test keys ───────────────────────────────────────────────
# All keys share a unique tag so Playwright tests can isolate them precisely
# even when the DB contains unrelated objects from prior test runs.
TEST_TAG="_pw_hsm_locate"
TS="$(date +%s)"
KMS_BASE_ARGS=(--url "http://127.0.0.1:9998")

echo "==> Creating 2 HSM AES-256 keys (slot ${SOFTHSM2_HSM_SLOT_ID})..."
env PATH="${PATH}" SOFTHSM2_CONF="${SOFTHSM2_CONF}" \
  "${ckms_bin}" "${KMS_BASE_ARGS[@]}" sym keys create \
  --algorithm aes --number-of-bits 256 \
  --tag "${TEST_TAG}" \
  "hsm::${SOFTHSM2_HSM_SLOT_ID}::pw_locate_aes1_${TS}"

env PATH="${PATH}" SOFTHSM2_CONF="${SOFTHSM2_CONF}" \
  "${ckms_bin}" "${KMS_BASE_ARGS[@]}" sym keys create \
  --algorithm aes --number-of-bits 256 \
  --tag "${TEST_TAG}" \
  "hsm::${SOFTHSM2_HSM_SLOT_ID}::pw_locate_aes2_${TS}"

echo "==> Creating 2 software AES-256 keys..."
env PATH="${PATH}" SOFTHSM2_CONF="${SOFTHSM2_CONF}" \
  "${ckms_bin}" "${KMS_BASE_ARGS[@]}" sym keys create \
  --algorithm aes --number-of-bits 256 \
  --tag "${TEST_TAG}"

env PATH="${PATH}" SOFTHSM2_CONF="${SOFTHSM2_CONF}" \
  "${ckms_bin}" "${KMS_BASE_ARGS[@]}" sym keys create \
  --algorithm aes --number-of-bits 256 \
  --tag "${TEST_TAG}"

echo "==> Test keys created (tag: ${TEST_TAG})."

# ── 7. Start Vite preview server ─────────────────────────────────────────
VITE_LOG="${SQLITE_DIR}/vite.log"
echo "==> Starting Vite preview server (port 5173)..."
(cd "${UI_DIR}" && pnpm preview --port 5173 --host 127.0.0.1 --strictPort) \
  >"${VITE_LOG}" 2>&1 &
PREVIEW_PID=$!

echo "==> Waiting for Vite preview to be ready..."
for i in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5173/ui/ 2>/dev/null || true)
  if [ -n "${code}" ] && [ "${code}" -ge 100 ] 2>/dev/null; then
    echo "    Vite preview ready after ${i}s (HTTP ${code})"
    break
  fi
  if [ "${i}" -eq 60 ]; then
    echo "ERROR: Vite preview did not become ready within 60 s" >&2
    exit 1
  fi
  sleep 1
done

# ── 8. Run Playwright HSM integration tests ───────────────────────────────
echo "==> Running Playwright HSM E2E tests..."
TEST_EXIT=0
(
  cd "${UI_DIR}"
  CI=true \
    PLAYWRIGHT_BASE_URL="http://127.0.0.1:5173" \
    PLAYWRIGHT_WORKERS="${PLAYWRIGHT_WORKERS:-4}" \
    PLAYWRIGHT_KMS_HAS_HSM=true \
    PLAYWRIGHT_HSM_TEST_TAG="${TEST_TAG}" \
    PLAYWRIGHT_HSM_KEY_COUNT=2 \
    PLAYWRIGHT_SW_KEY_COUNT=2 \
    pnpm exec playwright test tests/e2e/locate-hsm-real.spec.ts
) || TEST_EXIT=$?

# ── 9. Report server errors ───────────────────────────────────────────────
SERVER_ERRORS=$(grep -c ' ERROR ' "${KMS_LOG}" 2>/dev/null || true)
SERVER_WARNS=$(grep -c '  WARN ' "${KMS_LOG}" 2>/dev/null || true)

if [ "${SERVER_ERRORS}" -gt 0 ] || [ "${SERVER_WARNS}" -gt 0 ]; then
  echo ""
  echo "==> KMS server log summary: ${SERVER_ERRORS} error(s), ${SERVER_WARNS} warning(s)"
  echo "--- Server errors/warnings ---"
  grep -E ' (ERROR|WARN) ' "${KMS_LOG}" || true
  echo "--- End server errors/warnings ---"
  echo ""
fi

if [ "${TEST_EXIT}" -ne 0 ]; then
  echo "==> Playwright HSM tests FAILED (exit code ${TEST_EXIT})"
  echo "==> Full KMS server log: ${KMS_LOG}"
  exit "${TEST_EXIT}"
fi

echo "==> UI HSM E2E tests passed!"

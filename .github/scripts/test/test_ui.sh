#!/usr/bin/env bash
# ============================================================================
# test_ui.sh – Run Playwright E2E tests for the KMS web UI.
#
# When SoftHSM2 is available the KMS server is started with HSM support and
# test keys are pre-created via ckms so the HSM-specific Playwright tests
# run alongside the regular E2E suite in a single pass.
#
# Usage (via nix.sh):
#   bash .github/scripts/nix.sh --variant non-fips test ui
# ============================================================================
set -euo pipefail

# ── VARIANT default ─────────────────────────────────────────────────────────
# Default to non-fips when caller doesn't specify.
: "${VARIANT:=non-fips}"

# ── Paths & common helpers ───────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=.github/scripts/common.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../common.sh"

REPO_ROOT="$(get_repo_root "$SCRIPT_DIR")"
WASM_CRATE="${REPO_ROOT}/crate/clients/wasm"
UI_DIR="${REPO_ROOT}/ui"

init_build_env "$@"

run_ui() {
    (cd "${UI_DIR}" && "$@")
}

# Run pnpm with FIPS OpenSSL env vars stripped.
# pnpm uses MD4 in createBase32Hash (depPathToFilename) which is blocked
# by the FIPS provider loaded via LD_PRELOAD in the Nix CI shell.
# Stripping LD_PRELOAD/OPENSSL_CONF/OPENSSL_MODULES lets pnpm use the default
# OpenSSL provider; cargo/KMS builds are unaffected.
run_pnpm() {
    env -u LD_PRELOAD -u OPENSSL_CONF -u OPENSSL_MODULES pnpm "$@"
}

ensure_pnpm() {
    if ! command -v pnpm &>/dev/null; then
        npm install -g pnpm@10.17.1
    fi
}

# ── SoftHSM2 detection ──────────────────────────────────────────────────────
# softhsm2-util is required; abort early with a clear message if not found.
SOFTHSM2_LIB_DIR=""
SOFTHSM2_PKCS11_LIB_PATH=""
SOFTHSM2_HOME=""
SOFTHSM2_CONF=""
SOFTHSM2_HSM_SLOT_ID=""
HSM_USER_PASSWORD="12345678"

if ! command -v softhsm2-util >/dev/null 2>&1; then
    echo "ERROR: softhsm2-util not found. Please install SoftHSM2 before running UI E2E tests." >&2
    exit 1
fi

SOFTHSM2_BIN_PATH="$(command -v softhsm2-util)"
SOFTHSM2_PREFIX="$(dirname "$(dirname "${SOFTHSM2_BIN_PATH}")")"
if [ -d "${SOFTHSM2_PREFIX}/lib/softhsm" ]; then
    SOFTHSM2_LIB_DIR="${SOFTHSM2_PREFIX}/lib/softhsm"
elif [ -d "${SOFTHSM2_PREFIX}/lib" ]; then
    SOFTHSM2_LIB_DIR="${SOFTHSM2_PREFIX}/lib"
fi
SOFTHSM2_PKCS11_LIB_PATH="${SOFTHSM2_LIB_DIR:+${SOFTHSM2_LIB_DIR}/libsofthsm2.so}"
# Library search paths (needed for cargo build and KMS binary at runtime).
_LD="${SOFTHSM2_LIB_DIR:+${SOFTHSM2_LIB_DIR}:}${NIX_OPENSSL_OUT:+${NIX_OPENSSL_OUT}/lib:}${LD_LIBRARY_PATH:-}"
_DYLD="${SOFTHSM2_LIB_DIR:+${SOFTHSM2_LIB_DIR}:}${NIX_OPENSSL_OUT:+${NIX_OPENSSL_OUT}/lib:}${DYLD_LIBRARY_PATH:-}"

# ── SoftHSM2 token initialization ───────────────────────────────────────────
echo "========================================="
echo "SoftHSM2 detected – initialising token"
echo "========================================="

export SOFTHSM2_HOME="${REPO_ROOT}/.softhsm2-ui-test"
mkdir -p "${SOFTHSM2_HOME}/tokens"
export SOFTHSM2_CONF="${SOFTHSM2_HOME}/softhsm2.conf"
echo "directories.tokendir = ${SOFTHSM2_HOME}/tokens" >"${SOFTHSM2_CONF}"

softhsm2-util --version

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

# ── 1. Build WASM ────────────────────────────────────────────────────────────
if [ "${VARIANT}" = "non-fips" ]; then
    echo "==> Building WASM (non-fips, web target) …"
else
    echo "==> Building WASM (fips, web target) …"
fi
(
    cd "${WASM_CRATE}"
    # Unset variables that inject macOS-specific flags into the wasm32 linker.
    # RUSTFLAGS/LDFLAGS are set by ensure_macos_frameworks_ldflags in common.sh
    # and contain -F<sdk>/System/Library/Frameworks which breaks wasm32 linking.
    unset SDKROOT MACOSX_DEPLOYMENT_TARGET RUSTFLAGS LDFLAGS \
        OPENSSL_DIR OPENSSL_LIB_DIR OPENSSL_INCLUDE_DIR
    if [ "${VARIANT}" = "non-fips" ]; then
        wasm-pack build --target web --features non-fips
    else
        wasm-pack build --target web
    fi
)

PKG_SRC="${WASM_CRATE}/pkg"
PKG_DST="${UI_DIR}/src/wasm/pkg"
mkdir -p "${PKG_DST}"
cp -r "${PKG_SRC}/." "${PKG_DST}/"

# ── 2. Build KMS server + ckms CLI ───────────────────────────────────────────
echo "==> Building KMS server and ckms CLI …"
env \
    PATH="${PATH}" \
    LD_LIBRARY_PATH="${_LD}" \
    DYLD_LIBRARY_PATH="${_DYLD}" \
    cargo build -p cosmian_kms_server -p ckms \
    "${FEATURES_FLAG[@]}"

CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"
kms_bin="${CARGO_TARGET_DIR}/debug/cosmian_kms"
ckms_bin="${CARGO_TARGET_DIR}/debug/ckms"

# ── 3. Install JS deps and build UI ─────────────────────────────────────────
ensure_pnpm

echo "==> Installing UI dependencies …"
rm -rf "${UI_DIR}/node_modules"
run_ui run_pnpm install --frozen-lockfile

echo "==> Building UI (VITE_KMS_URL=http://127.0.0.1:9998, VITE_DEV_MODE=true) …"
(cd "${UI_DIR}" && {
    chmod -R u+w dist >/dev/null 2>&1 || true
    rm -rf dist >/dev/null 2>&1 || true
})
(cd "${UI_DIR}" && env -u LD_PRELOAD -u OPENSSL_CONF -u OPENSSL_MODULES VITE_KMS_URL="http://127.0.0.1:9998" VITE_DEV_MODE="true" pnpm run build:vite)

# ── 4. Install Playwright's Chromium browser ─────────────────────────────────
echo "==> Installing Playwright Chromium browser …"
if command -v sudo >/dev/null 2>&1 || [ "$(id -u)" -eq 0 ]; then
    run_ui run_pnpm exec playwright install chromium --with-deps
else
    echo "    sudo not available; installing browser only (no system deps) …"
    run_ui run_pnpm exec playwright install chromium
fi

# ── 5. Start KMS server ─────────────────────────────────────────────────────
SQLITE_DIR="$(mktemp -d)"
KMS_PID=""
PREVIEW_PID=""

cleanup() {
    echo "==> Cleaning up …"
    [ -n "${KMS_PID:-}" ] && { kill "${KMS_PID}" 2>/dev/null || true; }
    [ -n "${PREVIEW_PID:-}" ] && { kill "${PREVIEW_PID}" 2>/dev/null || true; }
    # Kill any remaining node/vite child processes that outlived pnpm.
    fuser -k 5173/tcp 2>/dev/null || true
    rm -rf "${SQLITE_DIR}"
    [ -n "${SOFTHSM2_HOME:-}" ] && rm -rf "${SOFTHSM2_HOME}"
}
trap cleanup EXIT INT TERM

# Kill any leftover KMS server from a previous interrupted run.
if lsof -ti :9998 >/dev/null 2>&1; then
    echo "==> Killing stale process on port 9998 …"
    lsof -ti :9998 | xargs kill -9 2>/dev/null || true
    sleep 1
fi
if lsof -ti :5173 >/dev/null 2>&1; then
    echo "==> Killing stale process on port 5173 …"
    lsof -ti :5173 | xargs kill -9 2>/dev/null || true
    sleep 1
fi

KMS_LOG="${SQLITE_DIR}/kms-server.log"
KMS_CONF_FILE="${SQLITE_DIR}/kms.toml"

# Generate a TOML config file.
# Using --config bypasses the default-path detection that errors when
# /etc/cosmian/kms.toml exists alongside extra CLI arguments (macOS dev
# machines).  ui_index_html_folder is intentionally omitted: the UI is
# served by the Vite preview process on port 5173; omitting this flag also
# avoids a known actix-files interaction that causes the server to exit
# immediately after worker initialization on Linux CI.
cat >"${KMS_CONF_FILE}" <<HSMEOF
default_username = "admin"
vendor_identification = "test_vendor"
hsm_model = "softhsm2"
hsm_admin = ["admin"]
hsm_slot = [${SOFTHSM2_HSM_SLOT_ID}]
hsm_password = ["${HSM_USER_PASSWORD}"]

[db]
database_type = "sqlite"
sqlite_path = "${SQLITE_DIR}"
clear_database = true

[http]
hostname = "127.0.0.1"
port = 9998
cors_allowed_origins = ["http://127.0.0.1:5173"]
HSMEOF

echo "==> Starting KMS server with SoftHSM2 (port 9998) …"
env \
    PATH="${PATH}" \
    LD_LIBRARY_PATH="${_LD}" \
    DYLD_LIBRARY_PATH="${_DYLD}" \
    SOFTHSM2_PKCS11_LIB="${SOFTHSM2_PKCS11_LIB_PATH}" \
    SOFTHSM2_CONF="${SOFTHSM2_CONF}" \
    RUST_LOG="cosmian_kms_server=info,cosmian_kms_server_database=info" \
    "${kms_bin}" \
    --config "${KMS_CONF_FILE}" \
    >"${KMS_LOG}" 2>&1 &
KMS_PID=$!

echo "==> Waiting for KMS to be ready …"
kms_wait_ready "http://127.0.0.1:9998/kmip/2_1" "${KMS_PID}" "${KMS_LOG}" 300

# ── 6. Pre-create test keys ─────────────────────────────────────────────────
TS="$(date +%s)"
KMS_BASE_ARGS=(--url "http://127.0.0.1:9998")

echo "==> Creating 2 HSM AES-256 keys (slot ${SOFTHSM2_HSM_SLOT_ID}) …"
# Note: HSM keys do not support tags (the HsmStore silently ignores them).
env PATH="${PATH}" SOFTHSM2_CONF="${SOFTHSM2_CONF}" \
    "${ckms_bin}" "${KMS_BASE_ARGS[@]}" sym keys create \
    --algorithm aes --number-of-bits 256 \
    "hsm::${SOFTHSM2_HSM_SLOT_ID}::pw_locate_aes1_${TS}"

env PATH="${PATH}" SOFTHSM2_CONF="${SOFTHSM2_CONF}" \
    "${ckms_bin}" "${KMS_BASE_ARGS[@]}" sym keys create \
    --algorithm aes --number-of-bits 256 \
    "hsm::${SOFTHSM2_HSM_SLOT_ID}::pw_locate_aes2_${TS}"

echo "==> HSM test keys created."

# ── 7. Start Vite preview server ────────────────────────────────────────────
echo "==> Starting Vite preview server (port 5173) …"
VITE_PREVIEW_LOG="${SQLITE_DIR}/vite-preview.log"
(cd "${UI_DIR}" && env -u LD_PRELOAD -u OPENSSL_CONF -u OPENSSL_MODULES pnpm exec vite preview --port 5173 --host 127.0.0.1 --strictPort) >"${VITE_PREVIEW_LOG}" 2>&1 &
PREVIEW_PID=$!

echo "==> Waiting for Vite preview to be ready …"
for i in $(seq 1 60); do
    # Check if process is still alive
    if ! kill -0 "${PREVIEW_PID}" 2>/dev/null; then
        echo "ERROR: Vite preview process (PID ${PREVIEW_PID}) exited unexpectedly after ${i}s" >&2
        echo "--- Vite preview log ---"
        cat "${VITE_PREVIEW_LOG}" || true
        echo "--- End Vite preview log ---"
        exit 1
    fi
    # Use bash /dev/tcp instead of nc/curl to avoid OpenSSL initialisation
    # failures caused by the FIPS LD_PRELOAD bootstrap, and to avoid
    # relying on nc which is not in the Nix shell PATH.
    if (echo >/dev/tcp/127.0.0.1/5173) 2>/dev/null; then
        echo "    Vite preview ready after ${i}s (port open)"
        break
    fi
    if [ "${i}" -eq 60 ]; then
        echo "ERROR: Vite preview did not become ready within 60 s" >&2
        echo "--- Vite preview log ---"
        cat "${VITE_PREVIEW_LOG}" || true
        echo "--- End Vite preview log ---"
        exit 1
    fi
    sleep 1
done

# ── 8. Run Playwright E2E tests ─────────────────────────────────────────────
echo "==> Running Playwright E2E tests (workers=${PLAYWRIGHT_WORKERS:-10}) …"
TEST_EXIT=0
PW_ENV=(
    CI=true
    PLAYWRIGHT_BASE_URL="http://127.0.0.1:5173"
    PLAYWRIGHT_WORKERS="${PLAYWRIGHT_WORKERS:-10}"
    PLAYWRIGHT_HSM_KEY_COUNT=2
)
if [ "${VARIANT}" = "fips" ]; then
    PW_ENV+=(PLAYWRIGHT_FIPS_MODE=true)
fi

(cd "${UI_DIR}" && env -u LD_PRELOAD -u OPENSSL_CONF -u OPENSSL_MODULES "${PW_ENV[@]}" pnpm run test:e2e) || TEST_EXIT=$?

# ── 9. Report server errors ─────────────────────────────────────────────────
SERVER_ERRORS=$(grep -c ' ERROR ' "${KMS_LOG}" 2>/dev/null || true)
SERVER_WARNS=$(grep -c ' WARN ' "${KMS_LOG}" 2>/dev/null || true)

if [ "${SERVER_ERRORS}" -gt 0 ] || [ "${SERVER_WARNS}" -gt 0 ]; then
    echo ""
    echo "==> KMS server log summary: ${SERVER_ERRORS} error(s), ${SERVER_WARNS} warning(s)"
    echo "--- Server errors/warnings ---"
    grep -E ' (ERROR|WARN) ' "${KMS_LOG}" || true
    echo "--- End server errors/warnings ---"
    echo ""
fi

if [ "${TEST_EXIT}" -ne 0 ]; then
    echo "==> Playwright tests FAILED (exit code ${TEST_EXIT})"
    echo "==> Full KMS server log: ${KMS_LOG}"
    exit "${TEST_EXIT}"
fi

echo "==> UI E2E tests passed!"

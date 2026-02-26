#!/usr/bin/env bash
# ============================================================================
# test_ui.sh – Run Playwright E2E tests for the KMS web UI.
#
# This script mirrors the structure of test_wasm.sh:
#   1.  Build the WASM package (non-fips, web target).
#   2.  Copy the generated pkg/ into ui/src/wasm/pkg/.
#   3.  Install JS dependencies and build the Vite bundle, baking the local
#       KMS URL into the bundle via VITE_KMS_URL.
#   4.  Install Playwright's Chromium browser.
#   5.  Start the KMS server in the background and wait for it to be ready.
#   6.  Start `vite preview` in the background.
#   7.  Run `pnpm run test:e2e` (Playwright).
#
# The script is a no-op in FIPS mode (the matrix exclude in test_all.yml is
# the primary guard; this is defense-in-depth).
#
# Usage (via nix.sh):
#   bash .github/scripts/nix.sh --variant non-fips test ui
# ============================================================================
set -euo pipefail

# ── FIPS guard ───────────────────────────────────────────────────────────────
if [ "${VARIANT:-}" = "fips" ]; then
    echo "UI E2E tests are skipped in FIPS mode." >&2
    exit 0
fi

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WASM_CRATE="${REPO_ROOT}/crate/wasm"
UI_DIR="${REPO_ROOT}/ui"

# ── Build-profile helpers (mirrors test_wasm.sh) ─────────────────────────────
RELEASE_FLAG=""
if [ "${BUILD_PROFILE:-}" = "release" ]; then
    RELEASE_FLAG="--release"
fi

run_wasm_pack() {
    (cd "${WASM_CRATE}" && wasm-pack "$@")
}

run_ui() {
    (cd "${UI_DIR}" && "$@")
}

ensure_pnpm() {
    if ! command -v pnpm &>/dev/null; then
        npm install -g pnpm
    fi
}

# ── 1. Build WASM ────────────────────────────────────────────────────────────
echo "==> Building WASM (non-fips, web target) …"
run_wasm_pack build --target web --features non-fips

# Copy generated artefacts into the UI source tree.
PKG_SRC="${WASM_CRATE}/pkg"
PKG_DST="${UI_DIR}/src/wasm/pkg"
mkdir -p "${PKG_DST}"
cp -r "${PKG_SRC}/." "${PKG_DST}/"

# ── 2. Install JS deps and build UI ──────────────────────────────────────────
ensure_pnpm

echo "==> Installing UI dependencies …"
run_ui pnpm install --frozen-lockfile

echo "==> Building UI (VITE_KMS_URL=http://127.0.0.1:9998) …"
(cd "${UI_DIR}" && {
    chmod -R u+w dist >/dev/null 2>&1 || true
    rm -rf dist >/dev/null 2>&1 || true
})
(cd "${UI_DIR}" && VITE_KMS_URL="http://127.0.0.1:9998" pnpm run build)

# ── 3. Install Playwright's Chromium browser ─────────────────────────────────
echo "==> Installing Playwright Chromium browser …"
if command -v sudo >/dev/null 2>&1 || [ "$(id -u)" -eq 0 ]; then
    # On typical GitHub runners, Playwright can install system deps via sudo.
    run_ui pnpm exec playwright install chromium --with-deps
else
    # In nix-shell --pure environments, sudo may not be present on PATH.
    # Installing browsers still works; system deps are expected to be available
    # from the base image/runner.
    echo "    sudo not available; installing browser only (no system deps) …"
    run_ui pnpm exec playwright install chromium
fi

# ── 4. Start KMS server ───────────────────────────────────────────────────────
SQLITE_DIR="$(mktemp -d)"
KMS_PID=""
PREVIEW_PID=""

cleanup() {
    echo "==> Cleaning up …"
    if [ -n "${KMS_PID}" ]; then
        kill "${KMS_PID}" 2>/dev/null || true
    fi
    if [ -n "${PREVIEW_PID}" ]; then
        kill "${PREVIEW_PID}" 2>/dev/null || true
    fi
    rm -rf "${SQLITE_DIR}"
}
trap cleanup EXIT INT TERM

echo "==> Starting KMS server (non-fips, sqlite) …"
KMS_CONF_FILE="${SQLITE_DIR}/kms.toml"
cat >"${KMS_CONF_FILE}" <<EOF
default_username = "admin"

[db]
database_type = "sqlite"
sqlite_path = "${SQLITE_DIR}"
clear_database = true

[http]
hostname = "127.0.0.1"
port = 9998
EOF

# Force an explicit config to avoid picking up a host-installed default config
# at /etc/cosmian/kms.toml (which would ignore CLI args and may crash on log perms).
# shellcheck disable=SC2086
cargo run ${RELEASE_FLAG} -p cosmian_kms_server --bin cosmian_kms \
    --features non-fips \
    -- \
    --config "${KMS_CONF_FILE}" &
KMS_PID=$!

echo "==> Waiting for KMS to be ready …"
for i in $(seq 1 300); do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" -d '{}' \
        http://127.0.0.1:9998/kmip/2_1 2>/dev/null || true)
    if [ -n "${code}" ] && [ "${code}" -ge 100 ] 2>/dev/null; then
        echo "    KMS ready after ${i}s (HTTP ${code})"
        break
    fi
    if [ "${i}" -eq 300 ]; then
        echo "ERROR: KMS did not become ready within 300 s" >&2
        exit 1
    fi
    sleep 1
done

# ── 5. Start Vite preview server ─────────────────────────────────────────────
echo "==> Starting Vite preview server (port 5173) …"
VITE_PREVIEW_LOG="${SQLITE_DIR}/vite-preview.log"
(cd "${UI_DIR}" && pnpm preview --port 5173 --host 127.0.0.1 --strictPort) >"${VITE_PREVIEW_LOG}" 2>&1 &
PREVIEW_PID=$!

echo "==> Waiting for Vite preview to be ready …"
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

# ── 6. Run Playwright E2E tests ───────────────────────────────────────────────
echo "==> Running Playwright E2E tests …"
(cd "${UI_DIR}" && CI=true PLAYWRIGHT_BASE_URL="http://127.0.0.1:5173" pnpm run test:e2e)

echo "==> UI E2E tests passed!"

#!/usr/bin/env bash
# ============================================================================
# test_ui_oidc.sh – TRUE end-to-end Playwright tests for the KMS Web UI OIDC
# login flow against the real Auth0 IdP configured in
# test_data/configs/server/test/auth_ui.toml (demo-kms.eu.auth0.com).
#
# Requires (skips cleanly if unset):
#   OIDC_CLIENT_SECRET   Auth0 application client secret (server-side).
#   OIDC_TEST_USERNAME   Test user email (verified `email` claim).
#   OIDC_TEST_PASSWORD   Test user password.
# Optional overrides (default to the demo tenant):
#   OIDC_CLIENT_ID  (default rGRvFjjLDBro8gRwxghKuiu207wKfKyG)
#   OIDC_ISSUER_URL (default https://demo-kms.eu.auth0.com/)
#   OIDC_LOGOUT_URL (default https://demo-kms.eu.auth0.com/v2/logout)
#
# The Auth0 app has a pre-registered redirect URI, so the KMS runs on the
# FIXED origin http://127.0.0.1:9998 (no dynamic port).
#
# Usage:
#   OIDC_CLIENT_SECRET=... OIDC_TEST_USERNAME=... OIDC_TEST_PASSWORD=... \
#     bash .github/scripts/test/test_ui_oidc.sh
# ============================================================================
set -euo pipefail

: "${VARIANT:=non-fips}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=.github/scripts/common.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../common.sh"

REPO_ROOT="$(get_repo_root "$SCRIPT_DIR")"
UI_DIR="${REPO_ROOT}/ui"
WASM_CRATE="${REPO_ROOT}/crate/clients/wasm"

init_build_env "$@"

# ── Required secrets ────────────────────────────────────────────────────────
if [ -z "${OIDC_CLIENT_SECRET:-}" ] || [ -z "${OIDC_TEST_USERNAME:-}" ] || [ -z "${OIDC_TEST_PASSWORD:-}" ]; then
  echo "==> SKIP: OIDC_CLIENT_SECRET / OIDC_TEST_USERNAME / OIDC_TEST_PASSWORD not set."
  echo "         These true-E2E OIDC tests need a live Auth0 tenant + test user."
  exit 0
fi

OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-rGRvFjjLDBro8gRwxghKuiu207wKfKyG}"
OIDC_ISSUER_URL="${OIDC_ISSUER_URL:-https://demo-kms.eu.auth0.com/}"
OIDC_LOGOUT_URL="${OIDC_LOGOUT_URL:-https://demo-kms.eu.auth0.com/v2/logout}"

KMS_HOST="127.0.0.1"
KMS_PORT="9998" # must match the Auth0-registered redirect URI

run_pnpm() {
  env -u LD_PRELOAD -u OPENSSL_CONF -u OPENSSL_MODULES pnpm "$@"
}

ensure_pnpm() {
  if ! command -v pnpm &>/dev/null; then
    npm install -g pnpm@10.17.1
  fi
}

# ── 1. Build WASM ────────────────────────────────────────────────────────────
echo "==> Building WASM (${VARIANT}, web target) …"
(
  cd "${WASM_CRATE}"
  unset SDKROOT MACOSX_DEPLOYMENT_TARGET RUSTFLAGS LDFLAGS \
    OPENSSL_DIR OPENSSL_LIB_DIR OPENSSL_INCLUDE_DIR
  if [ "${VARIANT}" = "non-fips" ]; then
    wasm-pack build --target web --features non-fips
  else
    wasm-pack build --target web
  fi
)
mkdir -p "${UI_DIR}/src/wasm/pkg"
cp -r "${WASM_CRATE}/pkg/." "${UI_DIR}/src/wasm/pkg/"

# ── 2. Build KMS server ──────────────────────────────────────────────────────
echo "==> Building KMS server …"
cargo build -p cosmian_kms_server "${FEATURES_FLAG[@]}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"
kms_bin="${CARGO_TARGET_DIR}/debug/cosmian_kms"

# ── 3. Install JS deps and build UI (no VITE_DEV_MODE / VITE_KMS_URL) ───────
ensure_pnpm
echo "==> Installing UI dependencies …"
rm -rf "${UI_DIR}/node_modules"
(cd "${UI_DIR}" && run_pnpm install --frozen-lockfile)

echo "==> Building UI (real auth_method fetch, same-origin) …"
(cd "${UI_DIR}" && {
  chmod -R u+w dist >/dev/null 2>&1 || true
  rm -rf dist >/dev/null 2>&1 || true
})
(cd "${UI_DIR}" && run_pnpm run build:vite)

echo "==> Installing Playwright Chromium browser …"
if command -v sudo >/dev/null 2>&1 || [ "$(id -u)" -eq 0 ]; then
  (cd "${UI_DIR}" && run_pnpm exec playwright install chromium --with-deps)
else
  (cd "${UI_DIR}" && run_pnpm exec playwright install chromium)
fi

# ── Temp dirs / config ───────────────────────────────────────────────────────
WORK_DIR="$(mktemp -d)"
KMS_CONF_FILE="${WORK_DIR}/kms.toml"
KMS_LOG="${WORK_DIR}/kms-server.log"
KMS_SQLITE_DIR="${WORK_DIR}/kms-sqlite"
mkdir -p "${KMS_SQLITE_DIR}"

KMS_PID=""
cleanup() {
  echo "==> Cleaning up …"
  [ -n "${KMS_PID:-}" ] && { kill "${KMS_PID}" 2>/dev/null || true; }
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT INT TERM

SESSION_SALT="$(openssl rand -hex 32)"

cat >"${KMS_CONF_FILE}" <<EOF
vendor_identification = "test_vendor"

[http]
port = ${KMS_PORT}
hostname = "${KMS_HOST}"
kms_public_url = "http://${KMS_HOST}:${KMS_PORT}"

[db]
database_type = "sqlite"
sqlite_path = "${KMS_SQLITE_DIR}"
clear_database = true

[idp_auth]
jwt_auth_provider = ["${OIDC_ISSUER_URL},${OIDC_ISSUER_URL}.well-known/jwks.json,"]

[ui_config]
ui_index_html_folder = "${UI_DIR}/dist"
ui_session_salt = "${SESSION_SALT}"

[ui_config.ui_oidc_auth]
ui_oidc_client_id = "${OIDC_CLIENT_ID}"
ui_oidc_client_secret = "${OIDC_CLIENT_SECRET}"
ui_oidc_issuer_url = "${OIDC_ISSUER_URL}"
ui_oidc_logout_url = "${OIDC_LOGOUT_URL}"

[logging]
rust_log = "info,cosmian_kms=debug"
quiet = false
log_to_syslog = false
environment = "development"
ansi_colors = true
EOF

echo "==> Starting KMS server (http://${KMS_HOST}:${KMS_PORT}) …"
"${kms_bin}" --config "${KMS_CONF_FILE}" >"${KMS_LOG}" 2>&1 &
KMS_PID=$!

echo "==> Waiting for KMS to report JWT auth (OIDC discovery at startup) …"
for i in $(seq 1 60); do
  if ! kill -0 "${KMS_PID}" 2>/dev/null; then
    echo "ERROR: KMS server process exited early; log:" >&2
    cat "${KMS_LOG}" >&2
    exit 1
  fi
  if curl -sS --max-time 2 "http://${KMS_HOST}:${KMS_PORT}/ui/auth_method" 2>/dev/null | grep -q '"JWT"'; then
    echo "    KMS ready after ${i}s"
    break
  fi
  if [ "${i}" -eq 60 ]; then
    echo "ERROR: KMS did not report JWT auth within 60s (check OIDC discovery); log:" >&2
    cat "${KMS_LOG}" >&2
    exit 1
  fi
  sleep 1
done

# ── 4. Run Playwright OIDC E2E tests ────────────────────────────────────────
echo "==> Running Playwright OIDC E2E tests …"
TEST_EXIT=0
(cd "${UI_DIR}" && env -u LD_PRELOAD -u OPENSSL_CONF -u OPENSSL_MODULES \
  CI=true \
  PLAYWRIGHT_BASE_URL="http://${KMS_HOST}:${KMS_PORT}" \
  OIDC_TEST_USERNAME="${OIDC_TEST_USERNAME}" \
  OIDC_TEST_PASSWORD="${OIDC_TEST_PASSWORD}" \
  pnpm exec playwright test --config playwright.oidc.config.ts) || TEST_EXIT=$?

if [ "${TEST_EXIT}" -ne 0 ]; then
  echo "==> Playwright OIDC tests FAILED (exit code ${TEST_EXIT})"
  echo "--- KMS server log (last 80 lines) ---"
  tail -80 "${KMS_LOG}" || true
  exit "${TEST_EXIT}"
fi

echo "==> Playwright OIDC tests PASSED"

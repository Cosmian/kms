#!/usr/bin/env bash
# ============================================================================
# test_ui_auth.sh – Run TRUE end-to-end Playwright tests for the KMS Web UI
# login flow against a real Cosmian authentication server.
#
# Unlike test_ui.sh (which builds the UI with VITE_DEV_MODE=true, so the
# login form never renders), this harness:
#   1. Builds the UI WITHOUT VITE_DEV_MODE/VITE_KMS_URL, so `authMethod` is
#      fetched from the real `GET /ui/auth_method` and the Cosmian
#      username/password login form actually renders.
#   2. Builds and starts a real Cosmian authentication server (from the
#      sibling `authentication` repo) using its bundled dev config
#      (in-memory SQLite, bundled test certs, seeded `admin`/`change_me`).
#   3. Builds and starts the KMS server configured with [cosmian_auth],
#      serving the UI itself on the SAME origin (required for the session
#      cookie set by POST /ui/login_as to work without cross-origin
#      complications).
#   4. Runs `pnpm run test:e2e:auth` (tests/e2e-auth/, playwright.auth.config.ts).
#
# The `authentication` repo is expected as a sibling checkout of this repo
# (../authentication) — override with AUTH_SERVER_REPO if yours lives
# elsewhere.
#
# Usage:
#   bash .github/scripts/test/test_ui_auth.sh
#   AUTH_SERVER_REPO=/path/to/authentication bash .github/scripts/test/test_ui_auth.sh
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

AUTH_SERVER_REPO="${AUTH_SERVER_REPO:-${REPO_ROOT}/authentication}"
if [ ! -f "${AUTH_SERVER_REPO}/server/auth_verifier.dev.toml" ]; then
  echo "ERROR: Cosmian authentication server repo not found at '${AUTH_SERVER_REPO}'." >&2
  echo "       Set AUTH_SERVER_REPO to the path of a checkout of the 'authentication' repo." >&2
  exit 1
fi

run_pnpm() {
  env -u LD_PRELOAD -u OPENSSL_CONF -u OPENSSL_MODULES pnpm "$@"
}

ensure_pnpm() {
  if ! command -v pnpm &>/dev/null; then
    npm install -g pnpm@10.17.1
  fi
}

_get_free_port() {
  node -e "const net=require('node:net'); const server=net.createServer(); server.listen(0,'127.0.0.1',()=>{console.log(server.address().port); server.close();});"
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

# ── 3. Cosmian authentication server binary ──────────────────────────────────
# The binary must be built BEFORE entering the nix shell (the mise task does
# this), because the authentication submodule requires rustc ≥ 1.94 while the
# nix shell pins an older version.  We just resolve the path here.
auth_bin="${AUTH_SERVER_REPO}/target/debug/auth_verifier"
if [ ! -x "${auth_bin}" ]; then
  echo "ERROR: auth_verifier binary not found at '${auth_bin}'." >&2
  echo "       The mise task should have built it before entering the nix shell." >&2
  exit 1
fi
echo "==> Using auth_verifier: ${auth_bin}"

# ── Dynamic ports ────────────────────────────────────────────────────────────
AUTH_PORT=$(_get_free_port)
KMS_PORT=$(_get_free_port)
echo "==> Using dynamic ports: AUTH=${AUTH_PORT}, KMS=${KMS_PORT}"

# ── 4. Install JS deps and build UI (no VITE_DEV_MODE / VITE_KMS_URL) ───────
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

# ── Temp dirs / config files ─────────────────────────────────────────────────
WORK_DIR="$(mktemp -d)"
AUTH_CONF_FILE="${WORK_DIR}/auth_server.toml"
KMS_CONF_FILE="${WORK_DIR}/kms.toml"
AUTH_LOG="${WORK_DIR}/auth-server.log"
KMS_LOG="${WORK_DIR}/kms-server.log"
KMS_SQLITE_DIR="${WORK_DIR}/kms-sqlite"
mkdir -p "${KMS_SQLITE_DIR}"

AUTH_PID=""
KMS_PID=""
cleanup() {
  echo "==> Cleaning up …"
  [ -n "${KMS_PID:-}" ] && { kill "${KMS_PID}" 2>/dev/null || true; }
  [ -n "${AUTH_PID:-}" ] && { kill "${AUTH_PID}" 2>/dev/null || true; }
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT INT TERM

# Auth server config: the bundled dev.toml with the port substituted.
# Paths inside (tls_params, admin_ui_path) are relative to AUTH_SERVER_REPO,
# which is why the server is started with that as its cwd.
sed "s/^host_port = .*/host_port = ${AUTH_PORT}/" \
  "${AUTH_SERVER_REPO}/server/auth_verifier.dev.toml" >"${AUTH_CONF_FILE}"

echo "==> Starting Cosmian authentication server (port ${AUTH_PORT}) …"
(cd "${AUTH_SERVER_REPO}" && "${auth_bin}" "${AUTH_CONF_FILE}") >"${AUTH_LOG}" 2>&1 &
AUTH_PID=$!

echo "==> Waiting for authentication server to be ready …"
for i in $(seq 1 60); do
  if ! kill -0 "${AUTH_PID}" 2>/dev/null; then
    echo "ERROR: authentication server process exited early; log:" >&2
    cat "${AUTH_LOG}" >&2
    exit 1
  fi
  if curl -sS --max-time 2 --insecure -o /dev/null -w "%{http_code}" \
    "https://127.0.0.1:${AUTH_PORT}/.well-known/jwks.json" 2>/dev/null | grep -q '^200$'; then
    echo "    Authentication server ready after ${i}s"
    break
  fi
  if [ "${i}" -eq 60 ]; then
    echo "ERROR: authentication server did not become ready within 60s; log:" >&2
    cat "${AUTH_LOG}" >&2
    exit 1
  fi
  sleep 1
done

# KMS config: cosmian_auth pointed at the auth server above, serving the UI
# itself on the same origin as the API (required for the session cookie).
cat >"${KMS_CONF_FILE}" <<EOF
vendor_identification = "test_vendor"

[http]
port = ${KMS_PORT}
hostname = "localhost"
kms_public_url = "http://localhost:${KMS_PORT}"

[db]
database_type = "sqlite"
sqlite_path = "${KMS_SQLITE_DIR}"
clear_database = true

[cosmian_auth]
cosmian_auth_server_url = "https://localhost:${AUTH_PORT}"
cosmian_auth_realm = "_"
cosmian_auth_accept_invalid_certs = true

[ui_config]
ui_index_html_folder = "${UI_DIR}/dist"

[logging]
rust_log = "info,cosmian_kms=debug"
quiet = false
log_to_syslog = false
environment = "development"
ansi_colors = true
EOF

echo "==> Starting KMS server (port ${KMS_PORT}) …"
"${kms_bin}" --config "${KMS_CONF_FILE}" >"${KMS_LOG}" 2>&1 &
KMS_PID=$!

echo "==> Waiting for KMS to be ready with COSMIAN auth …"
for i in $(seq 1 60); do
  if ! kill -0 "${KMS_PID}" 2>/dev/null; then
    echo "ERROR: KMS server process exited early; log:" >&2
    cat "${KMS_LOG}" >&2
    exit 1
  fi
  if curl -sS --max-time 2 "http://127.0.0.1:${KMS_PORT}/ui/auth_method" 2>/dev/null | grep -q '"COSMIAN"'; then
    echo "    KMS ready after ${i}s"
    break
  fi
  if [ "${i}" -eq 60 ]; then
    echo "ERROR: KMS server did not report COSMIAN auth within 60s; log:" >&2
    cat "${KMS_LOG}" >&2
    exit 1
  fi
  sleep 1
done

# ── 5. Run Playwright E2E tests ─────────────────────────────────────────────
echo "==> Running Playwright auth E2E tests …"
TEST_EXIT=0
(cd "${UI_DIR}" && env -u LD_PRELOAD -u OPENSSL_CONF -u OPENSSL_MODULES \
  CI=true \
  PLAYWRIGHT_BASE_URL="http://localhost:${KMS_PORT}" \
  pnpm run test:e2e:auth) || TEST_EXIT=$?

if [ "${TEST_EXIT}" -ne 0 ]; then
  echo "==> Playwright auth tests FAILED (exit code ${TEST_EXIT})"
  echo "--- KMS server log (last 80 lines) ---"
  tail -80 "${KMS_LOG}" || true
  echo "--- Authentication server log (last 80 lines) ---"
  tail -80 "${AUTH_LOG}" || true
  exit "${TEST_EXIT}"
fi

echo "==> Playwright auth tests PASSED"

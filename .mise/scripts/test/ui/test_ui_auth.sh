#!/usr/bin/env bash
# ============================================================================
# test_ui_auth.sh – Run TRUE end-to-end Playwright tests for the KMS Web UI
# login flow against a real Authentication Verifier.
#
# Unlike test_ui.sh (which builds the UI with VITE_DEV_MODE=true, so the
# login form never renders), this harness:
#   1. Builds the UI WITHOUT VITE_DEV_MODE/VITE_KMS_URL, so `authMethod` is
#      fetched from the real `GET /ui/auth_method` and the
#      Authentication Verifier username/password login form actually renders.
#   2. Starts a real Authentication Verifier from a complete test_data fixture,
#      then uses its admin API to create realm `kms` and user `kms-user`.
#   3. Builds and starts the KMS server configured with [auth_verifier],
#      serving the UI itself on the SAME origin (required for the session
#      cookie set by POST /ui/login_as to work without cross-origin
#      complications).
#   4. Runs `pnpm run test:e2e:auth` (tests/e2e-auth/, playwright.auth.config.ts).
#
# The `authentication` repo is expected as a sibling checkout of this repo
# (../authentication) — override with AUTH_VERIFIER_REPO if yours lives
# elsewhere.
#
# Usage:
#   bash .mise/scripts/test/ui/test_ui_auth.sh
#   AUTH_VERIFIER_REPO=/path/to/authentication bash .mise/scripts/test/ui/test_ui_auth.sh
# ============================================================================
set -euo pipefail

: "${VARIANT:=non-fips}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=.github/scripts/common.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../../common.sh"

REPO_ROOT="$(get_repo_root "$SCRIPT_DIR")"
UI_DIR="${REPO_ROOT}/ui"
WASM_CRATE="${REPO_ROOT}/crate/clients/wasm"

init_build_env "$@"

AUTH_VERIFIER_REPO="${AUTH_VERIFIER_REPO:-${REPO_ROOT}/authentication}"
if [ ! -d "${AUTH_VERIFIER_REPO}/server" ]; then
  echo "ERROR: Authentication Verifier repo not found at '${AUTH_VERIFIER_REPO}'." >&2
  echo "       Set AUTH_VERIFIER_REPO to the path of a checkout of the 'authentication' repo." >&2
  exit 1
fi

run_pnpm() {
  env -u LD_PRELOAD -u OPENSSL_CONF -u OPENSSL_MODULES pnpm "$@"
}

_get_free_port() {
  node -e "const net=require('node:net'); const server=net.createServer(); server.listen(0,'127.0.0.1',()=>{console.log(server.address().port); server.close();});"
}

# ── 1. Build WASM ────────────────────────────────────────────────────────────
echo "==> Building WASM (${VARIANT}, web target) …"
(
  cd "${WASM_CRATE}"
  # Pre-populate pkg/package.json with "repository" as a string.  Both
  # wasm-pack 0.13.x and 0.15.x read the existing pkg/package.json during the
  # wasm-bindgen install step; if that field is a JSON object they fail with
  # "invalid type: map, expected a string".  Providing a string-format stub
  # ensures the read succeeds, and wasm-pack then overwrites the file with the
  # full generated content.
  mkdir -p pkg
  printf '{"name":"cosmian_kms_client_wasm","repository":"https://github.com/Cosmian/kms"}\n' \
    >pkg/package.json
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
AUTH_CONF_FILE="${WORK_DIR}/auth_verifier.toml"
KMS_CONF_FILE="${WORK_DIR}/kms.toml"
AUTH_LOG="${WORK_DIR}/auth-verifier.log"
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

# Copy complete fixtures; only existing scalar values vary at runtime.
set_toml_value() {
  local config="$1" key="$2" value="$3"
  grep -qE "^${key} *= " "${config}" || {
    echo "ERROR: key '${key}' missing in ${config}" >&2
    return 1
  }
  sed -E "s|^(${key} *= *).*|\\1${value}|" "${config}" >"${config}.tmp"
  mv "${config}.tmp" "${config}"
}
cp "${REPO_ROOT}/test_data/configs/auth_verifier/ui_auth.toml" "${AUTH_CONF_FILE}"
set_toml_value "${AUTH_CONF_FILE}" host_port "${AUTH_PORT}"

# ── 3. Authentication Verifier — start with pre-built binary ─────────────────
# The binary is pre-built with the host toolchain by the `test:ui:auth` mise
# task BEFORE entering the nix shell (the nix rustc may be too old for this
# crate).  Run with the repo as cwd so relative paths in the config work.
AUTH_BIN="${AUTH_VERIFIER_REPO}/target/debug/auth_verifier"
if [ ! -x "${AUTH_BIN}" ]; then
  echo "ERROR: auth_verifier binary not found at '${AUTH_BIN}'." >&2
  echo "       The mise task should have built it with the host toolchain." >&2
  exit 1
fi
echo "==> Starting Authentication Verifier (port ${AUTH_PORT}) …"
(cd "${AUTH_VERIFIER_REPO}" && "${AUTH_BIN}" "${AUTH_CONF_FILE}") >"${AUTH_LOG}" 2>&1 &
AUTH_PID=$!

echo "==> Waiting for Authentication Verifier to be ready …"
_auth_timeout=${AUTH_VERIFIER_TIMEOUT:-120}
for i in $(seq 1 "${_auth_timeout}"); do
  if ! kill -0 "${AUTH_PID}" 2>/dev/null; then
    echo "ERROR: Authentication Verifier process exited early; log:" >&2
    cat "${AUTH_LOG}" >&2
    exit 1
  fi
  # curl links the Nix OpenSSL, which cannot load the FIPS provider selected by these variables.
  if env -u OPENSSL_CONF -u OPENSSL_MODULES curl -sS --max-time 2 --insecure -o /dev/null -w "%{http_code}" \
    "https://127.0.0.1:${AUTH_PORT}/.well-known/jwks.json" 2>/dev/null | grep -q '^200$'; then
    echo "    Authentication Verifier ready after ${i}s"
    break
  fi
  if [ "${i}" -eq "${_auth_timeout}" ]; then
    echo "ERROR: Authentication Verifier did not become ready within ${_auth_timeout}s; log:" >&2
    cat "${AUTH_LOG}" >&2
    exit 1
  fi
  sleep 1
done

# The admin realm is only for provisioning, never for KMS authentication.
AUTH_URL="https://127.0.0.1:${AUTH_PORT}"
ADMIN_COOKIES="${WORK_DIR}/admin.cookies"
curl -ksSf --max-time 10 -o /dev/null -c "${ADMIN_COOKIES}" \
  -u admin:change_me -H 'Content-Type: application/json' \
  -d '{}' "${AUTH_URL}/login?realm=_"
curl -ksSf --max-time 10 -o /dev/null -b "${ADMIN_COOKIES}" \
  -H 'Content-Type: application/json' \
  -d '{"id":"kms","auth_params":{"username_password_params":{"allow_expired_passwords":false}},"session_max_age_seconds":3600,"session_max_stale_age_seconds":3600}' \
  "${AUTH_URL}/admins/realms"
curl -ksSf --max-time 10 -o /dev/null -b "${ADMIN_COOKIES}" \
  -H 'Content-Type: application/json' \
  -d '{"realm":"kms","username":"kms-user","password_input":{"plaintext":"change_me"},"change_password":false,"roles":[]}' \
  "${AUTH_URL}/realms/kms/userpass"

# Serve the UI on the API origin so the login session cookie is same-origin.
cp "${REPO_ROOT}/test_data/configs/server/auth/ui_auth.toml" "${KMS_CONF_FILE}"
set_toml_value "${KMS_CONF_FILE}" kms_public_url "\"http://localhost:${KMS_PORT}\""
set_toml_value "${KMS_CONF_FILE}" port "${KMS_PORT}"
set_toml_value "${KMS_CONF_FILE}" sqlite_path "\"${KMS_SQLITE_DIR}\""
set_toml_value "${KMS_CONF_FILE}" auth_verifier_url "\"https://localhost:${AUTH_PORT}\""
set_toml_value "${KMS_CONF_FILE}" ui_index_html_folder "\"${UI_DIR}/dist\""

echo "==> Starting KMS server (port ${KMS_PORT}) …"
"${kms_bin}" --config "${KMS_CONF_FILE}" >"${KMS_LOG}" 2>&1 &
KMS_PID=$!

echo "==> Waiting for KMS to be ready with Auth Verifier …"
_kms_timeout=${KMS_READY_TIMEOUT:-120}
for i in $(seq 1 "${_kms_timeout}"); do
  if ! kill -0 "${KMS_PID}" 2>/dev/null; then
    echo "ERROR: KMS server process exited early; log:" >&2
    cat "${KMS_LOG}" >&2
    exit 1
  fi
  if curl -sS --max-time 2 "http://127.0.0.1:${KMS_PORT}/ui/auth_method" 2>/dev/null | grep -q '"AUTH_VERIFIER"'; then
    echo "    KMS ready after ${i}s"
    break
  fi
  if [ "${i}" -eq "${_kms_timeout}" ]; then
    echo "ERROR: KMS server did not report AUTH_VERIFIER auth within ${_kms_timeout}s; log:" >&2
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
  echo "--- Authentication Verifier log (last 80 lines) ---"
  tail -80 "${AUTH_LOG}" || true
  exit "${TEST_EXIT}"
fi

echo "==> Playwright auth tests PASSED"

# ── 6. Rust integration test ─────────────────────────────────────────────────
# Run the ignored Rust test that validates the same BFF login flow against the
# already-running KMS + auth-verifier.  PLAYWRIGHT_BASE_URL is reused so the
# test knows the KMS address without any extra configuration.
echo "==> Running Rust auth-verifier integration test …"
RUST_EXIT=0
PLAYWRIGHT_BASE_URL="http://localhost:${KMS_PORT}" \
  cargo test -p test_kms_server -- --ignored test_webui_login_via_auth_verifier || RUST_EXIT=$?

if [ "${RUST_EXIT}" -ne 0 ]; then
  echo "==> Rust auth-verifier integration test FAILED (exit code ${RUST_EXIT})"
  echo "--- KMS server log (last 40 lines) ---"
  tail -40 "${KMS_LOG}" || true
  echo "--- Authentication Verifier log (last 40 lines) ---"
  tail -40 "${AUTH_LOG}" || true
  exit "${RUST_EXIT}"
fi

echo "==> Rust auth-verifier integration test PASSED"

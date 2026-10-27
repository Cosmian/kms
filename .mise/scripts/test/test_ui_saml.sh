#!/usr/bin/env bash
# ============================================================================
# test_ui_saml.sh – TRUE end-to-end test of the KMS Web UI SAML single sign-on.
#
# Real stack, nothing mocked (see saml_sso/stack.sh):
#   Keycloak (SAML IdP) + Auth Verifier SAML build (SAML SP) + nginx on ONE public
#   origin https://localhost:8443, in Docker; the KMS runs on the host from this
#   checkout (port 9998, reached through nginx) and serves the UI built here.
# Then runs `pnpm run test:e2e:saml` (ui/tests/e2e-saml/, playwright.saml.config.ts).
#
# Needs: docker (with compose), jq, openssl, envsubst, curl, node/pnpm, wasm-pack.
# Fixed host ports: 8443 (proxy), 8444 (Auth Verifier), 9443 (Keycloak), 9998 (KMS).
# Image overrides (e.g. a registry mirror): KEYCLOAK_IMAGE, AUTH_VERIFIER_IMAGE, NGINX_IMAGE.
#
# Usage: bash .mise/scripts/test/test_ui_saml.sh [--variant non-fips]
# ============================================================================
set -euo pipefail

: "${VARIANT:=non-fips}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=.mise/scripts/common.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../common.sh"

REPO_ROOT="$(get_repo_root "$SCRIPT_DIR")"
UI_DIR="${REPO_ROOT}/ui"
WASM_CRATE="${REPO_ROOT}/crate/clients/wasm"
STACK="${SCRIPT_DIR}/saml_sso/stack.sh"
KMS_PORT=9998
PUBLIC_ORIGIN="https://localhost:8443"

init_build_env "$@"

for cmd in docker jq openssl envsubst curl node; do
  command -v "${cmd}" >/dev/null 2>&1 || {
    echo "ERROR: '${cmd}' is required for the SAML E2E test." >&2
    exit 1
  }
done
if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:${KMS_PORT}/version"; then
  echo "ERROR: something already listens on port ${KMS_PORT}; the SAML proxy forwards to it." >&2
  exit 1
fi

run_pnpm() {
  env -u LD_PRELOAD -u OPENSSL_CONF -u OPENSSL_MODULES pnpm "$@"
}
command -v pnpm >/dev/null 2>&1 || npm install -g pnpm@10.17.1

# ── 1. Build WASM, KMS server and the UI (real auth_method fetch, same origin) ─
echo "==> Building WASM (${VARIANT}, web target) …"
(
  cd "${WASM_CRATE}"
  # wasm-pack reads pkg/package.json first and fails if `repository` is an object.
  mkdir -p pkg
  printf '{"name":"cosmian_kms_client_wasm","repository":"https://github.com/Cosmian/kms"}\n' >pkg/package.json
  unset SDKROOT MACOSX_DEPLOYMENT_TARGET RUSTFLAGS LDFLAGS OPENSSL_DIR OPENSSL_LIB_DIR OPENSSL_INCLUDE_DIR
  if [ "${VARIANT}" = "non-fips" ]; then
    wasm-pack build --target web --features non-fips
  else
    wasm-pack build --target web
  fi
)
mkdir -p "${UI_DIR}/src/wasm/pkg"
cp -r "${WASM_CRATE}/pkg/." "${UI_DIR}/src/wasm/pkg/"

# The Auth Verifier signature check is compiled out under the `insecure` feature, which would
# silently turn the forged-cookie test into a false pass/fail.
if [[ " ${FEATURES_FLAG[*]} " == *insecure* ]]; then
  echo "ERROR: the SAML E2E test must run against a build without the 'insecure' feature." >&2
  exit 1
fi

echo "==> Building KMS server …"
cargo build -p cosmian_kms_server "${FEATURES_FLAG[@]}"
kms_bin="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}/debug/cosmian_kms"

echo "==> Building UI (no VITE_DEV_MODE / VITE_KMS_URL) …"
(cd "${UI_DIR}" && run_pnpm install --frozen-lockfile)
(cd "${UI_DIR}" && {
  chmod -R u+w dist >/dev/null 2>&1 || true
  rm -rf dist
  run_pnpm run build:vite
})
if command -v sudo >/dev/null 2>&1 || [ "$(id -u)" -eq 0 ]; then
  (cd "${UI_DIR}" && run_pnpm exec playwright install chromium --with-deps)
else
  (cd "${UI_DIR}" && run_pnpm exec playwright install chromium)
fi

# ── 2. Start Keycloak + Auth Verifier + nginx, then the KMS ──────────────────
KMS_PID=""
KMS_LOG="$(mktemp)"
cleanup() {
  echo "==> Cleaning up …"
  [ -n "${KMS_PID}" ] && { kill "${KMS_PID}" 2>/dev/null || true; }
  bash "${STACK}" down || true
  rm -f "${KMS_LOG}"
}
trap cleanup EXIT INT TERM

bash "${STACK}" up
echo "==> Starting KMS server (port ${KMS_PORT}) …"
"${kms_bin}" --config "${SAML_SSO_DIR:-/tmp/kms-saml-sso}/kms.toml" >"${KMS_LOG}" 2>&1 &
KMS_PID=$!

echo "==> Waiting for the KMS behind the SAML proxy …"
for i in $(seq 1 "${KMS_READY_TIMEOUT:-120}"); do
  if ! kill -0 "${KMS_PID}" 2>/dev/null; then
    echo "ERROR: KMS server exited early; log:" >&2
    cat "${KMS_LOG}" >&2
    exit 1
  fi
  if curl -ksS --max-time 2 "${PUBLIC_ORIGIN}/ui/auth_method" 2>/dev/null | grep -q '"AUTH_VERIFIER_SAML"'; then
    echo "    KMS ready after ${i}s"
    break
  fi
  if [ "${i}" -eq "${KMS_READY_TIMEOUT:-120}" ]; then
    echo "ERROR: KMS did not advertise AUTH_VERIFIER_SAML in time; log:" >&2
    tail -80 "${KMS_LOG}" >&2
    exit 1
  fi
  sleep 1
done

# ── 3. Run the Playwright SAML E2E suite ─────────────────────────────────────
echo "==> Running Playwright SAML E2E tests …"
TEST_EXIT=0
# shellcheck disable=SC2086 # PLAYWRIGHT_ARGS is deliberately word-split (e.g. "--repeat-each=5 --grep SSO")
(cd "${UI_DIR}" && env -u LD_PRELOAD -u OPENSSL_CONF -u OPENSSL_MODULES \
  CI=true PLAYWRIGHT_BASE_URL="${PUBLIC_ORIGIN}" pnpm run test:e2e:saml ${PLAYWRIGHT_ARGS:-}) || TEST_EXIT=$?

if [ "${TEST_EXIT}" -ne 0 ]; then
  echo "==> Playwright SAML tests FAILED (exit code ${TEST_EXIT})"
  echo "--- KMS server log (last 80 lines) ---"
  tail -80 "${KMS_LOG}" || true
  bash "${STACK}" logs || true
  exit "${TEST_EXIT}"
fi
echo "==> Playwright SAML tests PASSED"

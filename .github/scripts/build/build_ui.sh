#!/usr/bin/env bash

# Build the KMS UI
# This script:
# 1. Builds the WASM component
# 2. Builds the UI
# 3. Copies the built UI to the final location

# Exit on error, undefined vars, and fail pipelines; print commands
set -euo pipefail
set -x

CARGO_FEATURES=""
if [ -n "${FEATURES:-}" ]; then
  CARGO_FEATURES="--features ${FEATURES}"
fi

WASM_PACK_VERSION="0.13.1"

# Install nodejs from nodesource if npm is not installed
if ! command -v npm >/dev/null 2>&1; then
  SUDO="sudo"
  if [ "$(id -u)" = "0" ]; then SUDO=""; fi
  if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    curl -fsSL https://deb.nodesource.com/setup_23.x | "$SUDO" bash -
    "$SUDO" apt-get install -y nodejs
  elif [ -f /etc/redhat-release ]; then
    # RHEL/CentOS/Fedora
    curl -fsSL https://rpm.nodesource.com/setup_23.x | "$SUDO" bash -
    "$SUDO" yum install -y nodejs
  else
    echo "Unsupported distribution"
    exit 1
  fi
fi

# Install wasm-pack tool (pinned for compatibility with the WASM crate)
if ! command -v wasm-pack >/dev/null 2>&1 || ! wasm-pack --version 2>/dev/null | grep -q "${WASM_PACK_VERSION}"; then
  cargo install --version "${WASM_PACK_VERSION}" wasm-pack --locked --force
  export PATH="$HOME/.cargo/bin:$PATH"
fi

# Build WASM component
cd crate/clients/wasm
# shellcheck disable=SC2086
wasm-pack build --target web --release $CARGO_FEATURES

# Copy WASM artifacts to UI directory
WASM_DIR="../../../ui/src/wasm/"
rm -rf "$WASM_DIR"
mkdir -p "$WASM_DIR"
cp -R pkg "$WASM_DIR"

# Build UI
cd ../../../ui # current path: ./ui
rm -rf node_modules

if ! command -v pnpm >/dev/null 2>&1; then
  if command -v corepack >/dev/null 2>&1; then
    corepack enable || true
    corepack prepare pnpm@10 --activate || true
  fi
fi
if ! command -v pnpm >/dev/null 2>&1; then
  if ! npm install -g pnpm@10; then
    PREFIX_DIR="${PNPM_PREFIX_DIR:-$HOME/.local}"
    npm install -g pnpm@10 --prefix "$PREFIX_DIR"
    export PATH="$PREFIX_DIR/bin:$PATH"
  fi
fi

pnpm install --frozen-lockfile
pnpm run build

# ── Start a fresh KMS server for the integration tests ──────────────────────
# Go back to repo root to build the KMS binary, then return to ui/.
KMS_SQLITE_DIR=""
KMS_PID=""
cleanup_kms() {
  [ -n "${KMS_PID:-}" ] && { kill "${KMS_PID}" 2>/dev/null || true; }
  [ -n "${KMS_SQLITE_DIR:-}" ] && rm -rf "${KMS_SQLITE_DIR}"
}
trap cleanup_kms EXIT INT TERM

# Kill any existing process on port 9998 so our fresh binary can bind it.
if command -v lsof >/dev/null 2>&1 && lsof -ti :9998 >/dev/null 2>&1; then
  echo "==> Killing stale process on port 9998 …"
  kill "$(lsof -ti :9998)" 2>/dev/null || true
  sleep 1
fi

echo "==> Building KMS server binary …"
# shellcheck disable=SC2086
(cd .. && cargo build -p cosmian_kms_server --bin cosmian_kms $CARGO_FEATURES)

KMS_SQLITE_DIR="$(mktemp -d)"
echo "==> Starting KMS server (port 9998, sqlite=${KMS_SQLITE_DIR}) …"
KMS_CONF_FILE="${KMS_SQLITE_DIR}/kms.toml"
cat >"${KMS_CONF_FILE}" <<EOF
default_username = "admin"

[db]
database_type = "sqlite"
sqlite_path = "${KMS_SQLITE_DIR}"
clear_database = true

[http]
hostname = "127.0.0.1"
port = 9998
EOF
(cd .. && ./target/debug/cosmian_kms --config "${KMS_CONF_FILE}") &
KMS_PID=$!

echo "==> Waiting for KMS server to be ready …"
for _i in $(seq 1 60); do
  if curl -sf http://127.0.0.1:9998/version >/dev/null 2>&1; then
    echo "    KMS server ready."
    break
  fi
  if [ "${_i}" -eq 60 ]; then
    echo "ERROR: KMS server did not become ready within 60 s." >&2
    exit 1
  fi
  sleep 1
done

pnpm run check
pnpm audit

# Deploy built UI to root
cd .. # current path: ./

DEST_DIR="crate/server/ui${CARGO_FEATURES:+_non_fips}"
rm -rf "$DEST_DIR"
mkdir -p "$DEST_DIR"
cp -R ui/dist "$DEST_DIR"

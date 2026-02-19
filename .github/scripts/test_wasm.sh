#!/usr/bin/env bash
set -euo pipefail

# Run wasm tests for cosmian_kms_client_wasm
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

REPO_ROOT="$(get_repo_root "$SCRIPT_DIR")"
cd "$REPO_ROOT"

init_build_env "$@"
setup_test_logging

ensure_wasm_target() {
  if [ -d "$(rustc --print sysroot 2>/dev/null)/lib/rustlib/wasm32-unknown-unknown/lib" ]; then
    return 0
  fi

  if command -v rustup >/dev/null 2>&1; then
    rustup target add wasm32-unknown-unknown
  fi

  if [ ! -d "$(rustc --print sysroot 2>/dev/null)/lib/rustlib/wasm32-unknown-unknown/lib" ]; then
    echo "Error: wasm32-unknown-unknown target is not installed (and rustup is unavailable to install it)" >&2
    exit 1
  fi
}

node_major_version() {
  if ! command -v node >/dev/null 2>&1; then
    echo 0
    return 0
  fi

  local v
  v="$(node --version 2>/dev/null || true)"
  v="${v#v}"
  echo "${v%%.*}"
}

# wasm-bindgen-test-runner and the UI toolchain require a reasonably modern Node.
# If an old Node is active (e.g. via nvm), prefer running inside nix-shell.
if [ "${IN_NIX_NODE_SHELL:-0}" != "1" ]; then
  node_major="$(node_major_version)"
  if [ "$node_major" -gt 0 ] && [ "$node_major" -lt 18 ] && command -v nix-shell >/dev/null 2>&1; then
    printf -v quoted_args '%q ' "$@"
    exec nix-shell -p nodejs wasm-pack --run "cd '$REPO_ROOT' && IN_NIX_NODE_SHELL=1 bash .github/scripts/test_wasm.sh ${quoted_args}"
  fi
fi

# In the Nix CI/test environment we don't necessarily have rustup, extra Rust std
# components, Node.js, or a browser available. Since WASM tests are an optional
# tier, skip them there when prerequisites are missing.
if [ -n "${IN_NIX_SHELL:-}" ]; then
  # Prefer the Node runner; without it, the script would fall back to a browser
  # runner which is typically unavailable in minimal Nix shells.
  if ! command -v node >/dev/null 2>&1; then
    echo "Error: Node.js is not available (required for WASM tests in this environment)" >&2
    exit 1
  fi
fi

ensure_pnpm() {
  pnpm_major_version() {
    if ! command -v pnpm >/dev/null 2>&1; then
      echo 0
      return 0
    fi
    local v
    v="$(pnpm --version 2>/dev/null || true)"
    echo "${v%%.*}"
  }

  pnpm_major="$(pnpm_major_version)"
  if [ "$pnpm_major" -ge 9 ]; then
    return 0
  fi

  if command -v corepack >/dev/null 2>&1; then
    corepack enable >/dev/null 2>&1 || true
    corepack prepare pnpm@9 --activate >/dev/null 2>&1 || true
  fi

  pnpm_major="$(pnpm_major_version)"
  if [ "$pnpm_major" -ge 9 ]; then
    return 0
  fi

  if ! command -v npm >/dev/null 2>&1; then
    echo "Error: npm not found; cannot install pnpm" >&2
    return 1
  fi

  # Avoid installing into read-only prefixes (e.g. /nix/store). Prefer a
  # user-writable prefix and update PATH.
  if npm install -g pnpm@9 >/dev/null 2>&1; then
    pnpm_major="$(pnpm_major_version)"
    [ "$pnpm_major" -ge 9 ] && return 0
  fi

  local prefix_dir
  prefix_dir="${PNPM_PREFIX_DIR:-$HOME/.local}"
  npm install -g pnpm@9 --prefix "$prefix_dir" >/dev/null
  export PATH="$prefix_dir/bin:$PATH"

  pnpm_major="$(pnpm_major_version)"
  [ "$pnpm_major" -ge 9 ]
}

run_ui() {
  (
    cd ui
    unset OPENSSL_CONF OPENSSL_MODULES LD_PRELOAD OPENSSL_DIR OPENSSL_LIB_DIR OPENSSL_INCLUDE_DIR OPENSSL_STATIC PKG_CONFIG_PATH || true
    "$@"
  )
}

# wasm-pack invokes cargo (for metadata fetches and compilation) which does NOT
# need the host OpenSSL env vars set by common.sh / shell.nix.  Leaving those
# vars in place causes cargo's libcurl-based network layer to attempt loading the
# Nix-store OpenSSL provider (libcrypto.so.3) which is absent on macOS and
# triggers fatal TLS errors on every crates.io download.  Unset them in the
# subshell so wasm-pack/cargo uses its own network stack unmolested.
#
# Also strip macOS-specific framework linker flags that ensure_macos_frameworks_ldflags
# injects into RUSTFLAGS for native builds: the WASM linker (rust-lld) does not
# accept -F or -Wl,-F arguments and aborts with "unknown argument".
run_wasm_pack() {
  (
    cd crate/wasm
    unset OPENSSL_CONF OPENSSL_MODULES LD_PRELOAD OPENSSL_DIR OPENSSL_LIB_DIR OPENSSL_INCLUDE_DIR OPENSSL_STATIC PKG_CONFIG_PATH || true
    # Strip macOS framework linker flags from RUSTFLAGS (-C link-arg=-F<path> and
    # -C link-arg=-Wl,-F,<path>) while preserving all other flags (e.g. --cfg wasm_test_browser).
    if [ -n "${RUSTFLAGS:-}" ]; then
      RUSTFLAGS="$(printf '%s' "${RUSTFLAGS}" \
        | sed -e 's/-C link-arg=-F[^[:space:]]* \{0,1\}//g' \
              -e 's/-C link-arg=-Wl,-F,[^[:space:]]* \{0,1\}//g' \
              -e 's/[[:space:]]*$//')"
      export RUSTFLAGS
    fi
    wasm-pack "$@"
  )
}

# nix.sh runs this script *inside* a nix-shell for wasm tests (nodejs + wasm-pack).
# Keep this script runnable standalone too.
if ! command -v wasm-pack >/dev/null 2>&1; then
  if command -v nix-shell >/dev/null 2>&1; then
    printf -v quoted_args '%q ' "$@"
    exec nix-shell -p nodejs wasm-pack --run "cd '$REPO_ROOT' && IN_NIX_NODE_SHELL=1 bash .github/scripts/test_wasm.sh ${quoted_args}"
  fi
  echo "Error: wasm-pack not available (expected nix-shell or cargo-installed wasm-pack)." >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "Error: cargo not found (wasm-pack requires Rust toolchain)." >&2
  exit 1
fi

if ! command -v rustc >/dev/null 2>&1; then
  echo "Error: rustc not found (wasm-pack requires Rust toolchain)." >&2
  exit 1
fi

ensure_wasm_target

if command -v node >/dev/null 2>&1; then
  if [ -n "${RELEASE_FLAG:-}" ]; then
    run_wasm_pack test --node "$RELEASE_FLAG" "${FEATURES_FLAG[@]}"
  else
    run_wasm_pack test --node "${FEATURES_FLAG[@]}"
  fi
else
  echo "Node.js not found; falling back to Chrome headless" >&2
  if [ -n "${RELEASE_FLAG:-}" ]; then
    RUSTFLAGS="--cfg wasm_test_browser" run_wasm_pack test --headless --chrome "$RELEASE_FLAG" "${FEATURES_FLAG[@]}"
  else
    RUSTFLAGS="--cfg wasm_test_browser" run_wasm_pack test --headless --chrome "${FEATURES_FLAG[@]}"
  fi
fi

# Build the web-target WASM package and run React unit tests using the real artifacts.
if [ -n "${RELEASE_FLAG:-}" ]; then
  run_wasm_pack build --target web "$RELEASE_FLAG" "${FEATURES_FLAG[@]}"
else
  run_wasm_pack build --target web "${FEATURES_FLAG[@]}"
fi

WASM_DIR="ui/src/wasm"
rm -rf "$WASM_DIR"
mkdir -p "$WASM_DIR"
cp -R crate/wasm/pkg "$WASM_DIR/"

# Some tools (notably Vite/Vitest) may require a "main" field to resolve directory imports
# like `import init from "./wasm/pkg"`. wasm-pack emits "module" but not always "main".
if [ -f "ui/src/wasm/pkg/package.json" ] && command -v node >/dev/null 2>&1; then
  node <<'NODE'
const fs = require('node:fs');
const path = 'ui/src/wasm/pkg/package.json';
const pkg = JSON.parse(fs.readFileSync(path, 'utf8'));
if (!pkg.main) {
  pkg.main = pkg.module || 'cosmian_kms_client_wasm.js';
  fs.writeFileSync(path, JSON.stringify(pkg, null, 2) + '\n');
}
NODE
fi

if [ -n "${IN_NIX_SHELL:-}" ] && [ -f ui/package-lock.json ]; then
  run_ui npm ci
  run_ui npm run lint
  run_ui npm run test:unit
elif [ -f ui/pnpm-lock.yaml ]; then
  if ensure_pnpm; then
    run_ui pnpm install --frozen-lockfile
    run_ui pnpm run lint
    run_ui pnpm run test:unit
  elif [ -f ui/package-lock.json ]; then
    run_ui npm ci
    run_ui npm run lint
    run_ui npm run test:unit
  else
    run_ui npm install
    run_ui npm run lint
    run_ui npm run test:unit
  fi
elif [ -f ui/package-lock.json ]; then
  run_ui npm ci
  run_ui npm run lint
  run_ui npm run test:unit
else
  run_ui npm install
  run_ui npm run lint
  run_ui npm run test:unit
fi

# Run UI integration tests against a locally started KMS server.
# Always run the server in debug (no --release), even if wasm/ui builds are in release.
if command -v cargo >/dev/null 2>&1; then
  echo "Starting KMS server for UI integration tests (cargo run)…" >&2

  KMS_SQLITE_DIR="${KMS_SQLITE_DIR:-}"
  if [ -z "$KMS_SQLITE_DIR" ]; then
    KMS_SQLITE_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t kms-ui-integration)"
  fi

  KMS_LOG_FILE="${KMS_LOG_FILE:-/tmp/kms-ui-integration.log}"
  : >"$KMS_LOG_FILE"

  cargo run -p cosmian_kms_server --bin cosmian_kms "${FEATURES_FLAG[@]}" -- \
    --database-type sqlite \
    --sqlite-path "$KMS_SQLITE_DIR" \
    --hostname 127.0.0.1 \
    --port 9998 \
    >"$KMS_LOG_FILE" 2>&1 &

  kms_pid="$!"
  cleanup() {
    if kill -0 "$kms_pid" >/dev/null 2>&1; then
      kill "$kms_pid" >/dev/null 2>&1 || true
      wait "$kms_pid" >/dev/null 2>&1 || true
    fi
    if [ -n "${KMS_SQLITE_DIR:-}" ] && [ -d "$KMS_SQLITE_DIR" ]; then
      rm -rf "$KMS_SQLITE_DIR" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup EXIT

  # Wait for the server to accept connections (may take time on cold builds).
  if command -v curl >/dev/null 2>&1; then
    ready=0
    for _i in {1..300}; do
      if ! kill -0 "$kms_pid" >/dev/null 2>&1; then
        echo "Error: KMS server exited before becoming ready (see $KMS_LOG_FILE)" >&2
        tail -n 120 "$KMS_LOG_FILE" >&2 || true
        exit 1
      fi
      if curl -sS --max-time 1 -o /dev/null "http://127.0.0.1:9998/"; then
        ready=1
        break
      fi
      sleep 1
    done

    if [ "$ready" = "0" ]; then
      echo "Error: KMS server did not become ready in time (see $KMS_LOG_FILE)" >&2
      tail -n 120 "$KMS_LOG_FILE" >&2 || true
      exit 1
    fi
  else
    sleep 2
  fi

  if [ -n "${IN_NIX_SHELL:-}" ] && [ -f ui/package-lock.json ]; then
    KMS_URL="http://127.0.0.1:9998" run_ui npm run test:integration
  elif [ -f ui/pnpm-lock.yaml ]; then
    if ensure_pnpm; then
      KMS_URL="http://127.0.0.1:9998" run_ui pnpm run test:integration
    else
      KMS_URL="http://127.0.0.1:9998" run_ui npm run test:integration
    fi
  elif [ -f ui/package-lock.json ]; then
    KMS_URL="http://127.0.0.1:9998" run_ui npm run test:integration
  else
    KMS_URL="http://127.0.0.1:9998" run_ui npm run test:integration
  fi
else
  echo "Error: cargo not available; cannot run UI integration tests" >&2
  exit 1
fi

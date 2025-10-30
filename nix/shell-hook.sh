#!/usr/bin/env bash
set -euo pipefail

export OPENSSL_NO_VENDOR=1
export OPENSSL_STATIC=1
export PKG_CONFIG_ALL_STATIC=1
[ -d "${NIX_OPENSSL_OUT:-}/bin" ] && export PATH="${NIX_OPENSSL_OUT}/bin:$PATH"
if [ -n "${NIX_OPENSSL_OUT:-}" ]; then
  export OPENSSL_DIR="${NIX_OPENSSL_OUT}"
  export OPENSSL_LIB_DIR="${NIX_OPENSSL_OUT}/lib"
  export OPENSSL_INCLUDE_DIR="${NIX_OPENSSL_OUT}/include"

  # Set OPENSSL_CONF to point to the nix store OpenSSL config
  # This is required for FIPS mode to work properly during builds and tests
  if [ -f "${NIX_OPENSSL_OUT}/ssl/openssl.cnf" ]; then
    export OPENSSL_CONF="${NIX_OPENSSL_OUT}/ssl/openssl.cnf"
  fi

  # Force openssl-sys to use our specific OpenSSL and detect version correctly
  # Disable pkg-config to prevent it from finding wrong OpenSSL versions
  export OPENSSL_NO_PKG_CONFIG=1
  if [ -d "${NIX_OPENSSL_OUT}/lib/pkgconfig" ]; then
    export PKG_CONFIG_PATH="${NIX_OPENSSL_OUT}/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
  fi
  if [ -d "${NIX_OPENSSL_OUT}/lib64/pkgconfig" ]; then
    export PKG_CONFIG_PATH="${NIX_OPENSSL_OUT}/lib64/pkgconfig:${PKG_CONFIG_PATH:-}"
  fi
fi

if [ "$(uname -s)" = "Linux" ]; then
  [ -n "${NIX_CC_BIN:-}" ] && PATH="${NIX_CC_BIN}:$PATH"
  [ -n "${NIX_BINUTILS_BIN:-}" ] && PATH="${NIX_BINUTILS_BIN}:$PATH"
  AR_BIN="${NIX_BINUTILS_UNWRAPPED_BIN:-${NIX_BINUTILS_BIN:-}}"
  export CC="${NIX_CC_BIN:-}/cc"
  export AR="$AR_BIN/ar"
  if [ ! -x "$AR" ] && command -v ar >/dev/null 2>&1; then AR="$(command -v ar)"; fi
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$CC"
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_AR="$AR"
  export CC_x86_64_unknown_linux_gnu="$CC"
  export AR_x86_64_unknown_linux_gnu="$AR"
  export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C link-args=-Wl,--dynamic-linker=${NIX_DYN_LINKER:-} -C link-args=-Wl,-rpath,${NIX_GLIBC_LIB:-}"
fi

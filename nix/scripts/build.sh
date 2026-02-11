#!/usr/bin/env bash
set -eo pipefail
set -x

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
source "$REPO_ROOT/.github/scripts/common.sh"

init_build_env "$@"

# Ensure resulting Linux binaries do not embed /nix/store paths and use the system dynamic loader
if [ "$(uname)" = "Linux" ]; then
  # 1) Prevent Nix cc-wrapper from injecting RPATHs to /nix/store
  export NIX_DONT_SET_RPATH=1
  export NIX_LDFLAGS=""
  export NIX_CFLAGS_LINK=""

  # 2) Start from a clean RUSTFLAGS to avoid inherited Nix link-args/rpaths
  export RUSTFLAGS=""

  # 3) Use the Nix cc wrapper to link against the pinned glibc (ensures GLIBC<=2.34),
  #    but we will override the runtime interpreter and suppress rpaths below.

  # 4) Explicitly set the system dynamic linker (avoids /nix/store/…/ld-linux-x86-64.so.2)
  #    Architecture-specific paths
  ARCH="$(uname -m)"
  if [ "$ARCH" = "x86_64" ]; then
    # Prefer /lib64 path when present (matches expected ldd output), fallback to /lib/x86_64-linux-gnu
    if [ -e "/lib64/ld-linux-x86-64.so.2" ]; then
      RUSTFLAGS+=" -C link-arg=-Wl,--dynamic-linker,/lib64/ld-linux-x86-64.so.2"
    elif [ -e "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" ]; then
      RUSTFLAGS+=" -C link-arg=-Wl,--dynamic-linker,/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
    fi
  elif [ "$ARCH" = "aarch64" ]; then
    # ARM64 uses /lib/ld-linux-aarch64.so.1
    if [ -e "/lib/ld-linux-aarch64.so.1" ]; then
      RUSTFLAGS+=" -C link-arg=-Wl,--dynamic-linker,/lib/ld-linux-aarch64.so.1"
    elif [ -e "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1" ]; then
      RUSTFLAGS+=" -C link-arg=-Wl,--dynamic-linker,/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"
    fi
  fi

  export RUSTFLAGS

  # 5) Ensure OpenSSL is linked statically so no runtime SSL deps or rpaths are introduced
  export OPENSSL_STATIC=1
fi

# shellcheck disable=SC2086
cargo build -p cosmian_kms_server $RELEASE_FLAG "${FEATURES_FLAG[@]}"

COSMIAN_KMS_EXE="target/$BUILD_PROFILE/cosmian_kms"

# Verify binary works (temporarily use nix store OpenSSL config)
export OPENSSL_CONF="${NIX_OPENSSL_OUT:-}/ssl/openssl.cnf"
INFO_OUTPUT=$("$COSMIAN_KMS_EXE" --version 2>&1 || true)
echo "$INFO_OUTPUT"
echo "$INFO_OUTPUT" | grep -q "cosmian_kms_server" || {
  echo "Error: Binary does not appear to be working" >&2
  exit 1
}
unset OPENSSL_CONF

# Platform-specific checks
UNAME=$(uname)
if [ "$UNAME" = "Linux" ]; then
  LDD_OUTPUT=$(ldd "$COSMIAN_KMS_EXE")
  echo "$LDD_OUTPUT"
  echo "$LDD_OUTPUT" | grep -qi ssl && {
    echo "Error: Dynamic OpenSSL linkage detected on Linux (ldd | grep ssl)." >&2
    exit 1
  }

  # Enforce: no embedded /nix/store paths in ELF metadata (interpreter, RPATH/RUNPATH)
  if command -v readelf >/dev/null 2>&1; then
    # Interpreter path must be a system path, not /nix/store
    INTERP_LINE=$(readelf -l "$COSMIAN_KMS_EXE" | sed -n 's/^\s*Requesting program interpreter: \(.*\)]$/\1/p')
    if echo "$INTERP_LINE" | grep -q "/nix/store"; then
      echo "Error: ELF interpreter points to a /nix/store path: $INTERP_LINE" >&2
      exit 1
    fi

    # RPATH/RUNPATH must not reference /nix/store
    if readelf -d "$COSMIAN_KMS_EXE" | grep -E "(RUNPATH|RPATH)" | grep -q "/nix/store"; then
      echo "Error: ELF RUNPATH/RPATH contains /nix/store paths:" >&2
      readelf -d "$COSMIAN_KMS_EXE" | grep -E "(RUNPATH|RPATH)"
      exit 1
    fi
  fi

  # Verify GLIBC symbol versions are <= 2.34 (Rocky Linux 9 compatibility)
  GLIBC_SYMS=$(readelf -sW "$COSMIAN_KMS_EXE" | grep -o 'GLIBC_[0-9][0-9.]*' | sort -Vu)
  echo "$GLIBC_SYMS"
  MAX_GLIBC_VER=""
  [ -n "$GLIBC_SYMS" ] && MAX_GLIBC_VER=$(echo "$GLIBC_SYMS" | sed 's/^GLIBC_//' | sort -V | tail -n1)
  [ -n "$MAX_GLIBC_VER" ] && [ "$(printf '%s\n' "$MAX_GLIBC_VER" "2.34" | sort -V | tail -n1)" != "2.34" ] && {
    echo "Error: GLIBC symbols exceed 2.34 (max found: $MAX_GLIBC_VER)." >&2
    exit 1
  }
else
  # macOS: check with otool
  if command -v otool >/dev/null 2>&1; then
    OTOOL_OUTPUT=$(otool -L "$COSMIAN_KMS_EXE")
    echo "$OTOOL_OUTPUT"
    echo "$OTOOL_OUTPUT" | grep -qi ssl && {
      echo "Error: Dynamic OpenSSL linkage detected on macOS (otool -L | grep openssl)." >&2
      exit 1
    }
  fi
fi

echo "Build and OpenSSL checks succeeded."

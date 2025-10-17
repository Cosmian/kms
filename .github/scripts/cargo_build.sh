#!/bin/bash

# Build cosmian_kms_server inside the project's Nix shell and validate OpenSSL.
#
# Environment variables (optional):
#   TARGET                    e.g., x86_64-unknown-linux-gnu (defaults to host target)
#   DEBUG_OR_RELEASE          debug | release (default: debug)
#   FEATURES                  cargo feature list, space/comma separated (optional)
#
# Notes:
# - This script relies on the repo's nix-shell environment (shell.nix / flake)
#   to supply the correct toolchain and OpenSSL. No host OPENSSL_DIR is needed.
# - It enforces that the running binary reports the expected OpenSSL version and
#   that OpenSSL is statically linked (no libssl in ldd/otool output).

set -euo pipefail

HERE_DIR=$(cd "$(dirname "$0")" && pwd)
# Resolve repo root robustly: prefer git, else fallback to two levels up from .github/scripts
if command -v git >/dev/null 2>&1; then
  REPO_ROOT=$(git -C "$HERE_DIR" rev-parse --show-toplevel)
else
  REPO_ROOT=$(cd "$HERE_DIR/../.." && pwd)
fi

# Build and checks performed inside the Nix shell for full reproducibility
cd "$REPO_ROOT"

if ! command -v nix-shell >/dev/null 2>&1; then
  echo "Error: nix-shell not found in PATH. Please install Nix and try again." >&2
  exit 1
fi

# Ensure prebuilt OpenSSL 3.1.2 is available locally and instruct nix-shell to use it
OS_LOWER=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
# Default install location inside repo to avoid sudo
EXTERNAL_OPENSSL_DIR_DEFAULT="$REPO_ROOT/.openssl/3.1.2-${OS_LOWER}-${ARCH}"
EXTERNAL_OPENSSL_DIR="${EXTERNAL_OPENSSL_DIR:-$EXTERNAL_OPENSSL_DIR_DEFAULT}"

# Check if OpenSSL static libs and FIPS config are present; if not, import from package.cosmian.com
need_import=0
if [ ! -f "$EXTERNAL_OPENSSL_DIR/ssl/fipsmodule.cnf" ]; then
  need_import=1
fi
if [ ! -f "$EXTERNAL_OPENSSL_DIR/lib/libcrypto.a" ] && [ ! -f "$EXTERNAL_OPENSSL_DIR/lib64/libcrypto.a" ]; then
  need_import=1
fi

if [ "$need_import" -eq 1 ]; then
  echo "Preparing external OpenSSL 3.1.2 in $EXTERNAL_OPENSSL_DIR (skip Nix build)"
  OPENSSL_DIR="$EXTERNAL_OPENSSL_DIR" bash "$REPO_ROOT/.github/reusable_scripts/import_openssl_from_package.sh" "$OS_LOWER" "$ARCH"
else
  echo "Using cached external OpenSSL at $EXTERNAL_OPENSSL_DIR"
fi

# Write inner script to a temporary file and execute it inside nix-shell
TMP_SCRIPT=$(mktemp -t cosmian_kms_nix_build.XXXXXX.sh)
trap 'rm -f "$TMP_SCRIPT"' EXIT

cat >"$TMP_SCRIPT" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
set -x

# Resolve inputs with defaults inside the nix environment
: "${DEBUG_OR_RELEASE:=debug}"
: "${TARGET:=x86_64-unknown-linux-gnu}"
: "${FEATURES:=}"

RELEASE_FLAG=""
if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  RELEASE_FLAG="--release"
fi

FEATURES_FLAG=()
if [ -n "$FEATURES" ]; then
  FEATURES_FLAG=(--features "$FEATURES")
fi

if command -v rustup >/dev/null 2>&1; then
  rustup target add "$TARGET" || true
fi

cargo build -p cosmian_kms_server --target "$TARGET" $RELEASE_FLAG "${FEATURES_FLAG[@]:-}"

COSMIAN_KMS_EXE="target/$TARGET/$DEBUG_OR_RELEASE/cosmian_kms"
INFO_OUTPUT=$("$COSMIAN_KMS_EXE" --info)
echo "$INFO_OUTPUT"
echo "$INFO_OUTPUT" | grep -q "OpenSSL 3.1.2" || {
  echo "Error: The correct OpenSSL version 3.1.2 is not found in --info output." >&2
  exit 1
}

UNAME=$(uname)
if [ "$UNAME" = "Linux" ]; then
  LDD_OUTPUT=$(ldd "$COSMIAN_KMS_EXE")
  echo "$LDD_OUTPUT"
  echo "$LDD_OUTPUT" | grep -qi ssl && {
    echo "Error: Dynamic OpenSSL linkage detected on Linux (ldd | grep ssl)." >&2
    exit 1
  }
else
  if command -v otool >/dev/null 2>&1; then
    OTOOL_OUTPUT=$(otool -L "$COSMIAN_KMS_EXE")
    echo "$OTOOL_OUTPUT"
    echo "$OTOOL_OUTPUT" | grep -qi ssl && {
      echo "Error: Dynamic OpenSSL linkage detected on macOS (otool -L | grep openssl)." >&2
      exit 1
    }
  fi
fi

# Verify GLIBC symbol versions are <= 2.28
GLIBC_SYMS=$(readelf -sW "$COSMIAN_KMS_EXE" | grep -o 'GLIBC_[0-9][0-9.]*' | sort -Vu || true)
echo "$GLIBC_SYMS"
MAX_GLIBC_VER=""
if [ -n "$GLIBC_SYMS" ]; then
  MAX_GLIBC_VER=$(echo "$GLIBC_SYMS" | sed 's/^GLIBC_//' | sort -V | tail -n1)
fi
if [ -n "$MAX_GLIBC_VER" ] && [ "$(printf '%s\n' "$MAX_GLIBC_VER" "2.28" | sort -V | tail -n1)" != "2.28" ]; then
  echo "Error: GLIBC symbols exceed 2.28 (max found: $MAX_GLIBC_VER)." >&2
  exit 1
fi

echo "Build and OpenSSL checks succeeded."
BASH

chmod +x "$TMP_SCRIPT"

# Run inside nix-shell, explicitly referencing the repo's shell.nix if present
if [ -f "$REPO_ROOT/shell.nix" ]; then
  EXTERNAL_OPENSSL_DIR="$EXTERNAL_OPENSSL_DIR" \
    nix-shell "$REPO_ROOT/shell.nix" --pure --keep EXTERNAL_OPENSSL_DIR --keep DEBUG_OR_RELEASE --keep TARGET --keep FEATURES --run "bash '$TMP_SCRIPT'"
elif [ -f "$REPO_ROOT/default.nix" ]; then
  EXTERNAL_OPENSSL_DIR="$EXTERNAL_OPENSSL_DIR" \
    nix-shell "$REPO_ROOT/default.nix" --pure --keep EXTERNAL_OPENSSL_DIR --keep DEBUG_OR_RELEASE --keep TARGET --keep FEATURES --run "bash '$TMP_SCRIPT'"
else
  echo "Error: No shell.nix or default.nix found at $REPO_ROOT. Cannot start nix-shell." >&2
  exit 1
fi

#!/usr/bin/env bash
# .mise/lib/pkcs11_helpers.sh — Shared helpers for PKCS#11 integration tests.
#
# Source this from any MISE task script that tests PKCS#11 providers:
#   source "${SCRIPT_DIR}/../../lib/pkcs11_helpers.sh"
#
# Provides:
#   get_cosmian_pkcs11_lib   — resolve + validate path to libcosmian_pkcs11.{so,dylib}
#   install_veracrypt        — download and install VeraCrypt from GitHub releases

# ── Guard against double-sourcing ─────────────────────────────────────────────
[ -n "${_MISE_PKCS11_HELPERS_SH_LOADED:-}" ] && return 0
_MISE_PKCS11_HELPERS_SH_LOADED=1

# ── Ensure lib/common.sh is loaded (provides get_repo_root, require_cmd, etc.) ──
_PKCS11_HELPERS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=.mise/lib/common.sh
source "${_PKCS11_HELPERS_DIR}/common.sh"

# Return the path to the built cosmian_pkcs11 shared library and verify it
# exists.  Exits with an error message if the library has not been compiled.
# Usage:
#   pkcs11_lib=$(get_cosmian_pkcs11_lib)
#   pkcs11_lib=$(get_cosmian_pkcs11_lib "$cargo_target_dir")
get_cosmian_pkcs11_lib() {
  local cargo_target_dir="${1:-${CARGO_TARGET_DIR:-}}"
  if [ -z "$cargo_target_dir" ]; then
    cargo_target_dir="$(get_repo_root)/target"
  fi
  local lib
  if [ "$(uname)" = "Darwin" ]; then
    lib="$cargo_target_dir/debug/libcosmian_pkcs11.dylib"
  else
    lib="$cargo_target_dir/debug/libcosmian_pkcs11.so"
  fi
  if [ ! -f "$lib" ]; then
    echo "ERROR: PKCS#11 library not found: $lib" >&2
    echo "       Run: cargo build -p cosmian_pkcs11 --features non-fips" >&2
    exit 1
  fi
  echo "$lib"
}

# Install VeraCrypt from the official GitHub releases page.
# Uses the Ubuntu-specific .deb when available; falls back to the console
# setup bundle.  Installs libfuse2 and fuse as prerequisites on Ubuntu 24.04.
#
# Pinned version is controlled by VERACRYPT_VERSION (default: 1.26.20).
# Returns non-zero if installation fails — with set -e this aborts the caller.
#
# Usage:
#   install_veracrypt             # uses VERACRYPT_VERSION or 1.26.20
#   install_veracrypt "1.26.20"
install_veracrypt() {
  local version="${1:-${VERACRYPT_VERSION:-1.26.20}}"
  local ubuntu_ver
  ubuntu_ver=$(lsb_release -rs 2>/dev/null || echo "24.04")
  echo "Installing VeraCrypt ${version} on Ubuntu ${ubuntu_ver}..."

  # VeraCrypt 1.26.x requires libfuse2 on Ubuntu 24.04 (which ships FUSE3).
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libfuse2 fuse 2>/dev/null || true

  local gh_base="https://github.com/veracrypt/VeraCrypt/releases/download/VeraCrypt_${version}"

  # Try the distro-specific .deb first (preferred: handles all deps automatically).
  local deb_name="veracrypt-${version}-Ubuntu-${ubuntu_ver}-amd64.deb"
  if curl -fsSL --max-time 120 --retry 3 --retry-delay 5 \
    "${gh_base}/${deb_name}" -o "/tmp/${deb_name}" 2>/dev/null; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "/tmp/${deb_name}"
    rm -f "/tmp/${deb_name}"
    return 0
  fi

  echo "WARN: distro-specific .deb not found; trying console setup bundle..."
  local bundle="veracrypt-${version}-setup.tar.bz2"
  if curl -fsSL --max-time 120 --retry 3 --retry-delay 5 \
    "${gh_base}/${bundle}" -o "/tmp/${bundle}" 2>/dev/null; then
    tar xjf "/tmp/${bundle}" -C /tmp/
    local setup_bin="/tmp/veracrypt-${version}-setup-console-x64"
    if [ -f "$setup_bin" ]; then
      # Non-interactively: accept EULA ("yes") then choose install ("1").
      printf 'yes\n1\n' | sudo "$setup_bin" 2>/dev/null || true
    fi
    rm -f "/tmp/${bundle}" "$setup_bin" 2>/dev/null || true
    return 0
  fi

  echo "ERROR: Failed to install VeraCrypt ${version} — no download succeeded." >&2
  return 1
}

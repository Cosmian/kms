#!/usr/bin/env bash
# .mise/lib/kms_build.sh — Shared helpers for building KMS binaries.
#
# Source this from any MISE task script that needs to build or locate the KMS
# server and/or ckms CLI binaries:
#   source "${MISE_CONFIG_ROOT:-.}/.mise/lib/kms_build.sh"
#
# Provides:
#   kms_build_server       — cargo build the KMS server binary
#   kms_build_cli          — cargo build the ckms CLI binary
#   kms_build_all          — build server + CLI (+ pkcs11 in non-fips mode)
#   get_kms_bin            — echo the path to the compiled KMS server binary
#   get_ckms_bin           — echo the path to the compiled ckms binary
#   get_cargo_target_dir   — echo the resolved cargo target directory
#
# Requires:
#   FEATURES_FLAG[] — set by kms_init_env from common.sh

# ── Guard ─────────────────────────────────────────────────────────────────────
[ -n "${_MISE_KMS_BUILD_SH_LOADED:-}" ] && return 0
_MISE_KMS_BUILD_SH_LOADED=1

# ── Require common.sh ─────────────────────────────────────────────────────────
_KMS_BUILD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "${_MISE_COMMON_SH_LOADED:-}" ]; then
  # shellcheck source=.mise/lib/common.sh
  source "${_KMS_BUILD_DIR}/common.sh"
fi

# ── Helpers ───────────────────────────────────────────────────────────────────

# Echo the resolved cargo target directory.
# Usage: target_dir=$(get_cargo_target_dir)
get_cargo_target_dir() {
  echo "${CARGO_TARGET_DIR:-$(get_repo_root)/target}"
}

# Echo the path to the compiled KMS server binary.
# Does NOT build it — call kms_build_server first.
# Usage: kms_bin=$(get_kms_bin)
get_kms_bin() {
  echo "$(get_cargo_target_dir)/debug/cosmian_kms"
}

# Echo the path to the compiled ckms CLI binary.
# Does NOT build it — call kms_build_cli first.
# Usage: ckms_bin=$(get_ckms_bin)
get_ckms_bin() {
  echo "$(get_cargo_target_dir)/debug/ckms"
}

# Build the KMS server binary.
# Usage: kms_build_server [extra_cargo_args...]
# Requires: FEATURES_FLAG[] from kms_init_env
kms_build_server() {
  require_cmd cargo "Cargo is required to build the KMS server."
  cargo build -p cosmian_kms_server "${FEATURES_FLAG[@]}" "$@"
}

# Build the ckms CLI binary.
# Usage: kms_build_cli [extra_cargo_args...]
# Requires: FEATURES_FLAG[] from kms_init_env
kms_build_cli() {
  require_cmd cargo "Cargo is required to build the ckms CLI."
  cargo build -p ckms "${FEATURES_FLAG[@]}" "$@"
}

# Build server + CLI + (optionally) PKCS#11 library.
# In non-fips mode, also builds cosmian_pkcs11.
# Usage: kms_build_all [extra_cargo_args...]
# Requires: FEATURES_FLAG[], VARIANT from kms_init_env
kms_build_all() {
  require_cmd cargo "Cargo is required to build KMS binaries."
  local packages=(-p cosmian_kms_server -p ckms)
  if [ "${VARIANT:-fips}" = "non-fips" ]; then
    packages+=(-p cosmian_pkcs11)
  fi
  cargo build "${packages[@]}" "${FEATURES_FLAG[@]}" "$@"
}

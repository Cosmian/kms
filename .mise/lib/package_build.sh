#!/usr/bin/env bash
# .mise/lib/package_build.sh — Shared packaging logic for DEB/RPM/DMG builds.
#
# Source this from package tasks:
#   source "${MISE_CONFIG_ROOT:-.}/.mise/lib/package_build.sh"
#
# Provides:
#   pkg_nix_build_server <variant> <link> <out_link>
#   pkg_nix_build_cli <variant> <link> <out_link>
#   pkg_extract_version
#   pkg_build_deb <result_link> <variant> <link>
#   pkg_build_rpm <result_link> <variant> <link>

# ── Guard ─────────────────────────────────────────────────────────────────────
[ -n "${_MISE_PACKAGE_BUILD_SH_LOADED:-}" ] && return 0
_MISE_PACKAGE_BUILD_SH_LOADED=1

# ── Require libs ──────────────────────────────────────────────────────────────
if [ -z "${_MISE_COMMON_SH_LOADED:-}" ]; then
  source "${MISE_CONFIG_ROOT:-.}/.mise/lib/common.sh"
fi
if [ -z "${_MISE_NIX_HELPERS_SH_LOADED:-}" ]; then
  source "${MISE_CONFIG_ROOT:-.}/.mise/lib/nix_helpers.sh"
fi

# Build the KMS server binary via Nix.
# Usage: pkg_nix_build_server <variant> <link> <out_link>
pkg_nix_build_server() {
  local variant="$1" link="$2" out_link="$3"
  local attr="kms-server-${variant}-${link}-openssl"
  print_status "Building server (attr=${attr})..."
  nix_build "$attr" "$out_link"
}

# Build the ckms CLI binary via Nix.
# Usage: pkg_nix_build_cli <variant> <link> <out_link>
pkg_nix_build_cli() {
  local variant="$1" link="$2" out_link="$3"
  local attr="kms-cli-${variant}-${link}-openssl"
  print_status "Building CLI (attr=${attr})..."
  nix_build "$attr" "$out_link"
}

# Extract the workspace version from the root Cargo.toml.
pkg_extract_version() {
  local repo_root
  repo_root="$(get_repo_root)"
  grep '^version' "$repo_root/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/'
}

# Build a .deb package from a Nix result link.
# Usage: pkg_build_deb <result_link> <variant> <link>
pkg_build_deb() {
  # shellcheck disable=SC2034  # result_link is the Nix output path; positional for documentation clarity
  local result_link="$1" variant="$2" link="$3"
  local repo_root
  repo_root="$(get_repo_root)"

  # Delegate to the full packaging script (handles staging + cargo-deb)
  bash "${repo_root}/.mise/scripts/package/package_common.sh" \
    --format deb \
    --variant "${variant}" \
    --link "${link}"
}

# Build an .rpm package from a Nix result link.
# Usage: pkg_build_rpm <result_link> <variant> <link>
pkg_build_rpm() {
  # shellcheck disable=SC2034  # result_link is the Nix output path; positional for documentation clarity
  local result_link="$1" variant="$2" link="$3"
  local repo_root
  repo_root="$(get_repo_root)"

  # Delegate to the full packaging script (handles staging + cargo-generate-rpm)
  bash "${repo_root}/.mise/scripts/package/package_common.sh" \
    --format rpm \
    --variant "${variant}" \
    --link "${link}"
}

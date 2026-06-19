#!/usr/bin/env bash
# .mise/scripts/common.sh — backward-compatibility shim.
#
# All substantive functions are maintained in .mise/lib/common.sh (the
# authoritative copy).  This file delegates to that library and re-exports
# the few extras that scripts/common.sh historically provided.
#
# Active scripts should eventually migrate to sourcing .mise/lib/common.sh
# directly and calling kms_init_env <variant> <link> instead of
# init_build_env "$@".

# Guard against double-sourcing
if [ -n "${_SCRIPTS_COMMON_SH_LOADED:-}" ]; then return 0; fi
_SCRIPTS_COMMON_SH_LOADED=1

_SCRIPTS_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=.mise/lib/common.sh
source "${_SCRIPTS_COMMON_DIR}/../lib/common.sh"

# ── Extras not present in lib/common.sh ──────────────────────────────────────

# Unified nixpkgs pin consumed by nix.sh and any build script that sources
# this file.  Set once here so every caller uses the same pinned tarball.
export PIN_URL="${PIN_URL:-https://package.cosmian.com/nixpkgs/8b27c1239e5c421a2bbc2c65d52e4a6fbf2ff296.tar.gz}"
export PINNED_NIXPKGS_URL="$PIN_URL" # backward-compatible alias

# init_build_env: parse --variant / --link flags then delegate to kms_init_env.
# Legacy entry-point used by scripts that receive "$@" and need to extract
# these flags.  New scripts call kms_init_env <variant> <link> directly.
init_build_env() {
  local variant="fips" link="static"
  local i=1
  while [ $i -le $# ]; do
    case "${!i}" in
      --variant)
        i=$((i + 1))
        variant="${!i:-}"
        ;;
      --link)
        i=$((i + 1))
        link="${!i:-}"
        ;;
    esac
    i=$((i + 1))
  done
  # Inherit from environment when flags were not supplied
  [ "$variant" = "fips" ] && [ -n "${VARIANT:-}" ] && variant="$VARIANT"
  [ "$link" = "static" ] && [ -n "${LINK:-}" ] && link="$LINK"
  kms_init_env "$variant" "$link"
}

# _wait_for_port: legacy name kept for scripts that call it directly.
# lib/common.sh exports the canonical wait_for_port().
_wait_for_port() { wait_for_port "$@"; }

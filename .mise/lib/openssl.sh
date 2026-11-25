#!/usr/bin/env bash
# .mise/lib/openssl.sh — Read the OpenSSL versions pinned in crate/crypto/openssl_versions.json,
# the single source of truth shared with crate/crypto/build.rs, the Nix build and the CI.
#
# Source this from a script:
#   source "${MISE_CONFIG_ROOT:-.}/.mise/lib/openssl.sh"
#
# Provides (`which` is `main` for the linked library, `fips` for the CMVP-validated provider):
#   openssl_version <which>   e.g. 3.6.5
#   openssl_sha256 <which>
#   openssl_url <which>       download URL of the source tarball on the Cosmian mirror

# ── Guard ─────────────────────────────────────────────────────────────────────
[ -n "${_MISE_OPENSSL_SH_LOADED:-}" ] && return 0
_MISE_OPENSSL_SH_LOADED=1

_OPENSSL_VERSIONS_JSON="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/crate/crypto/openssl_versions.json"

# _openssl_field <which> <version|sha256>
_openssl_field() {
  local which="$1" field="$2"
  case "$which" in main | fips) ;; *)
    echo "openssl_${field}: expected 'main' or 'fips', got '${which}'" >&2
    return 2
    ;;
  esac
  if command -v jq >/dev/null 2>&1; then
    jq -er --arg w "$which" --arg f "$field" '.[$w][$f]' "$_OPENSSL_VERSIONS_JSON"
  else
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]][sys.argv[3]])' \
      "$_OPENSSL_VERSIONS_JSON" "$which" "$field"
  fi
}

openssl_version() { _openssl_field "$1" version; }
openssl_sha256() { _openssl_field "$1" sha256; }
openssl_url() {
  local version
  version="$(openssl_version "$1")" || return
  echo "https://package.cosmian.com/openssl/openssl-${version}.tar.gz"
}

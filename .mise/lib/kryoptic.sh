#!/usr/bin/env bash
# .mise/lib/kryoptic.sh — Out-of-tree build helper for the published `kryoptic`
# PKCS#11 v3.0 software token (https://github.com/latchset/kryoptic), used
# exclusively as a v3.0 conformance-test oracle by
# crate/hsm/base_hsm/tests/kryoptic_conformance.rs.
#
# `kryoptic` is deliberately NOT a [dev-dependencies] entry in
# crate/hsm/base_hsm/Cargo.toml: its `kryoptic-lib` dependency requires
# `rusqlite = "0.38.0"` (exact 0.x minor), while crate/server_database depends
# on `tokio-rusqlite`, which only ever pins `rusqlite` at `^0.37` or
# `^0.40.1` — never `0.38.x`. Both `rusqlite` major/minor lines pull in a
# different `libsqlite3-sys` version, and Cargo forbids two versions of a
# crate that both declare `links = "sqlite3"` in one resolved graph.
# Declaring `kryoptic` as a workspace dependency would break the entire
# workspace build. Instead, this library fetches and builds the published
# `kryoptic` crate out-of-tree, in its own isolated Cargo invocation/lockfile,
# so it never touches this workspace's dependency graph — mirroring how
# softhsm2.sh builds/locates the SoftHSM2 PKCS#11 library outside Cargo.
#
# Source this from a task file:
#   source "${MISE_CONFIG_ROOT:-.}/.mise/lib/kryoptic.sh"
#
# Provides:
#   kryoptic_build_cdylib
#
# Globals set:
#   KRYOPTIC_PKCS11_LIB

# ── Guard ─────────────────────────────────────────────────────────────────────
[ -n "${_MISE_KRYOPTIC_SH_LOADED:-}" ] && return 0
_MISE_KRYOPTIC_SH_LOADED=1

# ── Require common.sh ─────────────────────────────────────────────────────────
if [ -z "${_MISE_COMMON_SH_LOADED:-}" ]; then
  source "${MISE_CONFIG_ROOT:-.}/.mise/lib/common.sh"
fi

# Pinned version of the published `kryoptic` crate (crates.io) used as the
# v3.0 conformance oracle. Bump deliberately, alongside re-verifying the
# conformance test suite, rather than floating to "latest".
KRYOPTIC_VERSION="1.5.2"

KRYOPTIC_PKCS11_LIB=""

# cdylib filename for the current OS.
_kryoptic_cdylib_filename() {
  case "$(uname -s)" in
    Darwin) echo "libkryoptic_pkcs11.dylib" ;;
    *) echo "libkryoptic_pkcs11.so" ;;
  esac
}

# Download (if needed), build, and locate the `kryoptic` cdylib artifact.
# Usage: kryoptic_build_cdylib
# Sets: KRYOPTIC_PKCS11_LIB (exported) — absolute path to the built
#   libkryoptic_pkcs11.{so,dylib} artifact.
#
# The download+extract step is cached under the system temp dir: subsequent
# calls reuse the extracted source and Cargo's own incremental build cache.
kryoptic_build_cdylib() {
  require_cmd curl
  require_cmd tar
  require_cmd cargo

  local root="${TMPDIR:-/tmp}/cosmian-kms-kryoptic-conformance"
  local src_dir="${root}/kryoptic-${KRYOPTIC_VERSION}"

  if [ ! -f "${src_dir}/Cargo.toml" ]; then
    mkdir -p "$root"
    local tarball="${root}/kryoptic.crate.tar.gz"
    print_status "Downloading kryoptic ${KRYOPTIC_VERSION} from crates.io"
    curl -sSfL \
      -A "cosmian-kms-base-hsm-kryoptic-conformance-tests" \
      -o "$tarball" \
      "https://crates.io/api/v1/crates/kryoptic/${KRYOPTIC_VERSION}/download"
    tar xzf "$tarball" -C "$root"
  fi

  # `standard` = sqlitedb + ecc_all (incl. eddsa) + ffdh + hash_all + kdf_all
  # (incl. hkdf) + rsa + hotp — i.e. every v3.0 mechanism family exercised by
  # the conformance tests. This build is fully isolated (its own Cargo.lock),
  # so the `rusqlite` conflict that blocks a normal workspace dependency does
  # not apply here.
  print_status "Building kryoptic cdylib (cargo build --release --features standard)"
  (cd "$src_dir" && cargo build --release --features standard)

  local cdylib_name artifact
  cdylib_name="$(_kryoptic_cdylib_filename)"
  artifact="${src_dir}/target/release/${cdylib_name}"
  if [ ! -f "$artifact" ]; then
    print_error "kryoptic cdylib artifact not found at expected path ${artifact} after build"
  fi

  KRYOPTIC_PKCS11_LIB="$artifact"
  export KRYOPTIC_PKCS11_LIB
  print_status "kryoptic cdylib ready at ${KRYOPTIC_PKCS11_LIB}"
}

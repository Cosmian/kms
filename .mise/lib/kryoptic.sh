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

# Builds this workspace's own OpenSSL (see crate/crypto/build.rs, pinned to
# 3.6.2) if not already built, and points `kryoptic`'s OpenSSL discovery at it
# via `PKG_CONFIG_PATH`, instead of letting it silently pick up whatever
# OpenSSL happens to be installed system-wide.
#
# Why this matters: `kryoptic-lib`'s default feature set enables `ossl/dynamic`
# (`pkg_config::Config::new().probe("openssl")`), and the `standard` feature
# pulls in `eddsa`, which requires `ossl/ossl320` — i.e. kryoptic itself
# hard-requires OpenSSL >= 3.2.0. Ubuntu 22.04/24.04 CI runners (and some
# local dev machines) ship an older system OpenSSL (e.g. 3.0.x), which fails
# this check with "OpenSSL 3.2.0 or later is required" even though this exact
# workspace already builds a conformant OpenSSL 3.6.2 for its own crates.
# Uniformizing on that same build removes the dependency on the ambient
# system OpenSSL version entirely, making this suite reproducible across
# local machines and CI.
_kryoptic_ensure_repo_openssl() {
  require_cmd cargo
  require_cmd pkg-config

  local repo_root target_dir
  repo_root="$(get_repo_root "${MISE_CONFIG_ROOT:-.}")"
  target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"

  # `FEATURES_FLAG` is normally set by `kms_init_env` (empty array for fips,
  # `(--features non-fips)` for non-fips). Default to empty under `set -u` if
  # this function is ever invoked without it having run first.
  local -a features_flag=()
  if [ "${FEATURES_FLAG+set}" = "set" ]; then
    features_flag=("${FEATURES_FLAG[@]}")
  fi

  print_status "Building this workspace's OpenSSL 3.6.2 (cargo build -p cosmian_kms_crypto), \
if not already built"
  (cd "$repo_root" && cargo build -p cosmian_kms_crypto "${features_flag[@]}")

  # Mirrors crate/crypto/build.rs's prefix naming: `openssl-<version>-<os>-<arch>`
  # for FIPS, `openssl-non-fips-<version>-<os>-<arch>` for non-FIPS. Globbed
  # rather than reconstructed from `uname`, so this does not need to track the
  # pinned OpenSSL version or the os/arch string conventions independently.
  local prefix glob_desc candidates
  local glob_pattern
  if [ "${VARIANT:-fips}" = "non-fips" ]; then
    glob_desc="${target_dir}/openssl-non-fips-*"
    candidates=("${target_dir}"/openssl-non-fips-*)
  else
    glob_desc="${target_dir}/openssl-[0-9]*"
    glob_pattern="${target_dir}/openssl-[0-9]*"
    # shellcheck disable=SC2206 # intentional glob expansion of a version-numbered prefix
    candidates=($glob_pattern)
  fi
  prefix="${candidates[0]:-}"
  if [ -z "$prefix" ] || [ ! -d "$prefix" ]; then
    print_error "Could not locate this workspace's built OpenSSL prefix under ${target_dir} \
(expected a directory matching ${glob_desc})"
  fi
  if [ ! -f "${prefix}/lib/pkgconfig/openssl.pc" ]; then
    print_error "No openssl.pc found under ${prefix}/lib/pkgconfig; this workspace's OpenSSL \
build layout may have changed (see crate/crypto/build.rs)"
  fi

  # Our OpenSSL is built `no-shared` (static only, see crate/crypto/build.rs), so
  # request static linking explicitly — the `pkg-config` crate honors
  # `OPENSSL_STATIC` the same way `openssl-sys` does.
  PKG_CONFIG_PATH="${prefix}/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
  export PKG_CONFIG_PATH
  OPENSSL_STATIC=1
  export OPENSSL_STATIC
  print_status "kryoptic will build against this workspace's OpenSSL at ${prefix}"
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

  _kryoptic_ensure_repo_openssl

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
  # not apply here. `PKG_CONFIG_PATH`/`OPENSSL_STATIC` (set by
  # `_kryoptic_ensure_repo_openssl` above) steer `ossl/dynamic`'s pkg-config
  # probe at this workspace's own OpenSSL 3.6.2 instead of the ambient system
  # one.
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

#!/usr/bin/env bash
# .mise/lib/kryoptic.sh — Out-of-tree build helper for the published `kryoptic`
# PKCS#11 v3.0 software token (https://github.com/latchset/kryoptic), used
# as the PKCS#11 v3.0 test token by crate/hsm/kryoptic
# (`mise run test:hsm-kryoptic`).
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
#   kryoptic_setup <state_dir>
#
# Globals set:
#   KRYOPTIC_PKCS11_LIB, KRYOPTIC_CONF, KRYOPTIC_HSM_SLOT_ID, HSM_USER_PASSWORD

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
#
# The NON-FIPS prefix is used for every variant, never the FIPS one. The FIPS
# prefix's openssl.cnf activates `fips.so`; the KMS test binary (static OpenSSL,
# FIPS provider) and the kryoptic cdylib (its own static OpenSSL copy) would then
# both dlopen that same module in one process. The FIPS module keeps its core
# dispatch table in file-scope globals, so the two OpenSSL copies corrupt each
# other and the KMS default context intermittently loses CTR-DRBG ("unable to
# fetch drbg"), failing every KmsRng call. The non-FIPS prefix only uses the
# built-in default provider (no shared module), and kryoptic is only the token
# simulator, so its own OpenSSL flavour is irrelevant to what the KMS tests.
_kryoptic_ensure_repo_openssl() {
  require_cmd cargo
  require_cmd pkg-config

  local repo_root target_dir
  repo_root="$(get_repo_root "${MISE_CONFIG_ROOT:-.}")"
  target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"

  print_status "Building this workspace's non-FIPS OpenSSL 3.6.2 (cargo build -p cosmian_kms_crypto \
--features non-fips), if not already built"
  (cd "$repo_root" && cargo build -p cosmian_kms_crypto --features non-fips)

  # Mirrors crate/crypto/build.rs's prefix naming: `openssl-<version>-<os>-<arch>`
  # for FIPS, `openssl-non-fips-<version>-<os>-<arch>` for non-FIPS. Globbed
  # rather than reconstructed from `uname`, so this does not need to track the
  # pinned OpenSSL version or the os/arch string conventions independently.
  local prefix candidates
  candidates=("${target_dir}"/openssl-non-fips-*)
  prefix="${candidates[0]:-}"
  if [ -z "$prefix" ] || [ ! -d "$prefix" ]; then
    print_error "Could not locate this workspace's non-FIPS OpenSSL prefix under ${target_dir} \
(expected a directory matching ${target_dir}/openssl-non-fips-*)"
  fi
  if [ ! -f "${prefix}/lib/pkgconfig/openssl.pc" ]; then
    print_error "No openssl.pc found under ${prefix}/lib/pkgconfig; this workspace's OpenSSL \
build layout may have changed (see crate/crypto/build.rs)"
  fi

  # Our OpenSSL is built `no-shared` (static only, see crate/crypto/build.rs). Keep
  # these values in private helper variables: shellHook exports such as PKG_CONFIG_PATH
  # and OPENSSL_STATIC must not be mutated, or later workspace builds inherit Kryoptic's
  # static-prefix settings and fail to link libssl/libcrypto.
  KRYOPTIC_BUILD_PKG_CONFIG_PATH="${prefix}/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
  KRYOPTIC_BUILD_PKG_CONFIG_PATH_FOR_TARGET="${prefix}/lib/pkgconfig${PKG_CONFIG_PATH_FOR_TARGET:+:${PKG_CONFIG_PATH_FOR_TARGET}}"
  KRYOPTIC_BUILD_OPENSSL_SOURCES="${prefix}"
  KRYOPTIC_BUILD_OPENSSL_STATIC=1
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
  # not apply here. Pass the overrides explicitly at the Cargo boundary. This avoids
  # relying on shell function/subshell export behavior when `env -u CARGO_TARGET_DIR`
  # launches the isolated Kryoptic workspace build.
  # `KRYOPTIC_OPENSSL_SOURCES` is consumed by ossl-sys; the pkg-config variables steer
  # both host and target discovery, and the bindgen override keeps workspace headers
  # ahead of Nix's system include defaults.
  print_status "Building kryoptic cdylib (cargo build --release --features standard)"
  (
    cd "$src_dir" || exit
    env -u CARGO_TARGET_DIR \
      PKG_CONFIG_PATH="$KRYOPTIC_BUILD_PKG_CONFIG_PATH" \
      PKG_CONFIG_PATH_FOR_TARGET="$KRYOPTIC_BUILD_PKG_CONFIG_PATH_FOR_TARGET" \
      KRYOPTIC_OPENSSL_SOURCES="$KRYOPTIC_BUILD_OPENSSL_SOURCES" \
      OSSL_BINDGEN_CLANG_ARGS="-isystem ${KRYOPTIC_BUILD_OPENSSL_SOURCES}/include" \
      OPENSSL_STATIC="$KRYOPTIC_BUILD_OPENSSL_STATIC" \
      cargo build --release --features standard
  )

  local cdylib_name artifact
  cdylib_name="$(_kryoptic_cdylib_filename)"
  artifact="${src_dir}/target/release/${cdylib_name}"
  if [ ! -f "$artifact" ] && [ -n "${CARGO_TARGET_DIR:-}" ] && [ -f "${CARGO_TARGET_DIR}/release/${cdylib_name}" ]; then
    artifact="${CARGO_TARGET_DIR}/release/${cdylib_name}"
  fi
  if [ ! -f "$artifact" ]; then
    print_error "kryoptic cdylib artifact not found at expected path ${artifact} after build"
  fi

  # Fail fast on a stale artifact: Cargo may reuse a cached cdylib whose static OpenSSL still
  # has the FIPS prefix baked in as OPENSSLDIR (e.g. a cached temp dir from before the
  # non-FIPS switch). That copy would load `fips.so` next to the KMS's own and reproduce the
  # "unable to fetch drbg" failure, so refuse to run rather than report a misleading result.
  if ! grep -aqF "${KRYOPTIC_BUILD_OPENSSL_SOURCES}/ssl" "$artifact"; then
    print_error "${artifact} was not built against ${KRYOPTIC_BUILD_OPENSSL_SOURCES}; it is stale. \
Run 'cargo clean -p ossl-sys -p kryoptic-lib' in ${src_dir} (or delete ${src_dir}/target) and retry"
  fi

  # An explicit OPENSSL_CONF overrides the baked-in OPENSSLDIR for BOTH the KMS and the
  # kryoptic OpenSSL copies, so a FIPS config would make them share `fips.so` again.
  if [ -n "${OPENSSL_CONF:-}" ]; then
    print_warning "OPENSSL_CONF=${OPENSSL_CONF} is set: kryoptic's OpenSSL will read it too. If it \
activates the FIPS provider, kryoptic and the KMS share fips.so and the KMS RNG can fail with \
'unable to fetch drbg'. Unset it for this task unless it is default-provider only."
  fi

  KRYOPTIC_PKCS11_LIB="$artifact"
  export KRYOPTIC_PKCS11_LIB
  print_status "kryoptic cdylib ready at ${KRYOPTIC_PKCS11_LIB}"
}
# Setup Kryoptic configuration pointing to an SQLite-backed token database.
# Usage: kryoptic_setup <state_dir>
# Sets: KRYOPTIC_CONF, KRYOPTIC_HSM_SLOT_ID, HSM_USER_PASSWORD (exported)
kryoptic_setup() {
  local state_dir="$1"
  rm -rf "$state_dir"
  mkdir -p "$state_dir"

  local db_path="${state_dir}/token.sql"
  local conf_path="${state_dir}/token.conf"

  cat >"$conf_path" <<EOF
[[slots]]
slot = 1
dbtype = "sqlite"
dbargs = "${db_path}"
EOF

  KRYOPTIC_CONF="$conf_path"
  KRYOPTIC_HSM_SLOT_ID=1
  HSM_USER_PASSWORD="12345678"

  export KRYOPTIC_CONF
  export KRYOPTIC_HSM_SLOT_ID
  export HSM_USER_PASSWORD
  print_status "Kryoptic token configured at slot ${KRYOPTIC_HSM_SLOT_ID} with config ${KRYOPTIC_CONF}"
}

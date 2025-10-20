{ pkgs ? import (builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/24.05.tar.gz";
    sha256 = "1lr1h35prqkd1mkmzriwlpvxcb34kmhc9dnr48gkm8hh089hifmx";
  }) {} }:

let
  # Platform flags
  isLinux = pkgs.stdenv.isLinux;
  isDarwin = pkgs.stdenv.isDarwin;
  isLinuxStr = if isLinux then "1" else "0";
  isDarwinStr = if isDarwin then "1" else "0";

  # Detect the host nixpkgs glibc version (Linux only)
  hostGlibcVersion = if isLinux then (pkgs.stdenv.cc.libc.version or (pkgs.lib.getVersion pkgs.stdenv.cc.libc)) else "n/a";

  # If host glibc > 2.28, fall back to a pinned nixpkgs with glibc 2.28 (nixos-19.03)
  # You can override via environment variable NIXPKGS_GLIBC_228_URL if needed.
  legacyUrl = builtins.getEnv "NIXPKGS_GLIBC_228_URL";
  nixpkgs_19_03_url = if legacyUrl != "" then legacyUrl
    else "https://github.com/NixOS/nixpkgs/archive/refs/heads/nixos-19.03.tar.gz";

  # On Linux, if host glibc > 2.28, fall back to a pinned nixpkgs with glibc 2.28; on non-Linux, just use current pkgs
  pkgsGlibc228 = if isLinux then (
    if pkgs.lib.versionOlder hostGlibcVersion "2.29"
    then pkgs
    else import (builtins.fetchTarball {
      # Consider pinning sha256 for full reproducibility
      url = nixpkgs_19_03_url;
    }) {}
  ) else pkgs;

  # Verify the selected pkgs set actually uses glibc 2.28
  selectedGlibcVersion = if isLinux then (pkgsGlibc228.stdenv.cc.libc.version or (pkgsGlibc228.lib.getVersion pkgsGlibc228.stdenv.cc.libc)) else "n/a";
  _ = if isLinux then pkgsGlibc228.lib.assertMsg (pkgsGlibc228.lib.versionOlder selectedGlibcVersion "2.29")
    ("Selected nixpkgs uses glibc > 2.28 (got " + selectedGlibcVersion
      + "). Set NIXPKGS_GLIBC_228_URL to a nixpkgs tarball with glibc <= 2.28.") else true;

  # Allow using a preinstalled OpenSSL instead of building in Nix when provided
  externalOpenSSLDir = builtins.getEnv "EXTERNAL_OPENSSL_DIR";
  useNixOpenSSLFlag = builtins.getEnv "USE_NIX_OPENSSL";
  # If USE_NIX_OPENSSL=1 is provided, force using Nix-built OpenSSL even if EXTERNAL_OPENSSL_DIR is set
  useExternalOpenSSL = if useNixOpenSSLFlag == "1" then false else externalOpenSSLDir != "";

  # Pinned OpenSSL 3.1.2 derivation (only when no external dir is provided)
  openssl312 = if useExternalOpenSSL then null else pkgsGlibc228.callPackage ./nix/openssl-3_1_2-fips.nix {};
  opensslOut = if useExternalOpenSSL then externalOpenSSLDir else (builtins.toString openssl312);
in
pkgsGlibc228.mkShell {
  name = "cosmian-kms-dev-shell";

  # Tools available in the shell
  buildInputs = [
    pkgsGlibc228.pkg-config
    pkgsGlibc228.cmake
    pkgsGlibc228.git
    pkgsGlibc228.rustup
  ]
  # Prefer GCC/binutils on Linux; avoid GNU binutils on macOS where Apple tooling is used
  ++ (if isLinux then [ pkgsGlibc228.gcc pkgsGlibc228.binutils ] else [])
  ++ (if useExternalOpenSSL then [] else [ openssl312 ]);

  # Defaults that can be overridden when invoking
  DEBUG_OR_RELEASE = "debug";
  FEATURES = "non-fips";
  # Expose detected glibc version
  # Expose versions for visibility
  HOST_GLIBC_VERSION = hostGlibcVersion;
  GLIBC_VERSION = selectedGlibcVersion;

  # Ensure crates link to our OpenSSL and not vendored/system
  OPENSSL_NO_VENDOR = "1";
  OPENSSL_STATIC = "1";
  PKG_CONFIG_ALL_STATIC = "1";
  OPENSSL_DIR = opensslOut;
  # Help crates like openssl-sys find the right headers and libs deterministically
  OPENSSL_INCLUDE_DIR = "${opensslOut}/include";
  # Prefer lib first, fall back to lib64 if needed in shellHook
  OPENSSL_LIB_DIR = "${opensslOut}/lib";

  shellHook = ''
    # Export simple platform flags for use in shell logic
    export IS_LINUX="${isLinuxStr}"
    export IS_DARWIN="${isDarwinStr}"

    if [ -n "${externalOpenSSLDir}" ] && [ "${useNixOpenSSLFlag}" != "1" ]; then
      echo "cosmian-kms nix-shell ready (OpenSSL 3.1.2 from EXTERNAL_OPENSSL_DIR: ${externalOpenSSLDir})"
    else
      echo "cosmian-kms nix-shell ready (OpenSSL 3.1.2 from Nix derivation)"
    fi
    if [ "$IS_LINUX" = "1" ]; then
      echo "host glibc version: ${hostGlibcVersion}"
      echo "toolchain glibc (nixpkgs) version: ${selectedGlibcVersion}"
    fi

    # Force OpenSSL environment to our Nix-built OpenSSL 3.1.2
    export OPENSSL_DIR="${opensslOut}"
    export OPENSSL_INCLUDE_DIR="${opensslOut}/include"
    # Default to lib; may switch to lib64 below if present
    export OPENSSL_LIB_DIR="${opensslOut}/lib"
    export OPENSSL_NO_VENDOR=1
    export OPENSSL_STATIC=1
    export PKG_CONFIG_ALL_STATIC=1

    # Prepend OpenSSL bin to PATH for deterministic `openssl` resolution
    if [ -d "''${OPENSSL_DIR}/bin" ]; then
      export PATH="''${OPENSSL_DIR}/bin:$PATH"
    fi

    # Ensure pkg-config can locate OpenSSL .pc files (first in search path)
    pc_dir=""
    if [ -d "''${OPENSSL_DIR}/lib/pkgconfig" ]; then
      pc_dir="''${OPENSSL_DIR}/lib/pkgconfig"
    elif [ -d "''${OPENSSL_DIR}/lib64/pkgconfig" ]; then
      pc_dir="''${OPENSSL_DIR}/lib64/pkgconfig"
    fi
    if [ -n "$pc_dir" ]; then
      # Force pkg-config to resolve exclusively to our OpenSSL .pc files
      export PKG_CONFIG_PATH="$pc_dir"
      export PKG_CONFIG_LIBDIR="$pc_dir"
    fi

    # If lib64 exists, point OPENSSL_LIB_DIR to it to match static libs location
    if [ -d "''${OPENSSL_DIR}/lib64" ]; then
      export OPENSSL_LIB_DIR="''${OPENSSL_DIR}/lib64"
    fi

    # Make sure our OpenSSL include/lib paths come first for any C/C++ compilation (e.g., openssl-sys probe)
    export NIX_CFLAGS_COMPILE="-I''${OPENSSL_INCLUDE_DIR} ''${NIX_CFLAGS_COMPILE:-}"
    # Prefer lib64 if present
    if [ -d "''${OPENSSL_DIR}/lib64" ]; then
      export NIX_LDFLAGS="-L''${OPENSSL_DIR}/lib64 ''${NIX_LDFLAGS:-}"
    else
      export NIX_LDFLAGS="-L''${OPENSSL_DIR}/lib ''${NIX_LDFLAGS:-}"
    fi
  ''
  # Linux-only toolchain pinning and glibc rpath/dynamic linker injection (avoid evaluating on macOS)
  + (if isLinux then ''
    # Ensure we always use the Nix toolchain (glibc ≤ 2.28) for linking (Linux only)
    export NIX_CC_DIR="${pkgsGlibc228.stdenv.cc}/bin"
    export NIX_BINUTILS_DIR="${pkgsGlibc228.binutils}/bin"
    if [ -d "''${NIX_CC_DIR}" ]; then
      export PATH="''${NIX_CC_DIR}:$PATH"
    fi
    if [ -d "''${NIX_BINUTILS_DIR}" ]; then
      export PATH="''${NIX_BINUTILS_DIR}:$PATH"
    fi
    # Explicitly pin toolchain binaries
    export CC="${pkgsGlibc228.stdenv.cc}/bin/cc"
    export CXX="${pkgsGlibc228.stdenv.cc}/bin/c++"
    # Prefer unwrapped binutils binaries to avoid wrapper indirections that may refer to stale store paths
    _BINUTILS_UNWRAPPED_BIN="${pkgsGlibc228.binutils-unwrapped or pkgsGlibc228.binutils}/bin"
    if [ ! -x "$_BINUTILS_UNWRAPPED_BIN/ar" ] && [ -x "${pkgsGlibc228.binutils}/bin/ar" ]; then
      _BINUTILS_UNWRAPPED_BIN="${pkgsGlibc228.binutils}/bin"
    fi
    export LD="$_BINUTILS_UNWRAPPED_BIN/ld"
    export AR="$_BINUTILS_UNWRAPPED_BIN/ar"
    export NM="$_BINUTILS_UNWRAPPED_BIN/nm"
    export RANLIB="$_BINUTILS_UNWRAPPED_BIN/ranlib"
    export OBJDUMP="$_BINUTILS_UNWRAPPED_BIN/objdump"
    # Make rust/cargo use the pinned linker
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$CC"
    # And the pinned archiver (avoid stale binutils-wrapper paths)
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_AR="$AR"
    # Also set target-specific CC/AR env vars that the cc crate recognizes
    export CC_x86_64_unknown_linux_gnu="$CC"
    export AR_x86_64_unknown_linux_gnu="$AR"

    # Enforce dynamic linker and rpath to glibc <= 2.28 from the pinned nixpkgs (Linux only)
    glibc_lib_dir="${pkgsGlibc228.glibc}/lib"
    dyn_linker_path="${pkgsGlibc228.glibc}/lib/ld-linux-x86-64.so.2"
    # Append link-args while preserving any existing RUSTFLAGS
    export RUSTFLAGS="''${RUSTFLAGS:+$RUSTFLAGS }-C link-args=-Wl,--dynamic-linker=$dyn_linker_path -C link-args=-Wl,-rpath,$glibc_lib_dir"

    echo "Toolchain: CC=$CC | AR=$AR"
    echo "Target toolchain: CC_x86_64_unknown_linux_gnu=$CC_x86_64_unknown_linux_gnu | AR_x86_64_unknown_linux_gnu=$AR_x86_64_unknown_linux_gnu"
    echo "Cargo target overrides: LINKER=$CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER | AR=$CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_AR"
    if [ ! -x "$AR" ]; then
      echo "Warning: AR does not exist at $AR; attempting to fall back to 'ar' on PATH" >&2
      if command -v ar >/dev/null 2>&1; then
        export AR="$(command -v ar)"
        export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_AR="$AR"
        export AR_x86_64_unknown_linux_gnu="$AR"
        echo "Using fallback AR at $AR" >&2
      else
        echo "Error: could not find a working 'ar' tool" >&2
        exit 1
      fi
    fi
  '' else "")
  + ''
    # Old binutils in the glibc 2.27 toolchain can choke on compressed DWARF in dev builds
    # Avoid the issue in debug by disabling debuginfo unless explicitly overridden
    if [ "''${DEBUG_OR_RELEASE}" = "debug" ] && [ -z "''${RUSTFLAGS:-}" ]; then
      export RUSTFLAGS="-C debuginfo=0 $RUSTFLAGS"
    fi

    # Validate OpenSSL version = 3.1.2
    if ! command -v openssl >/dev/null 2>&1; then
      echo "Error: openssl not found in PATH (expected from ''${OPENSSL_DIR}/bin)." >&2
      exit 1
    fi
    sel_ver=$(openssl version 2>/dev/null | awk '{print $2}')
    if [ "$sel_ver" != "3.1.2" ]; then
      echo "Error: OpenSSL version must be 3.1.2, found: $sel_ver from $(command -v openssl)" >&2
      exit 1
    fi

    # Basic static artifacts check (lib or lib64)
   if { [ ! -f "''${OPENSSL_DIR}/lib/libcrypto.a" ] || [ ! -f "''${OPENSSL_DIR}/lib/libssl.a" ]; } \
     && { [ ! -f "''${OPENSSL_DIR}/lib64/libcrypto.a" ] || [ ! -f "''${OPENSSL_DIR}/lib64/libssl.a" ]; }; then
      echo "Error: Missing static OpenSSL libs in ''${OPENSSL_DIR}/lib or lib64 (libcrypto.a, libssl.a)." >&2
      exit 1
    fi

    # FIPS provider artifacts should exist (darwin/linux derivations)
    if [ ! -f "''${OPENSSL_DIR}/ssl/fipsmodule.cnf" ]; then
      echo "Error: Missing fipsmodule.cnf in ''${OPENSSL_DIR}/ssl (FIPS installation incomplete)." >&2
      exit 1
    fi
    if [ ! -d "''${OPENSSL_DIR}/lib/ossl-modules" ] && [ ! -d "''${OPENSSL_DIR}/lib64/ossl-modules" ]; then
      echo "Error: Missing ossl-modules directory with FIPS provider in ''${OPENSSL_DIR}." >&2
      exit 1
    fi

    # On macOS, if the OpenSSL static libs arch doesn't match, align Rust TARGET accordingly
    if [ "$(uname -s)" = "Darwin" ]; then
      if command -v lipo >/dev/null 2>&1; then
  lib_arch=$(lipo -info "''${OPENSSL_DIR}/lib/libcrypto.a" 2>/dev/null | sed -n 's/^Architectures in the fat file: .* are //p; s/^Non-fat file: .* is architecture: //p')
        case "$lib_arch" in
          *arm64*) lib_target="aarch64-apple-darwin" ;;
          *x86_64*) lib_target="x86_64-apple-darwin" ;;
          *) lib_target="" ;;
        esac
        if [ -n "$lib_target" ]; then
          if [ -z "''${TARGET:-}" ] || [ "''${TARGET}" != "$lib_target" ]; then
            echo "Info: Setting Rust TARGET to $lib_target to match OpenSSL arch ($lib_arch)." >&2
            export TARGET="$lib_target"
            if command -v rustup >/dev/null 2>&1; then
              rustup target add "$lib_target" >/dev/null 2>&1 || true
            fi
            export CMAKE_OSX_ARCHITECTURES="''${lib_arch%% *}"
          fi
        fi
      fi
    fi

    # Ensure the toolchain from rust-toolchain.toml is installed and components are present
    if command -v rustup >/dev/null 2>&1; then
      # This will install the pinned toolchain if missing
      rustup show >/dev/null 2>&1 || true
      rustup component add rustfmt clippy >/dev/null 2>&1 || true
    fi

    echo "Set DEBUG_OR_RELEASE=$DEBUG_OR_RELEASE (override when needed)"
    echo "Set FEATURES=$FEATURES (override when needed)"

    # Provide a default TARGET triple if none is set, using current rustc host
    if [ -z "''${TARGET:-}" ]; then
      host_triple=$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')
      if [ -n "$host_triple" ]; then
        export TARGET="$host_triple"
      fi
    fi
    export CARGO_BUILD_TARGET="$TARGET"
    echo "Using TARGET=$TARGET"
  '';
}

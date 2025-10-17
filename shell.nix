{ pkgs ? import <nixpkgs> {} }:

let
  # Always use the pinned OpenSSL 3.1.2 built from our derivation
  openssl312 = pkgs.callPackage ./nix/openssl-3_1_2-fips.nix {};
  opensslOut = builtins.toString openssl312;
in pkgs.mkShell {
  name = "cosmian-kms-dev-shell";

  # Tools available in the shell
  buildInputs = [
    pkgs.pkg-config
    pkgs.cmake
    pkgs.git
    pkgs.rustup
    pkgs.curl
    openssl312
  ];

  # Defaults that can be overridden when invoking
  DEBUG_OR_RELEASE = "debug";
  FEATURES = "non-fips";

  # Ensure crates link to our OpenSSL and not vendored/system
  OPENSSL_NO_VENDOR = "1";
  OPENSSL_STATIC = "1";
  PKG_CONFIG_ALL_STATIC = "1";
  OPENSSL_DIR = opensslOut;

  shellHook = ''
    echo "cosmian-kms nix-shell ready (OpenSSL 3.1.2 enforced)"

    # Prepend OpenSSL bin to PATH for deterministic `openssl` resolution
    if [ -d "''${OPENSSL_DIR}/bin" ]; then
      export PATH="''${OPENSSL_DIR}/bin:$PATH"
    fi

    # Ensure pkg-config can locate OpenSSL .pc files (first in search path)
    if [ -d "''${OPENSSL_DIR}/lib/pkgconfig" ]; then
      export PKG_CONFIG_PATH="''${OPENSSL_DIR}/lib/pkgconfig:''${PKG_CONFIG_PATH:-}"
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

    # Basic static artifacts check
    if [ ! -f "''${OPENSSL_DIR}/lib/libcrypto.a" ] || [ ! -f "''${OPENSSL_DIR}/lib/libssl.a" ]; then
      echo "Error: Missing static OpenSSL libs in ''${OPENSSL_DIR}/lib (libcrypto.a, libssl.a)." >&2
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

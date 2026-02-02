{
  pkgs ?
    let
      rustOverlay = import (
        builtins.fetchTarball {
          url = "https://github.com/oxalica/rust-overlay/archive/refs/heads/stable.tar.gz";
        }
      );
      pinned =
        import
          (builtins.fetchTarball {
            url = "https://github.com/NixOS/nixpkgs/archive/24.05.tar.gz";
            sha256 = "1lr1h35prqkd1mkmzriwlpvxcb34kmhc9dnr48gkm8hh089hifmx";
          })
          {
            overlays = [ rustOverlay ];
            config = if (builtins.getEnv "WITH_HSM") == "1" then { allowUnfree = true; } else { };
          };
    in
    pinned,
# Explicit variant argument to avoid relying on builtins.getEnv during evaluation
}:

let
  # Import project-level outputs to access tools like cargo-packager
  # Use custom OpenSSL 3.1.2 (FIPS-capable) for both FIPS and non-FIPS modes
  # The same OpenSSL library is used; FIPS vs non-FIPS is controlled at runtime
  # via OPENSSL_CONF and OPENSSL_MODULES environment variables
  # Wrapper config to activate both default and FIPS providers while reusing
  # the derivation's generated fipsmodule.cnf. This avoids generating configs
  # inside nix/openssl.nix and strictly reuses the derivation outputs.
  # SoftHSM override with OpenSSL-only backend (Botan disabled)
  # Note: softhsm 2.5.x in nixos-19.03 uses autotools (configure), not CMake
  # Prefer nixpkgs' OpenSSL for building SoftHSM (ensures compatibility); server uses openssl312
  # Allow selectively adding extra tools from the environment (kept via nix-shell --keep)
  withHsm = (builtins.getEnv "WITH_HSM") == "1";
  withPython = (builtins.getEnv "WITH_PYTHON") == "1";
  withCurl = (builtins.getEnv "WITH_CURL") == "1";
  # Import FIPS OpenSSL 3.1.2 - will be used for FIPS builds
  openssl312Fips = import ./nix/openssl.nix {
    inherit (pkgs)
      stdenv
      lib
      fetchurl
      perl
      coreutils
      ;
    static = true;
  };
  # Shared (dynamic) build for components that require .so (e.g., SoftHSM2)
  openssl312FipsShared = import ./nix/openssl.nix {
    inherit (pkgs)
      stdenv
      lib
      fetchurl
      perl
      coreutils
      ;
    static = false;
  };
  utimacoDrv = import ./nix/utimaco.nix {
    inherit pkgs;
    inherit (pkgs) lib;
  };
  # Preload shim to force FIPS provider load + properties for OpenSSL at runtime
  opensslFipsBootstrap = import ./nix/openssl-fips-bootstrap.nix { inherit pkgs; };
  # Ensure softhsm2 uses the same pinned nixpkgs instance to avoid glibc mismatches
  softhsmDrv = import ./nix/softhsm2.nix {
    inherit pkgs;
    # Use FIPS shared OpenSSL when running in FIPS variant so SoftHSM2 links to it
    openssl = if (builtins.getEnv "VARIANT") == "fips" then openssl312FipsShared else pkgs.openssl;
  };
in
pkgs.mkShell {
  buildInputs = [
    # Provide both OpenSSL packages - the shellHook will configure which one to use
    openssl312Fips
    openssl312FipsShared
    pkgs.openssl
    pkgs.pkg-config
    pkgs.gcc
    pkgs.rust-bin.stable.latest.default
    opensslFipsBootstrap
  ]
  ++ (if withCurl then [ pkgs.curl ] else [ ])
  ++ (
    if withHsm then
      [
        softhsmDrv
        pkgs.wget
      ]
      # Utimaco HSM simulator is only available on x86_64-linux
      ++ pkgs.lib.optionals (pkgs.stdenv.system == "x86_64-linux") [ utimacoDrv ]
      # psmisc is only available on Linux; macOS has killall built-in
      ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.psmisc ]
    else
      [ ]
  )
  ++ (
    if withPython then
      [
        pkgs.python3
        pkgs.python3Packages.virtualenv
      ]
    else
      [ ]
  );

  shellHook = ''
    set -eo pipefail

    # Unset any OpenSSL variables that might be set by Nix before we configure them
    unset OPENSSL_DIR OPENSSL_LIB_DIR OPENSSL_INCLUDE_DIR OPENSSL_CONF OPENSSL_MODULES || true

    # Configure OpenSSL based on requested variant
    export OPENSSL_NO_VENDOR=1

    # Check which variant is requested (defaults to non-fips if not set)
    # VARIANT should be set by nix.sh via the command string
    VARIANT_MODE="''${VARIANT:-non-fips}"

    if [ "$VARIANT_MODE" = "fips" ]; then
      # Use Nix-provided FIPS OpenSSL 3.1.2 (shared) for dynamic linking in Rust
      OPENSSL_PKG_PATH="${openssl312FipsShared}"

      # Prefer our OpenSSL via pkg-config
      export PKG_CONFIG_PATH="$OPENSSL_PKG_PATH/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

      # Force dynamic linking for openssl-sys
      export OPENSSL_STATIC=0

      # Set OPENSSL_DIR for openssl-sys during compilation
      export OPENSSL_DIR="$OPENSSL_PKG_PATH"
      export OPENSSL_LIB_DIR="$OPENSSL_PKG_PATH/lib"
      export OPENSSL_INCLUDE_DIR="$OPENSSL_PKG_PATH/include"

      # Set runtime FIPS configuration pointing to dev/test locations
      export OPENSSL_CONF="$OPENSSL_PKG_PATH/ssl/openssl.cnf"
      export OPENSSL_MODULES="$OPENSSL_PKG_PATH/lib/ossl-modules"

      echo "Using FIPS OpenSSL 3.1.2 from Nix: $OPENSSL_PKG_PATH"
      echo "  OPENSSL_CONF=$OPENSSL_CONF"
      echo "  OPENSSL_MODULES=$OPENSSL_MODULES"

      # Verify FIPS OpenSSL shared library presence
      if [ -f "$OPENSSL_PKG_PATH/lib/libcrypto.so.3" ]; then
        echo "FIPS OpenSSL libcrypto.so.3 found (shared)"
      else
        echo "WARNING: FIPS OpenSSL libcrypto.so.3 NOT found at $OPENSSL_PKG_PATH/lib"
      fi

      # Verify FIPS module
      if [ -f "$OPENSSL_MODULES/fips.so" ]; then
        echo "FIPS provider module found: $OPENSSL_MODULES/fips.so"
      else
        echo "WARNING: FIPS provider module NOT found"
      fi

      # Runtime library path for FIPS (shared)
      if [ "''${WITH_HSM:-}" = "1" ]; then
        export LD_LIBRARY_PATH="$OPENSSL_PKG_PATH/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        unset NIX_LD_LIBRARY_PATH NIX_CFLAGS_COMPILE NIX_LDFLAGS || true
      else
        export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib}/lib:${pkgs.gcc.cc.lib}/lib:$OPENSSL_PKG_PATH/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
      fi

      # Preload bootstrap so even statically linked libcrypto gets providers + properties
      if [ -f "${opensslFipsBootstrap}/lib/libopenssl_fips_bootstrap.so" ]; then
        export LD_PRELOAD="${opensslFipsBootstrap}/lib/libopenssl_fips_bootstrap.so''${LD_PRELOAD:+:$LD_PRELOAD}"
        echo "LD_PRELOAD set to bootstrap OpenSSL FIPS providers"
      fi
    else
      # Use standard nixpkgs OpenSSL for non-FIPS
      # Note: pkgs.openssl.dev has headers, pkgs.openssl.out has libraries
      OPENSSL_PKG_PATH="${pkgs.openssl.out}"

      export OPENSSL_DIR="$OPENSSL_PKG_PATH"
      export OPENSSL_LIB_DIR="$OPENSSL_PKG_PATH/lib"
      export OPENSSL_INCLUDE_DIR="${pkgs.openssl.dev}/include"

      # Use the standard OpenSSL config from nixpkgs
      export OPENSSL_CONF="$OPENSSL_PKG_PATH/etc/ssl/openssl.cnf"

      echo "Using standard OpenSSL (non-FIPS): $OPENSSL_PKG_PATH"
      echo "  OPENSSL_CONF=$OPENSSL_CONF"

      # Verify non-FIPS OpenSSL library presence
      if [ -f "$OPENSSL_PKG_PATH/lib/libcrypto.so.3" ]; then
        echo "OpenSSL libcrypto.so.3 found"
      else
        echo "WARNING: OpenSSL libcrypto.so.3 NOT found at $OPENSSL_PKG_PATH/lib"
      fi

      # Runtime library path for non-FIPS
      if [ "''${WITH_HSM:-}" = "1" ]; then
        export LD_LIBRARY_PATH="$OPENSSL_PKG_PATH/lib"
        unset NIX_LD_LIBRARY_PATH NIX_CFLAGS_COMPILE NIX_LDFLAGS || true
      else
        export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib}/lib:${pkgs.gcc.cc.lib}/lib:$OPENSSL_PKG_PATH/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
      fi
    fi

    # Skip local OpenSSL build since Nix provides it
    export SERVER_SKIP_OPENSSL_BUILD=1
    export RUST_TEST_THREADS=1

    # Ensure TLS works for reqwest/native-tls inside Nix by pointing to the CA bundle
    export SSL_CERT_FILE="${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"

    if [ "''${WITH_HSM:-}" = "1" ]; then
      # Enable core dumps for post-mortem analysis of HSM-related crashes
      ulimit -c unlimited || true
      # SOFTHSM2_PKCS11_LIB can be set externally if needed; no dlclose shims applied
    fi
  '';
}

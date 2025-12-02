{
  pkgs ? import (builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/24.05.tar.gz";
    sha256 = "1lr1h35prqkd1mkmzriwlpvxcb34kmhc9dnr48gkm8hh089hifmx";
  }) { },
}:

let
  inherit (pkgs.stdenv) isLinux;
  # Import project-level outputs to access tools like cargo-packager
  project = import ./default.nix { inherit pkgs; };
  hostGlibc =
    if isLinux then
      (pkgs.stdenv.cc.libc.version or (pkgs.lib.getVersion pkgs.stdenv.cc.libc))
    else
      "n/a";
  nixpkgs1903 = builtins.getEnv "NIXPKGS_GLIBC_228_URL";
  pkgs228 =
    if isLinux && !(pkgs.lib.versionOlder hostGlibc "2.29") then
      import (builtins.fetchTarball {
        url =
          if nixpkgs1903 != "" then
            nixpkgs1903
          else
            "https://github.com/NixOS/nixpkgs/archive/refs/heads/nixos-19.03.tar.gz";
      }) { }
    else
      pkgs;
  # Use custom OpenSSL 3.1.2 (FIPS-capable) for both FIPS and non-FIPS modes
  # The same OpenSSL library is used; FIPS vs non-FIPS is controlled at runtime
  # via OPENSSL_CONF and OPENSSL_MODULES environment variables
  openssl312 = pkgs228.callPackage ./nix/openssl.nix { };
  # SoftHSM override with OpenSSL-only backend (Botan disabled)
  # Note: softhsm 2.5.x in nixos-19.03 uses autotools (configure), not CMake
  # Prefer nixpkgs' OpenSSL for building SoftHSM (ensures compatibility); server uses openssl312
  opensslForSofthsm = pkgs228.openssl;
  softhsm_pkg = pkgs228.softhsm.overrideAttrs (
    old:
    let
      lib = pkgs.lib or pkgs228.lib;
      # Drop crypto-backend and backend-specific flags to avoid duplicates
      filteredFlags = lib.filter (
        f:
        !(lib.hasPrefix "--with-crypto-backend=" f)
        && !(lib.hasPrefix "--with-botan" f)
        && !(lib.hasPrefix "--with-openssl" f)
      ) (old.configureFlags or [ ]);
      # Force OpenSSL backend only (no Botan)
      extraFlags = [
        "--with-crypto-backend=openssl"
        "--with-openssl=${opensslForSofthsm}"
      ];
      extraInputs = [ opensslForSofthsm ];
    in
    {
      configureFlags = filteredFlags ++ extraFlags;
      buildInputs = (old.buildInputs or [ ]) ++ extraInputs;
    }
  );
  # Allow selectively adding extra tools from the environment (kept via nix-shell --keep)
  withWget = (builtins.getEnv "WITH_WGET") == "1";
  withHsm = (builtins.getEnv "WITH_HSM") == "1";
  withPython = (builtins.getEnv "WITH_PYTHON") == "1";
  extraTools = if withWget then [ pkgs228.wget ] else [ ];
in
pkgs228.mkShell {
  name = "cosmian-kms-dev-shell";
  buildInputs = [
    pkgs228.pkg-config
    pkgs228.cmake
    pkgs228.git
    pkgs228.rustup
    # Provide cargo-packager in the shell so packaging scripts can call `cargo packager`
    project.cargoPackagerTool
  ]
  ++ (
    if isLinux then
      [
        pkgs228.gcc
        pkgs228.binutils
      ]
    else
      [ ]
  )
  ++ (
    if pkgs228.stdenv.isDarwin then
      [ pkgs228.libiconv ]
      ++ (with pkgs228.darwin.apple_sdk.frameworks; [
        SystemConfiguration
        Security
        CoreFoundation
      ])
    else
      [ ]
  )
  ++ [ openssl312 ]
  ++ extraTools
  ++ (
    if withHsm then
      [
        pkgs228.psmisc
        # Use a SoftHSM build with OpenSSL backend (Botan disabled)
        softhsm_pkg
      ]
    else
      [ ]
  )
  ++ (
    if withPython then
      # Python 3.11 fallback logic: older pinned nixpkgs (e.g. 19.03) does not provide python311.
      # Use host 'pkgs' Python when python311 is absent from pkgs228.
      let
        pyBase = pkgs228.python311 or pkgs.python311;
        pyVenv =
          if (pkgs228 ? python311Packages) && (pkgs228.python311Packages ? virtualenv) then
            pkgs228.python311Packages.virtualenv
          else
            pkgs.python311Packages.virtualenv;
      in
      [
        pyBase
        pyVenv
      ]
    else
      [ ]
  );
  shellHook = ''
    export NIX_OPENSSL_OUT="${openssl312}"
    ${
      if isLinux then
        ''
          export NIX_CC_BIN="${pkgs228.stdenv.cc}/bin"
          export NIX_BINUTILS_BIN="${pkgs228.binutils}/bin"
          export NIX_BINUTILS_UNWRAPPED_BIN="${(pkgs228.binutils-unwrapped or pkgs228.binutils)}/bin"
          export NIX_GLIBC_LIB="${pkgs228.glibc}/lib"
          export NIX_DYN_LINKER="${pkgs228.glibc}/lib/ld-linux-x86-64.so.2"
        ''
      else
        ""
    }
    # --- Begin inlined nix/shell-hook.sh ---
    set -euo pipefail

    export OPENSSL_NO_VENDOR=1
    export OPENSSL_STATIC=1
    export PKG_CONFIG_ALL_STATIC=1
    [ -d ${"\${NIX_OPENSSL_OUT:-}"}/bin ] && export PATH=${"\${NIX_OPENSSL_OUT}"}/bin:$PATH
    if [ -n ${"\${NIX_OPENSSL_OUT:-}"} ]; then
      export OPENSSL_DIR=${"\${NIX_OPENSSL_OUT}"}
      export OPENSSL_LIB_DIR=${"\${NIX_OPENSSL_OUT}"}/lib
      export OPENSSL_INCLUDE_DIR=${"\${NIX_OPENSSL_OUT}"}/include

      # Add OpenSSL lib directory to LD_LIBRARY_PATH so dynamically linked binaries can find it
      export LD_LIBRARY_PATH=${"\${NIX_OPENSSL_OUT}"}/lib:${"\${LD_LIBRARY_PATH:-}"}


      # Force openssl-sys to use our specific OpenSSL and detect version correctly
      # Disable pkg-config to prevent it from finding wrong OpenSSL versions
      export OPENSSL_NO_PKG_CONFIG=1
      if [ -d ${"\${NIX_OPENSSL_OUT}"}/lib/pkgconfig ]; then
        export PKG_CONFIG_PATH=${"\${NIX_OPENSSL_OUT}"}/lib/pkgconfig:${"\${PKG_CONFIG_PATH:-}"}
      fi
      if [ -d ${"\${NIX_OPENSSL_OUT}"}/lib64/pkgconfig ]; then
        export PKG_CONFIG_PATH=${"\${NIX_OPENSSL_OUT}"}/lib64/pkgconfig:${"\${PKG_CONFIG_PATH:-}"}
      fi
    fi

    if [ "$(uname -s)" = "Linux" ]; then
      [ -n ${"\${NIX_CC_BIN:-}"} ] && PATH=${"\${NIX_CC_BIN}"}:$PATH
      [ -n ${"\${NIX_BINUTILS_BIN:-}"} ] && PATH=${"\${NIX_BINUTILS_BIN}"}:$PATH
      AR_BIN=${"\${NIX_BINUTILS_UNWRAPPED_BIN:-\${NIX_BINUTILS_BIN:-}}"}
      export CC=${"\${NIX_CC_BIN:-}"}/cc
      export AR="$AR_BIN/ar"
      if [ ! -x "$AR" ] && command -v ar >/dev/null 2>&1; then AR="$(command -v ar)"; fi
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$CC"
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_AR="$AR"
      export CC_x86_64_unknown_linux_gnu="$CC"
      export AR_x86_64_unknown_linux_gnu="$AR"
    fi
    # --- End inlined nix/shell-hook.sh ---
  '';
}

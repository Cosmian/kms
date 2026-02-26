# Shared helpers for cli.nix and kms-server.nix.
# Returns an attrset of common derivations, helpers, and values.
{
  pkgs,
  pkgs234 ? pkgs, # nixpkgs 22.05 with glibc 2.34 (Rocky Linux 9 compatibility)
  lib ? pkgs.lib,
  openssl36 ? null,
  openssl312 ? null,
  static ? true,
  features ? [ ],
}:

let
  isFips = (builtins.length features) == 0 || !(builtins.elem "non-fips" features);
  baseVariant = if isFips then "fips" else "non-fips";
  # Use nixpkgs with glibc 2.34 on Linux to keep Rocky Linux 9 compatibility
  opensslPkgs = if pkgs.stdenv.isLinux then pkgs234 else pkgs;

  openssl36_ =
    if openssl36 != null then
      openssl36
    else
      opensslPkgs.callPackage ./openssl.nix {
        inherit static;
        version = "3.6.0";
        enableLegacy = true;
        srcUrl = "https://package.cosmian.com/openssl/openssl-3.6.0.tar.gz";
        sha256SRI = "sha256-tqX0S362nj+jXb8VUkQFtEg3pIHUPYHa3d4/8h/LuOk=";
        expectedHash = "b6a5f44b7eb69e3fa35dbf15524405b44837a481d43d81daddde3ff21fcbb8e9";
      };

  openssl312_ =
    if openssl312 != null then
      openssl312
    else
      opensslPkgs.callPackage ./openssl.nix {
        inherit static;
        version = "3.1.2";
      };

  # Always link against OpenSSL 3.6.0; the FIPS provider (3.1.2) is loaded at runtime.
  opensslLink = openssl36_;

  srcRoot = ../.;

  # Build a filtered source tree.
  # extraPaths: additional top-level workspace paths to include beyond the common set.
  mkFilteredSrc =
    extraPaths:
    lib.cleanSourceWith {
      src = srcRoot;
      filter =
        path: type:
        let
          rel = lib.removePrefix (toString srcRoot + "/") (toString path);
          isEphemeral =
            lib.hasInfix "/target/" rel
            || lib.hasSuffix "/target" rel
            || lib.hasPrefix "crate/server/ui/dist" rel
            || lib.hasPrefix "crate/server/ui_non_fips/dist" rel;
          basePaths =
            rel == "Cargo.toml"
            || rel == "Cargo.lock"
            || rel == "LICENSE"
            || rel == "README.md"
            || rel == "CHANGELOG.md"
            || rel == "crate"
            || lib.hasPrefix "crate/" rel
            || rel == "resources"
            || lib.hasPrefix "resources/" rel
            || rel == "pkg"
            || lib.hasPrefix "pkg/" rel;
          extra = builtins.any (p: rel == p || lib.hasPrefix "${p}/" rel) extraPaths;
        in
        lib.cleanSourceFilter path type && (!isEphemeral) && (basePaths || extra);
    };

  buildInputs = [
    opensslLink
  ]
  ++ lib.optionals pkgs.stdenv.isDarwin (
    let
      fw = pkgs.darwin.apple_sdk.frameworks;
    in
    [
      fw.SystemConfiguration
      fw.Security
      fw.CoreFoundation
      pkgs.libiconv
    ]
  );

  # Environment variables for openssl-sys to pick our OpenSSL
  opensslEnv = {
    OPENSSL_DIR = opensslLink;
    OPENSSL_LIB_DIR = "${opensslLink}/lib";
    OPENSSL_INCLUDE_DIR = "${opensslLink}/include";
    OPENSSL_NO_VENDOR = 1;
  };

  # Shell snippet that re-links ELF binaries with the host system dynamic linker.
  # innerCmds: shell commands to run after the NIX_* guards are set up; $DL holds the linker path.
  mkRelinkSnippet = innerCmds: ''
    if [ "$(uname)" = "Linux" ]; then
      DL=""
      ARCH="$(uname -m)"
      if [ "$ARCH" = "x86_64" ]; then DL="/lib64/ld-linux-x86-64.so.2"; fi
      if [ "$ARCH" = "aarch64" ]; then DL="/lib/ld-linux-aarch64.so.1"; fi
      if [ -n "$DL" ]; then
        export NIX_ENFORCE_PURITY=0
        export NIX_DONT_SET_RPATH=1
        export NIX_LDFLAGS=""
        export NIX_CFLAGS_LINK=""
        ${innerCmds}
      fi
    fi
  '';

  # --features flag for cargo invocations (empty string when features list is empty)
  featuresFlag = lib.optionalString (
    features != [ ]
  ) "--features ${lib.concatStringsSep "," features}";

in
{
  inherit
    isFips
    baseVariant
    opensslPkgs
    openssl36_
    openssl312_
    opensslLink
    mkFilteredSrc
    buildInputs
    opensslEnv
    mkRelinkSnippet
    featuresFlag
    ;
}

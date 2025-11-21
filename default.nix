{
  # Pin nixpkgs so nix-build works without '-I nixpkgs=…' or channels
  pkgs ? let
    nixpkgsSrc = builtins.fetchTarball {
      url = "https://github.com/NixOS/nixpkgs/archive/24.05.tar.gz";
    };
  in import nixpkgsSrc { config.allowUnfree = true; },
  # Allow callers (e.g., Docker) to toggle deterministic hash enforcement
  # via: nix-build default.nix --arg enforceDeterministicHash false -A kms-server-fips
  enforceDeterministicHash ? true,
}:

let
  # Reuse the same pinned nixpkgs for internal imports/overlays
  nixpkgsSrc = builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/24.05.tar.gz";
  };
  # Bring a modern Rust toolchain (1.90.0) via oxalica/rust-overlay for Cargo edition2024 support
  rustOverlay = import (
    builtins.fetchTarball {
      url = "https://github.com/oxalica/rust-overlay/archive/refs/heads/master.tar.gz";
    }
  );
  pkgsWithRust = import nixpkgsSrc {
    overlays = [ rustOverlay ];
    config.allowUnfree = true;
  };
  # Use minimal Rust profile (no docs) and add only needed components to save disk space
  rustToolchain = pkgsWithRust.rust-bin.stable."1.90.0".minimal.override {
    extensions = [
      "rustfmt"
      "clippy"
    ];
  };

  # For Linux, we need glibc <= 2.28. Import older nixpkgs to get its stdenv.
  pkgs228 =
    if pkgs.stdenv.isLinux then
      (
        let
          nixpkgs1903 = builtins.getEnv "NIXPKGS_GLIBC_228_URL";
        in
        import (builtins.fetchTarball {
          url =
            if nixpkgs1903 != "" then
              nixpkgs1903
            else
              "https://github.com/NixOS/nixpkgs/archive/refs/heads/nixos-19.03.tar.gz";
        }) { config.allowUnfree = true; }
      )
    else
      pkgs;

  # Create rustPlatform: on Linux use pkgs228.makeRustPlatform (glibc 2.27),
  # but with modern Rust toolchain
  rustPlatform190 =
    if pkgs.stdenv.isLinux then
      pkgs228.makeRustPlatform {
        cargo = rustToolchain;
        rustc = rustToolchain;
      }
    else
      pkgsWithRust.makeRustPlatform {
        cargo = rustToolchain;
        rustc = rustToolchain;
      };

  # Build OpenSSL with old nixpkgs stdenv (glibc 2.27)
  openssl312 = pkgs228.callPackage ./nix/openssl-3_1_2.nix { };

  # Tool: cargo-generate-rpm (not available in some nixpkgs pins). Build it from crates.io.
  # Build cargo-generate-rpm with the same modern Rust toolchain (Cargo 1.90)
  # to support lockfile v4 and avoid -Znext-lockfile-bump issues
  cargoGenerateRpmTool = rustPlatform190.buildRustPackage rec {
    pname = "cargo-generate-rpm";
    version = "0.16.0";
    src = pkgs.fetchCrate {
      inherit pname version;
      # Pinned crate tarball hash from crates.io fetch
      sha256 = "sha256-esp3MJ24RQpMFn9zPgccp7NESoFAUPU7y+YRsJBVVr4=";
    };
    # Pinned cargo vendor hash for reproducible builds
    cargoSha256 = "sha256-vXb6O9xoYRVAbFGlhbPE6xYYqjSWT/fvoXYl4dkMxEg=";
    nativeBuildInputs = [
      rustToolchain
      pkgs.pkg-config
      pkgs.git
      pkgs.cacert
    ];
    doCheck = false; # skip upstream tests; they assume specific host paths like /usr/bin/ldd
  };

  # Tool: cargo-packager (may be missing in pinned nixpkgs). Build it from crates.io
  # so DMG packaging keeps using cargo-packager as required.
  cargoPackagerTool = rustPlatform190.buildRustPackage rec {
    pname = "cargo-packager";
    # Align with version used in CI scripts to reduce surprises
    version = "0.11.7"; # Update if needed; hash will enforce correctness
    src = pkgs.fetchCrate {
      inherit pname version;
      # Initial placeholder; Nix will suggest the correct one on first build if mismatched
      sha256 = "sha256-dSF2BzT+wun75qRBvDJpoOwNG4dHUeVnTx/Ygm5wtK0=";
    };
    # Pinned cargo vendor hash differs by platform (target-specific deps)
    # Observed on current macOS build: got sha256-uhXPFBZ6sWQch+liz7F67PC6ns+P63eMJ6bYWr07L8U=
    # Swap mapping accordingly to keep both platforms green.
    # - macOS (Darwin): sha256-uhXPFBZ6sWQch+liz7F67PC6ns+P63eMJ6bYWr07L8U=
    # - Linux:          sha256-bV3OMNY/UM+1Cz/bmpKRMMCV863e7qMKDQ3Dh+bofo8=
    cargoSha256 =
      if pkgs.stdenv.isDarwin then
        "sha256-uhXPFBZ6sWQch+liz7F67PC6ns+P63eMJ6bYWr07L8U="
      else
        "sha256-bV3OMNY/UM+1Cz/bmpKRMMCV863e7qMKDQ3Dh+bofo8=";
    nativeBuildInputs = [
      rustToolchain
      pkgs.pkg-config
      pkgs.git
      pkgs.cacert
    ];
    doCheck = false;
  };

  # Common patch phase to substitute OpenSSL asset placeholders (XXX/YYY)
  # in crate/server/Cargo.toml. Parameterized by a label for logging.
  patchOpenSSLPhase = variant: ''
    runHook prePatch
    OSSL="${openssl312}"
    OSSL_NO_SLASH="${openssl312}"
    OSSL_NO_SLASH="''${OSSL_NO_SLASH#/}"

    echo "Substituting OpenSSL paths in crate/server/Cargo.toml (${variant})"
    substituteInPlace crate/server/Cargo.toml \
      --replace 'XXX' "''${OSSL}" \
      --replace 'YYY' "''${OSSL_NO_SLASH}"
    runHook postPatch
  '';

  # Build UI for both variants (use modern pkgs for UI build tools)
  ui-fips = pkgs.callPackage ./nix/build-ui.nix {
    features = [ ];
  };

  ui-non-fips = pkgs.callPackage ./nix/build-ui.nix {
    features = [ "non-fips" ];
  };

  # DRY helpers to build servers and packages for both variants
  mkKmsServer =
    { features, ui, enforceDeterministicHash ? true }:
    pkgs.callPackage ./nix/kms-server.nix {
      inherit openssl312 pkgs228;
      rustPlatform = rustPlatform190;
      inherit features ui enforceDeterministicHash;
    };

  # Build KMS server in both variants
  # Use shell environment build for glibc 2.27 compatibility
  kms-server-fips = mkKmsServer {
    features = [ ];
    ui = ui-fips;
    # Propagate top-level toggle (defaults to true)
    enforceDeterministicHash = enforceDeterministicHash;
  };

  kms-server-non-fips = mkKmsServer {
    features = [ "non-fips" ];
    ui = ui-non-fips;
    # Disable hash enforcement for non-FIPS builds due to non-determinism in additional dependencies
    enforceDeterministicHash = false;
  };

in
rec {
  # Binary packages (can be installed with nix-env)
  inherit
    kms-server-fips
    kms-server-non-fips
    ;

  # Export OpenSSL 3.1.2 FIPS derivation for tooling (packaging script)
  inherit openssl312;

  # Export cargo-packager and cargo-generate-rpm tools for scripts and dev shell
  inherit cargoPackagerTool cargoGenerateRpmTool;

  # Export the pinned Rust toolchain (1.90.0) so scripts can use a modern Cargo (edition2024)
  inherit rustToolchain;

  # Default to FIPS variant
  kms-server = kms-server-fips;

}

{
  # Pin nixpkgs so nix-build works without '-I nixpkgs=…' or channels
  pkgs ?
    let
      nixpkgsSrc = builtins.fetchTarball {
        url = "https://github.com/NixOS/nixpkgs/archive/24.05.tar.gz";
      };
    in
    import nixpkgsSrc { config.allowUnfree = true; },
  # Allow callers (e.g., Docker) to toggle deterministic hash enforcement.
  # Default is relaxed (false) so builds don't fail when hashes drift; CI/scripts
  # can enable it explicitly when needed.
  enforceDeterministicHash ? false,
}:

let
  # Extract version from workspace Cargo.toml
  # Read the file and parse it to find version = "x.y.z"
  cargoTomlContent = builtins.readFile ./Cargo.toml;
  # Split into lines and find the version line in [workspace.package] section
  lines = pkgs.lib.splitString "\n" cargoTomlContent;
  # Find workspace.package section, then extract version
  extractVersion =
    lines:
    let
      # Find index of [workspace.package]
      findWorkspacePackage =
        idx:
        if idx >= builtins.length lines then
          null
        else if pkgs.lib.hasPrefix "[workspace.package]" (builtins.elemAt lines idx) then
          idx
        else
          findWorkspacePackage (idx + 1);

      workspaceIdx = findWorkspacePackage 0;

      # Starting from workspace.package section, find version line
      findVersion =
        idx:
        if idx >= builtins.length lines || workspaceIdx == null then
          null
        else
          let
            line = builtins.elemAt lines idx;
            # Stop at next section
            isNextSection = pkgs.lib.hasPrefix "[" line && idx > workspaceIdx;
          in
          if isNextSection then
            null
          else if pkgs.lib.hasPrefix "version" (pkgs.lib.replaceStrings [ " " "\t" ] [ "" "" ] line) then
            # Extract "x.y.z" from version = "x.y.z"
            let
              # Remove everything before the first quote
              afterFirstQuote = builtins.elemAt (pkgs.lib.splitString "\"" line) 1;
            in
            afterFirstQuote
          else
            findVersion (idx + 1);
    in
    if workspaceIdx == null then
      throw "Could not find [workspace.package] in Cargo.toml"
    else
      let
        ver = findVersion (workspaceIdx + 1);
      in
      if ver == null then throw "Could not find version in [workspace.package] section" else ver;

  kmsVersion = extractVersion lines;

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
    targets = [ "wasm32-unknown-unknown" ];
  };

  # For Linux, we need glibc <= 2.28. Import older nixpkgs to get its stdenv (2.28).
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
              # Pin to a stable tag tarball (glibc 2.28 lives in 19.03)
              "https://github.com/NixOS/nixpkgs/archive/nixos-19.03.tar.gz";
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

  # Build OpenSSL 3.1.2 with old nixpkgs stdenv (glibc 2.27)
  # Create both static and dynamic versions
  openssl312-static = pkgs228.callPackage ./nix/openssl.nix { static = true; };
  openssl312-dynamic = pkgs228.callPackage ./nix/openssl.nix { static = false; };
  # Default to static for backward compatibility
  openssl312 = openssl312-static;

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

  # Build UI for both variants (use modern pkgs for UI build tools)
  ui-fips = pkgs.callPackage ./nix/ui.nix {
    features = [ ];
    version = kmsVersion;
    inherit rustToolchain enforceDeterministicHash;
  };

  ui-non-fips = pkgs.callPackage ./nix/ui.nix {
    features = [ "non-fips" ];
    version = kmsVersion;
    inherit rustToolchain enforceDeterministicHash;
  };

  # DRY helper to build servers for both variants and both linkage modes
  mkKmsServer =
    {
      features,
      ui,
      static ? true,
      enforceDeterministicHash ? true,
    }:
    pkgs.callPackage ./nix/kms-server.nix {
      openssl312 = if static then openssl312-static else openssl312-dynamic;
      inherit pkgs228;
      rustPlatform = rustPlatform190;
      version = kmsVersion;
      inherit
        features
        ui
        static
        enforceDeterministicHash
        ;
    };

  # Build KMS server in both variants with static OpenSSL
  kms-server-fips-static-openssl = mkKmsServer {
    features = [ ];
    ui = ui-fips;
    static = true;
    inherit enforceDeterministicHash;
  };

  kms-server-non-fips-static-openssl = mkKmsServer {
    features = [ "non-fips" ];
    ui = ui-non-fips;
    static = true;
    enforceDeterministicHash = false;
  };

  # Build KMS server with dynamic OpenSSL linking
  kms-server-fips-dynamic-openssl = mkKmsServer {
    features = [ ];
    ui = ui-fips;
    static = false;
    enforceDeterministicHash = false;
  };

  kms-server-non-fips-dynamic-openssl = mkKmsServer {
    features = [ "non-fips" ];
    ui = ui-non-fips;
    static = false;
    enforceDeterministicHash = false;
  };

  # Docker images using dockerTools (minimal images)
  docker-image-fips = pkgs.callPackage ./nix/docker.nix {
    kmsServer = kms-server-fips-static-openssl;
    variant = "fips";
    version = kmsVersion;
  };

  docker-image-non-fips = pkgs.callPackage ./nix/docker.nix {
    kmsServer = kms-server-non-fips-static-openssl;
    variant = "non-fips";
    version = kmsVersion;
  };

in
rec {
  # Binary packages (can be installed with nix-env)
  inherit
    kms-server-fips-static-openssl
    kms-server-non-fips-static-openssl
    kms-server-fips-dynamic-openssl
    kms-server-non-fips-dynamic-openssl
    ;

  # Export UI builds for debugging/development
  inherit ui-fips ui-non-fips;

  # Docker images
  inherit
    docker-image-fips
    docker-image-non-fips
    ;

  # Export OpenSSL 3.1.2 FIPS derivations for tooling (packaging script)
  inherit openssl312 openssl312-static openssl312-dynamic;

  # Export cargo-packager and cargo-generate-rpm tools for scripts and dev shell
  inherit cargoPackagerTool cargoGenerateRpmTool;

  # Export the pinned Rust toolchain (1.90.0) so scripts can use a modern Cargo (edition2024)
  inherit rustToolchain;

  # Default to FIPS variant
  kms-server = kms-server-fips-static-openssl;
  docker-image = docker-image-fips;

  # Expected-hash files (generated by Nix, copyable into nix/expected-hashes)
  # Each attribute produces one file named per convention under $out/.
  expected-hash-server-fips-static =
    let
      sys = pkgs.stdenv.hostPlatform.system;
      parts = pkgs.lib.splitString "-" sys;
      arch = builtins.elemAt parts 0;
      os = builtins.elemAt parts 1;
      name = "cosmian-kms-server.fips.static-openssl.${arch}.${os}.sha256";
    in
    pkgs.runCommand "expected-hash-server-fips-static"
      {
        buildInputs = [
          pkgs.openssl
          pkgs.coreutils
        ];
      }
      ''
        set -euo pipefail
        mkdir -p "$out"
        bin='${kms-server-fips-static-openssl}/bin/cosmian_kms'
        [ -x "$bin" ] || { echo "Missing binary: $bin" >&2; exit 1; }
        hash="$(${pkgs.openssl}/bin/openssl dgst -sha256 -r "$bin" | awk '{print $1}')"
        printf '%s\n' "$hash" >"$out/${name}"
      '';

  expected-hash-server-fips-dynamic =
    let
      sys = pkgs.stdenv.hostPlatform.system;
      parts = pkgs.lib.splitString "-" sys;
      arch = builtins.elemAt parts 0;
      os = builtins.elemAt parts 1;
      name = "cosmian-kms-server.fips.dynamic-openssl.${arch}.${os}.sha256";
    in
    pkgs.runCommand "expected-hash-server-fips-dynamic"
      {
        buildInputs = [
          pkgs.openssl
          pkgs.coreutils
        ];
      }
      ''
        set -euo pipefail
        mkdir -p "$out"
        bin='${kms-server-fips-dynamic-openssl}/bin/cosmian_kms'
        [ -x "$bin" ] || { echo "Missing binary: $bin" >&2; exit 1; }
        hash="$(${pkgs.openssl}/bin/openssl dgst -sha256 -r "$bin" | awk '{print $1}')"
        printf '%s\n' "$hash" >"$out/${name}"
      '';

  expected-hash-server-non-fips-static =
    let
      sys = pkgs.stdenv.hostPlatform.system;
      parts = pkgs.lib.splitString "-" sys;
      arch = builtins.elemAt parts 0;
      os = builtins.elemAt parts 1;
      name = "cosmian-kms-server.non-fips.static-openssl.${arch}.${os}.sha256";
    in
    pkgs.runCommand "expected-hash-server-non-fips-static"
      {
        buildInputs = [
          pkgs.openssl
          pkgs.coreutils
        ];
      }
      ''
        set -euo pipefail
        mkdir -p "$out"
        bin='${kms-server-non-fips-static-openssl}/bin/cosmian_kms'
        [ -x "$bin" ] || { echo "Missing binary: $bin" >&2; exit 1; }
        hash="$(${pkgs.openssl}/bin/openssl dgst -sha256 -r "$bin" | awk '{print $1}')"
        printf '%s\n' "$hash" >"$out/${name}"
      '';

  expected-hash-server-non-fips-dynamic =
    let
      sys = pkgs.stdenv.hostPlatform.system;
      parts = pkgs.lib.splitString "-" sys;
      arch = builtins.elemAt parts 0;
      os = builtins.elemAt parts 1;
      name = "cosmian-kms-server.non-fips.dynamic-openssl.${arch}.${os}.sha256";
    in
    pkgs.runCommand "expected-hash-server-non-fips-dynamic"
      {
        buildInputs = [
          pkgs.openssl
          pkgs.coreutils
        ];
      }
      ''
        set -euo pipefail
        mkdir -p "$out"
        bin='${kms-server-non-fips-dynamic-openssl}/bin/cosmian_kms'
        [ -x "$bin" ] || { echo "Missing binary: $bin" >&2; exit 1; }
        hash="$(${pkgs.openssl}/bin/openssl dgst -sha256 -r "$bin" | awk '{print $1}')"
        printf '%s\n' "$hash" >"$out/${name}"
      '';

}

{
  # Pin nixpkgs so nix-build works without '-I nixpkgs=…' or channels
  # Pin nixpkgs for a stable toolchain; Linux builds target glibc 2.34 compatibility.
  pkgs ?
    let
      nixpkgsSrc = builtins.fetchTarball {
        # Use an immutable commit tarball so builds are deterministic across machines.
        url = "https://github.com/NixOS/nixpkgs/archive/8b27c1239e5c421a2bbc2c65d52e4a6fbf2ff296.tar.gz";
        sha256 = "sha256-CqCX4JG7UiHvkrBTpYC3wcEurvbtTADLbo3Ns2CEoL8=";
      };
    in
    import nixpkgsSrc { config.allowUnfree = true; },
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
  # Reuse the same pinned nixpkgs; Linux builds target glibc 2.34 compatibility.
  nixpkgsSrc = builtins.fetchTarball {
    # Use an immutable commit tarball so builds are deterministic across machines.
    url = "https://github.com/NixOS/nixpkgs/archive/8b27c1239e5c421a2bbc2c65d52e4a6fbf2ff296.tar.gz";
    sha256 = "sha256-CqCX4JG7UiHvkrBTpYC3wcEurvbtTADLbo3Ns2CEoL8=";
  };
  # Bring a modern Rust toolchain (1.90.0) via oxalica/rust-overlay for Cargo edition2024 support
  rustOverlay = import (
    builtins.fetchTarball {
      # Pin rust-overlay to an immutable commit (master is moving).
      url = "https://github.com/oxalica/rust-overlay/archive/23dd7fa91602a68bd04847ac41bc10af1e6e2fd2.tar.gz";
      sha256 = "sha256-KvmjUeA7uODwzbcQoN/B8DCZIbhT/Q/uErF1BBMcYnw=";
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

  # For Linux, pin nixpkgs 22.05 (glibc 2.34) to get its stdenv while using a modern
  # Rust toolchain (1.90.0) from rust-overlay. Rocky Linux 9 compatibility requires GLIBC <= 2.34.
  # Hardcoded URL+hash for full determinism — override via `--arg pkgs234 ...` if needed.
  pkgs234 =
    if pkgs.stdenv.isLinux then
      import (builtins.fetchTarball {
        url = "https://github.com/NixOS/nixpkgs/archive/380be19fbd2d9079f677978361792cb25e8a3635.tar.gz";
        sha256 = "sha256-Zffu01pONhs/pqH07cjlF10NnMDLok8ix5Uk4rhOnZQ=";
      }) { config.allowUnfree = true; }
    else
      pkgs;

  # Create rustPlatform: on Linux use pkgs234.makeRustPlatform (glibc 2.34),
  # but with modern Rust toolchain
  rustPlatform190 =
    if pkgs.stdenv.isLinux then
      pkgs234.makeRustPlatform {
        cargo = rustToolchain;
        rustc = rustToolchain;
      }
    else
      pkgsWithRust.makeRustPlatform {
        cargo = rustToolchain;
        rustc = rustToolchain;
      };

  # Build OpenSSL 3.1.2 with nixpkgs 22.05 stdenv (glibc 2.34 for Rocky Linux 9)
  # Create both static and dynamic versions
  openssl312-static = pkgs234.callPackage ./nix/openssl.nix { static = true; };
  openssl312-dynamic = pkgs234.callPackage ./nix/openssl.nix { static = false; };
  # Default to static for backward compatibility
  openssl312 = openssl312-static;

  # Build OpenSSL 3.6.0 with legacy provider for non-FIPS builds
  # Common parameters for both static and dynamic builds
  openssl36Args = {
    version = "3.6.0";
    enableLegacy = true;
    srcUrl = "https://package.cosmian.com/openssl/openssl-3.6.0.tar.gz";
    sha256SRI = "sha256-tqX0S362nj+jXb8VUkQFtEg3pIHUPYHa3d4/8h/LuOk=";
    expectedHash = "b6a5f44b7eb69e3fa35dbf15524405b44837a481d43d81daddde3ff21fcbb8e9";
  };
  openssl36-static = pkgs234.callPackage ./nix/openssl.nix (openssl36Args // { static = true; });
  openssl36-dynamic = pkgs234.callPackage ./nix/openssl.nix (openssl36Args // { static = false; });

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
    cargoSha256 = "sha256-mUsoPBgv60Eir/uIK+Xe+GmXdSFKXoopB4PlvFvHZuA=";
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
    inherit rustToolchain;
  };

  ui-non-fips = pkgs.callPackage ./nix/ui.nix {
    features = [ "non-fips" ];
    version = kmsVersion;
    inherit rustToolchain;
  };

  # DRY helper to build servers for both variants and both linkage modes
  mkKmsServer =
    {
      features,
      ui,
      static ? true,
    }:
    pkgs.callPackage ./nix/kms-server.nix {
      openssl312 = if static then openssl312-static else openssl312-dynamic;
      openssl36 = if static then openssl36-static else openssl36-dynamic;
      inherit pkgs234;
      rustPlatform = rustPlatform190;
      version = kmsVersion;
      inherit
        features
        ui
        static
        ;
    };

  # Build KMS server in both variants with static OpenSSL
  kms-server-fips-static-openssl = mkKmsServer {
    features = [ ];
    ui = ui-fips;
    static = true;
  };

  kms-server-non-fips-static-openssl = mkKmsServer {
    features = [ "non-fips" ];
    ui = ui-non-fips;
    static = true;
  };

  # Build KMS server with dynamic OpenSSL linking
  kms-server-fips-dynamic-openssl = mkKmsServer {
    features = [ ];
    ui = ui-fips;
    static = false;
  };

  kms-server-non-fips-dynamic-openssl = mkKmsServer {
    features = [ "non-fips" ];
    ui = ui-non-fips;
    static = false;
  };

  # Docker images using dockerTools (minimal images)
  docker-image-fips = pkgs.callPackage ./nix/docker.nix {
    kmsServer = kms-server-fips-static-openssl;
    variant = "fips";
    version = kmsVersion;
    opensslDrv = openssl312;
  };

  docker-image-non-fips = pkgs.callPackage ./nix/docker.nix {
    kmsServer = kms-server-non-fips-static-openssl;
    variant = "non-fips";
    version = kmsVersion;
    # Provide OpenSSL 3.6.0 so the Docker image ships legacy provider + non-FIPS openssl.cnf
    opensslDrv = openssl36-static;
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

  # Export OpenSSL 3.6.0 derivations (with legacy provider for non-FIPS)
  inherit openssl36-static openssl36-dynamic;

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

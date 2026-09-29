# Nix derivations for the Cosmian KMS Kubernetes in-cluster binaries.
#
# These produce statically-linked Linux binaries (GLIBC ≤ 2.28) that are
# consumed by k8s-images.nix to build minimal Docker images. Neither binary
# performs cryptographic operations — they are thin gRPC/HTTP clients that
# delegate crypto to the KMS server — so a single (non-FIPS) variant suffices.
{
  pkgs ? import <nixpkgs> { },
  lib ? pkgs.lib,
  openssl36 ? null,
  openssl312 ? null,
  rustPlatform ? pkgs.rustPlatform,
  version,
  features ? [ ],
  static ? true,
}:

let
  common = import ./common.nix {
    inherit
      pkgs
      lib
      openssl36
      openssl312
      static
      features
      ;
    pkgs234 = pkgs;
  };
  inherit (common)
    buildInputs
    opensslEnv
    mkFilteredSrc
    mkRelinkSnippet
    featuresFlag
    ;

  filteredSrc = mkFilteredSrc [ ];

  mkCargoHash =
    hashFile:
    let
      fallback = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    in
    if builtins.pathExists hashFile then
      lib.replaceStrings [ "\n" "\r" " " "\t" ] [ "" "" "" "" ] (builtins.readFile hashFile)
    else
      fallback;

  glibcCheck =
    name:
    # Check GLIBC version <= 2.28 (RHEL 8 / Debian 10 / Ubuntu 18.04 compatibility)
    ''
      MAX_VER=$(readelf -sW "$out/bin/${name}" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//' | sort -V | tail -n1)
      if [ -n "$MAX_VER" ]; then
        [ "$(printf '%s\n' "$MAX_VER" "2.28" | sort -V | tail -n1)" = "2.28" ] || {
          echo "ERROR: ${name} requires GLIBC $MAX_VER > 2.28"; exit 1;
        }
      fi
    '';

  nativeBuildInputs = with pkgs; [
    pkg-config
    git
    file
    coreutils
    binutils
    patchelf
  ];

  # ── Operator ──────────────────────────────────────────────────────────────

  operator = rustPlatform.buildRustPackage (
    {
      pname = "cosmian-kms-operator";
      inherit version;
      auditable = false;
      doCheck = false;

      src = filteredSrc;
      cargoSha256 = mkCargoHash ./expected-hashes/k8s-operator.vendor.linux.sha256;
      buildType = "release";

      inherit nativeBuildInputs buildInputs;

      buildPhase = ''
        echo "== cargo build cosmian-kms-operator (release) =="
        cargo build --release -p cosmian_kms_k8s_operator --no-default-features ${featuresFlag}

        ${mkRelinkSnippet ''
          echo "== Re-linking cosmian-kms-operator with system dynamic linker: $DL =="
          cargo rustc --release -p cosmian_kms_k8s_operator --bin cosmian-kms-operator \
            --no-default-features ${featuresFlag} \
            -- -C link-arg=-Wl,--dynamic-linker,$DL
        ''}
      '';

      installPhase = ''
        mkdir -p "$out/bin"
        cp "target/release/cosmian-kms-operator" "$out/bin/"
      '';

      installCheckPhase = ''
        runHook preInstallCheck
        [ -x "$out/bin/cosmian-kms-operator" ] || { echo "ERROR: cosmian-kms-operator not found"; exit 1; }
        ${glibcCheck "cosmian-kms-operator"}
        runHook postInstallCheck
      '';
    }
    // opensslEnv
  );

  # ── CSI Provider ──────────────────────────────────────────────────────────

  csiProvider = rustPlatform.buildRustPackage (
    {
      pname = "cosmian-kms-csi-provider";
      inherit version;
      auditable = false;
      doCheck = false;

      src = filteredSrc;
      cargoSha256 = mkCargoHash ./expected-hashes/k8s-csi-provider.vendor.linux.sha256;
      buildType = "release";

      inherit nativeBuildInputs buildInputs;

      buildPhase = ''
        echo "== cargo build cosmian-kms-csi-provider (release) =="
        cargo build --release -p cosmian_kms_csi_provider --no-default-features ${featuresFlag}

        ${mkRelinkSnippet ''
          echo "== Re-linking cosmian-kms-csi-provider with system dynamic linker: $DL =="
          cargo rustc --release -p cosmian_kms_csi_provider --bin cosmian-kms-csi-provider \
            --no-default-features ${featuresFlag} \
            -- -C link-arg=-Wl,--dynamic-linker,$DL
        ''}
      '';

      installPhase = ''
        mkdir -p "$out/bin"
        cp "target/release/cosmian-kms-csi-provider" "$out/bin/"
      '';

      installCheckPhase = ''
        runHook preInstallCheck
        [ -x "$out/bin/cosmian-kms-csi-provider" ] || { echo "ERROR: cosmian-kms-csi-provider not found"; exit 1; }
        ${glibcCheck "cosmian-kms-csi-provider"}
        runHook postInstallCheck
      '';
    }
    // opensslEnv
  );

in
{
  inherit operator csiProvider;
}

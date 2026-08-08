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

  cargoHash =
    let
      vendorFile = ./expected-hashes/k8s-plugin.vendor.linux.sha256;
      fallback = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    in
    if builtins.pathExists vendorFile then
      lib.replaceStrings [ "\n" "\r" " " "\t" ] [ "" "" "" "" ] (builtins.readFile vendorFile)
    else
      fallback;
in
rustPlatform.buildRustPackage (
  {
    pname = "kubernetes-kms-plugin";
    inherit version;
    auditable = false;
    doCheck = false;

    src = filteredSrc;
    cargoSha256 = cargoHash;
    buildType = "release";

    nativeBuildInputs = with pkgs; [
      pkg-config
      git
      file
      coreutils
      binutils
      patchelf
    ];

    inherit buildInputs;

    buildPhase = ''
      echo "== cargo build kubernetes-kms-plugin (release) =="
      cargo build --release -p cosmian_kms_k8s_plugin --no-default-features ${featuresFlag}

      ${mkRelinkSnippet ''
        echo "== Re-linking kubernetes-kms-plugin with system dynamic linker: $DL =="
        cargo rustc --release -p cosmian_kms_k8s_plugin --bin kubernetes-kms-plugin \
          --no-default-features ${featuresFlag} \
          -- -C link-arg=-Wl,--dynamic-linker,$DL
      ''}
    '';

    installPhase = ''
      mkdir -p "$out/bin"
      cp "target/release/kubernetes-kms-plugin" "$out/bin/"
    '';

    installCheckPhase = ''
      runHook preInstallCheck
      [ -x "$out/bin/kubernetes-kms-plugin" ] || { echo "ERROR: kubernetes-kms-plugin not found"; exit 1; }
      "$out/bin/kubernetes-kms-plugin" --help >/dev/null 2>&1 || true

      # Check GLIBC version <= 2.28 (RHEL 8 / Debian 10 / Ubuntu 18.04 compatibility)
      MAX_VER=$(readelf -sW "$out/bin/kubernetes-kms-plugin" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//' | sort -V | tail -n1)
      if [ -n "$MAX_VER" ]; then
        [ "$(printf '%s\n' "$MAX_VER" "2.28" | sort -V | tail -n1)" = "2.28" ] || {
          echo "ERROR: kubernetes-kms-plugin requires GLIBC $MAX_VER > 2.28"; exit 1;
        }
      fi
      runHook postInstallCheck
    '';
  }
  // opensslEnv
)

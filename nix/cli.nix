{
  pkgs ? import <nixpkgs> { },
  pkgs228 ? pkgs, # nixpkgs ≈ 19.09 with glibc 2.28 (RHEL 8 / Debian 10 / Ubuntu 18.04 compatibility)
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
    pkgs234 = pkgs228; # common.nix uses pkgs234 naming; CLI targets glibc 2.28
  };
  inherit (common)
    buildInputs
    opensslEnv
    mkFilteredSrc
    mkRelinkSnippet
    featuresFlag
    ;

  filteredSrc = mkFilteredSrc [ ];

  # CLI vendor hash depends on operating system AND (on macOS only) linkage mode.
  # On Linux: static and dynamic produce identical vendor output → one shared file.
  # On macOS: static ≠ dynamic → linkage-specific files.
  cargoHash =
    let
      linkStr = if static then "static" else "dynamic";
      vendorFile =
        if pkgs.stdenv.isLinux then
          ./expected-hashes/cli.vendor.linux.sha256
        else if pkgs.stdenv.isDarwin then
          ./expected-hashes + "/cli.vendor.${linkStr}.darwin.sha256"
        else
          ./expected-hashes + "/cli.vendor.${linkStr}.linux.sha256"; # best-effort fallback
      fallback = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    in
    if builtins.pathExists vendorFile then
      lib.replaceStrings [ "\n" "\r" " " "\t" ] [ "" "" "" "" ] (builtins.readFile vendorFile)
    else
      fallback;
in
rustPlatform.buildRustPackage (
  {
    pname = "cosmian-kms-cli${if static then "" else "-dynamic"}";
    inherit version;
    auditable = false;
    doCheck = false;

    src = filteredSrc;
    cargoSha256 = cargoHash;
    buildType = "release";

    nativeBuildInputs =
      with pkgs;
      [
        pkg-config
        git
        file
        coreutils
      ]
      ++ lib.optionals pkgs.stdenv.isLinux [
        binutils
        patchelf
      ]
      ++ lib.optionals pkgs.stdenv.isDarwin [
        darwin.cctools
      ];

    inherit buildInputs;

    buildPhase = ''
      echo "== cargo build ckms (release) =="
      cargo build --release -p ckms --no-default-features ${featuresFlag}

      echo "== cargo build cosmian_pkcs11 (release) =="
      cargo build --release -p cosmian_pkcs11 --no-default-features ${featuresFlag}

      echo "== cargo build cosmian_pkcs11_verify (release) =="
      cargo build --release -p cosmian_pkcs11_verify --no-default-features ${featuresFlag}

      ${mkRelinkSnippet ''
        echo "== Re-linking ckms with system dynamic linker: $DL =="
        cargo rustc --release -p ckms --bin ckms --no-default-features ${featuresFlag} \
          -- -C link-arg=-Wl,--dynamic-linker,$DL

        echo "== Re-linking cosmian_pkcs11_verify with system dynamic linker: $DL =="
        cargo rustc --release -p cosmian_pkcs11_verify --bin cosmian_pkcs11_verify --no-default-features ${featuresFlag} \
          -- -C link-arg=-Wl,--dynamic-linker,$DL

        echo "== Re-linking libcosmian_pkcs11.so without Nix RPATH =="
        cargo rustc --release -p cosmian_pkcs11 --lib --no-default-features ${featuresFlag} \
          -- -C link-arg=-Wl,-soname,libcosmian_pkcs11.so
        patchelf --remove-rpath "target/release/libcosmian_pkcs11.so" 2>/dev/null || true
      ''}
    '';

    installPhase = ''
      mkdir -p "$out/bin" "$out/lib"
      cp "target/release/ckms" "$out/bin/"
      cp "target/release/cosmian_pkcs11_verify" "$out/bin/"
      if [ "$(uname)" = "Linux" ]; then
        cp "target/release/libcosmian_pkcs11.so" "$out/lib/"
      elif [ "$(uname)" = "Darwin" ]; then
        cp "target/release/libcosmian_pkcs11.dylib" "$out/lib/"
      fi
    '';

    installCheckPhase = ''
      runHook preInstallCheck
      [ -x "$out/bin/ckms" ] || { echo "ERROR: ckms not found"; exit 1; }
      [ -x "$out/bin/cosmian_pkcs11_verify" ] || { echo "ERROR: cosmian_pkcs11_verify not found"; exit 1; }
      "$out/bin/ckms" --help >/dev/null 2>&1 || true
      if [ "$(uname)" = "Linux" ]; then
        [ -f "$out/lib/libcosmian_pkcs11.so" ] || { echo "ERROR: libcosmian_pkcs11.so not found"; exit 1; }

        # Check GLIBC version <= 2.28 (Linux only, RHEL 8 / Debian 10 / Ubuntu 18.04 compatibility)
        for BIN in "$out/bin/ckms" "$out/bin/cosmian_pkcs11_verify" "$out/lib/libcosmian_pkcs11.so"; do
          MAX_VER=$(readelf -sW "$BIN" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//' | sort -V | tail -n1)
          [ -z "$MAX_VER" ] && continue
          [ "$(printf '%s\n' "$MAX_VER" "2.28" | sort -V | tail -n1)" = "2.28" ] || {
            echo "ERROR: $BIN requires GLIBC $MAX_VER > 2.28"; exit 1;
          }
        done
      elif [ "$(uname)" = "Darwin" ]; then
        [ -f "$out/lib/libcosmian_pkcs11.dylib" ] || { echo "ERROR: libcosmian_pkcs11.dylib not found"; exit 1; }
      fi
      runHook postInstallCheck
    '';
  }
  // opensslEnv
)

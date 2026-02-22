{
  pkgs ? import <nixpkgs> { },
  pkgs234 ? pkgs,
  lib ? pkgs.lib,
  openssl36 ? null,
  openssl312 ? null,
  rustPlatform ? pkgs.rustPlatform,
  version,
  features ? [ ],
  static ? true,
  enforceDeterministicHash ? false,
}:

let
  common = import ./common.nix {
    inherit
      pkgs
      pkgs234
      lib
      openssl36
      openssl312
      static
      features
      ;
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
      os = builtins.elemAt (lib.splitString "-" pkgs.stdenv.hostPlatform.system) 1;
      vendorFile = ./expected-hashes + "/cli.vendor.${os}.sha256";
      fallback =
        if os == "linux" then
          "sha256-mHB1pqIsgrsjtSN9MkBRVeFSDJu42BfVeJbwTk/YAxg="
        else
          "sha256-BBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    in
    if builtins.pathExists vendorFile then
      let
        trimmed = lib.replaceStrings [ "\n" "\r" " " "\t" ] [ "" "" "" "" ] (builtins.readFile vendorFile);
      in
      if enforceDeterministicHash then
        (
          assert trimmed != "";
          trimmed
        )
      else
        trimmed
    else if enforceDeterministicHash then
      builtins.throw ("Expected CLI vendor cargo hash file not found: " + vendorFile)
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

      ${mkRelinkSnippet ''
        echo "== Re-linking ckms with system dynamic linker: $DL =="
        cargo rustc --release -p ckms --bin ckms --no-default-features ${featuresFlag} \
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
      if [ "$(uname)" = "Linux" ]; then
        cp "target/release/libcosmian_pkcs11.so" "$out/lib/"
      elif [ "$(uname)" = "Darwin" ]; then
        cp "target/release/libcosmian_pkcs11.dylib" "$out/lib/"
      fi
    '';

    installCheckPhase = ''
      runHook preInstallCheck
      [ -x "$out/bin/ckms" ] || { echo "ERROR: ckms not found"; exit 1; }
      "$out/bin/ckms" --help >/dev/null 2>&1 || true
      if [ "$(uname)" = "Linux" ]; then
        [ -f "$out/lib/libcosmian_pkcs11.so" ] || { echo "ERROR: libcosmian_pkcs11.so not found"; exit 1; }
      elif [ "$(uname)" = "Darwin" ]; then
        [ -f "$out/lib/libcosmian_pkcs11.dylib" ] || { echo "ERROR: libcosmian_pkcs11.dylib not found"; exit 1; }
      fi
      runHook postInstallCheck
    '';
  }
  // opensslEnv
)

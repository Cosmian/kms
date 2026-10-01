{
  # musl cross package set for the target architecture — see kms-server-musl.nix for
  # the full explanation (same `pkgsWithRust.pkgsCross.*` value must be passed here).
  pkgsMusl,
  lib ? pkgsMusl.lib,
  openssl36 ? null,
  openssl312 ? null,
  rustPlatform ? pkgsMusl.rustPlatform,
  version,
  features ? [ ],
  # See kms-server-musl.nix's `muslCrtStatic` doc comment: false (dynamic, FIPS) keeps
  # `dlopen` working; true (fully static, non-FIPS) cannot `dlopen` at all.
  muslCrtStatic ? true,
}:

let
  common = import ./common.nix {
    pkgs = pkgsMusl;
    pkgs234 = pkgsMusl;
    inherit lib openssl36 openssl312 features;
    static = true; # OpenSSL main library is always statically embedded (.a) here
  };
  inherit (common)
    opensslLink
    mkFilteredSrc
    baseVariant
    ;

  libcTag = if muslCrtStatic then "musl-static" else "musl-dynamic";

  hostPlatform = pkgsMusl.stdenv.hostPlatform;
  archTag = if hostPlatform.isAarch64 then "aarch64" else "x86_64";
  muslTriple = hostPlatform.config;
  muslLoader = "/lib/ld-musl-${archTag}.so.1";

  filteredSrc = mkFilteredSrc [ ];

  # See kms-server-musl.nix: vendoring differs between fips/non-fips feature sets.
  cargoHash =
    let
      vendorFile = ./expected-hashes + "/cli.vendor.musl-${baseVariant}.sha256";
      placeholder = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    in
    if builtins.pathExists vendorFile then
      lib.replaceStrings [ "\n" "\r" " " "\t" ] [ "" "" "" "" ] (builtins.readFile vendorFile)
    else
      placeholder;
in
rustPlatform.buildRustPackage rec {
  pname = "cosmian-kms-cli-${libcTag}";
  inherit version;
  auditable = false;
  doCheck = false; # see kms-server-musl.nix: validated via Alpine-container smoke test instead

  src = filteredSrc;
  cargoSha256 = cargoHash;
  buildType = "release";

  nativeBuildInputs = with pkgsMusl.buildPackages; [
    pkg-config
    git
    file
    coreutils
    binutils
  ];

  buildInputs = [ opensslLink ];

  OPENSSL_DIR = opensslLink;
  OPENSSL_LIB_DIR = "${opensslLink}/lib";
  OPENSSL_INCLUDE_DIR = "${opensslLink}/include";
  OPENSSL_NO_VENDOR = 1;
  OPENSSL_STATIC = "1";

  RUSTFLAGS = lib.concatStringsSep " " [
    "-C target-feature=${if muslCrtStatic then "+crt-static" else "-crt-static"}"
    "-C debuginfo=0"
    "-C strip=symbols"
  ];

  buildPhase = ''
    echo "== cargo build ckms (release, ${muslTriple}, ${libcTag}) =="
    cargo build --release -p ckms --target ${muslTriple} --no-default-features \
      ${lib.optionalString (features != [ ]) "--features ${lib.concatStringsSep "," features}"}
  '';

  installPhase = ''
    mkdir -p "$out/bin"
    install -m755 "target/${muslTriple}/release/ckms" "$out/bin/ckms"
    ${lib.optionalString (!muslCrtStatic) ''
      patchelf --set-interpreter "${muslLoader}" "$out/bin/ckms"
    ''}
  '';

  installCheckPhase = ''
    runHook preInstallCheck
    BIN="$out/bin/ckms"
    [ -x "$BIN" ] || { echo "ERROR: ckms not found"; exit 1; }
    file "$BIN" || true

    ${
      if muslCrtStatic then
        ''
          if readelf -l "$BIN" | grep -q "INTERP"; then
            echo "ERROR: expected a fully static musl binary (no INTERP segment)"
            exit 1
          fi
        ''
      else
        ''
          interp=$(readelf -l "$BIN" | sed -n 's/^.*interpreter: \(.*\)\]$/\1/p')
          [ "$interp" = "${muslLoader}" ] || {
            echo "ERROR: expected interpreter ${muslLoader}, got: $interp"; exit 1;
          }
        ''
    }

    ACTUAL=$(sha256sum "$BIN" | awk '{print $1}')
    echo "$ACTUAL" > "$out/bin/ckms.sha256"
    HASH_FILENAME="cosmian-kms-cli.${libcTag}.${archTag}.linux.sha256"
    echo "$ACTUAL" > "$out/bin/$HASH_FILENAME"
    runHook postInstallCheck
  '';

  meta = with lib; {
    description = "Cosmian KMS CLI (ckms) - musl/Alpine-compatible Linux ${archTag} build";
    homepage = "https://github.com/Cosmian/kms";
    license = {
      shortName = "BUSL-1.1";
      fullName = "Business Source License 1.1";
      url = "https://github.com/Cosmian/kms/blob/develop/LICENSE";
      free = false;
    };
    platforms = [ "${archTag}-linux" ];
    maintainers = [ ];
  };
}

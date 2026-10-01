{
  # musl cross package set for the target architecture — e.g.
  # `pkgsWithRust.pkgsCross.musl64` (x86_64) or
  # `pkgsWithRust.pkgsCross.aarch64-multiplatform-musl` (aarch64). The Rust toolchain
  # used to build `rustPlatform` below must have the matching `*-unknown-linux-musl`
  # target added to its `targets` list (see default.nix) so the target's std library
  # is available.
  pkgsMusl,
  lib ? pkgsMusl.lib,
  # Optional external OpenSSL derivation overrides; if null, built from nix/openssl.nix.
  openssl36 ? null,
  openssl312 ? null,
  rustPlatform ? pkgsMusl.rustPlatform,
  version,
  features ? [ ], # [ "non-fips" ] or []
  ui ? null, # Pre-built UI derivation providing dist/
  # Linking mode for musl's *libc* (not OpenSSL, which is always statically embedded
  # here — see common.nix's `static = true` below, matching the existing
  # "static-openssl" convention used by the glibc builds):
  #   false (dynamic, used for the FIPS variant): links against musl's own small
  #     `libc.so`/`ld-musl-<arch>.so.1`, which is present by default on every real
  #     Alpine image. This keeps `dlopen` available, so the FIPS provider module
  #     (`fips.so`, loaded via `Provider::load(None, "fips")` in
  #     `openssl_providers.rs`) loads exactly like it does on the glibc build.
  #     NOTE: rustc always emits an explicit `-lgcc_s` for non-static musl targets
  #     (confirmed: `-C link-arg=-static-libgcc` does NOT suppress it — rustc's own
  #     codegen, not gcc's implicit linking, adds it). Alpine's base image does not
  #     ship `libgcc_s.so.1` (it's the separate `libgcc` apk package), so deployments
  #     of this variant must `apk add --no-cache libgcc` — documented in the
  #     Alpine how-to page, not fixable via a build flag on stable Rust.
  #   true (fully static, used for the non-FIPS variant, Rust's own default for musl
  #     targets): produces a binary with no dynamic linker at all (no INTERP segment),
  #     runnable even on `FROM scratch`, with zero extra apk packages. musl's static
  #     libc cannot `dlopen` at all, so the OpenSSL "legacy" provider load fails and
  #     is handled gracefully at runtime (logged as a warning, not fatal — see
  #     `init_openssl_providers` in `crate/server/src/openssl_providers.rs`) —
  #     everything else (default provider: AES/RSA/EC/PQC/Covercrypt) is unaffected.
  muslCrtStatic ? true,
}:

let
  common = import ./common.nix {
    pkgs = pkgsMusl;
    pkgs234 = pkgsMusl; # musl has no cross-distro GLIBC-version concern to pin against
    inherit lib openssl36 openssl312 features;
    static = true; # OpenSSL main library is always statically embedded (.a) here
  };
  inherit (common)
    isFips
    baseVariant
    openssl36_
    openssl312_
    opensslLink
    mkFilteredSrc
    ;

  libcTag = if muslCrtStatic then "musl-static" else "musl-dynamic";
  variant = "${baseVariant}-${libcTag}";

  hostPlatform = pkgsMusl.stdenv.hostPlatform;
  archTag = if hostPlatform.isAarch64 then "aarch64" else "x86_64";
  # musl triple, e.g. "x86_64-unknown-linux-musl" / "aarch64-unknown-linux-musl".
  muslTriple = hostPlatform.config;
  # Real loader path on an actual Alpine image (not a Nix store path) — this is what
  # the dynamic variant's binary must reference so it runs unmodified on Alpine.
  muslLoader = "/lib/ld-musl-${archTag}.so.1";

  filteredSrc = mkFilteredSrc [
    "test_data"
    "documentation"
  ];

  installCheckPhase = ''
    runHook preInstallCheck

    BIN="$out/bin/cosmian_kms"
    [ -f "$BIN" ] || { echo "ERROR: Binary not found"; exit 1; }
    echo "Binary exists at: $BIN"
    file "$BIN" || true
    readelf -l "$BIN" || true

    ${
      if muslCrtStatic then
        ''
          # Fully static: there must be no INTERP segment at all (no dynamic linker).
          if readelf -l "$BIN" | grep -q "INTERP"; then
            echo "ERROR: expected a fully static musl binary (no INTERP segment)"
            readelf -l "$BIN" | grep -A1 "INTERP" || true
            exit 1
          fi
          echo "Confirmed fully static musl binary (no dynamic linker)."
        ''
      else
        ''
          # Dynamic musl: INTERP must be the real Alpine loader path, never a Nix store path.
          interp=$(readelf -l "$BIN" | sed -n 's/^.*interpreter: \(.*\)\]$/\1/p')
          echo "Interpreter: $interp"
          [ "$interp" = "${muslLoader}" ] || {
            echo "ERROR: expected interpreter ${muslLoader}, got: $interp"; exit 1;
          }
        ''
    }

    # OpenSSL is always statically embedded in this build (no separate libssl/libcrypto.so).
    strings "$BIN" | grep -q "OpenSSL 3.6.2" || {
      echo "ERROR: Binary not statically linked against OpenSSL 3.6.2"; exit 1;
    }

    # Run version check only for the fully static variant on a matching CPU
    # architecture (the Nix builder can execute a foreign-libc binary natively as long
    # as the CPU architecture matches — e.g. an x86_64-musl binary runs fine on an
    # x86_64-glibc builder kernel — but a *dynamic* musl binary cannot: its
    # interpreter was just patched (above) from the Nix store's own musl loader to the
    # real Alpine path (/lib/ld-musl-<arch>.so.1), which does not exist on this
    # (non-Alpine) builder. That patch is exactly what makes the shipped binary work
    # unmodified on Alpine, but it means this builder can no longer execute it
    # directly — functional validation for the dynamic variant happens in CI's
    # Alpine-container smoke test instead (see packaging.yml). The fully static
    # variant has no interpreter dependency at all, so it is still executed directly
    # here.
    ${
      if muslCrtStatic then
        ''
          if [ "$(uname -m)" = "${archTag}" ]; then
            echo "Running version check..."
            if VERSION_OUTPUT=$("$BIN" --version 2>&1); then
              echo "Version output: $VERSION_OUTPUT"
              echo "$VERSION_OUTPUT" | grep -qE "(cosmian_kms_server|cosmian_kms)" || {
                echo "ERROR: Version check failed - output doesn't match expected pattern"; exit 1;
              }
            else
              echo "Binary execution failed (unexpected on matching architecture)"; exit 1
            fi
          else
            echo "Skipping direct execution check (builder arch $(uname -m) != target ${archTag})"
          fi
        ''
      else
        ''
          echo "Skipping direct execution check (dynamic-musl interpreter ${muslLoader} does not exist on this non-Alpine builder); validated via Alpine-container smoke test in CI instead."
        ''
    }

    ACTUAL=$(sha256sum "$BIN" | awk '{print $1}')
    echo "$ACTUAL" > "$out/bin/cosmian_kms.sha256"
    HASH_FILENAME="cosmian-kms-server.${baseVariant}.${libcTag}.${archTag}.linux.sha256"
    echo "$ACTUAL" > "$out/bin/$HASH_FILENAME"
    echo "Binary hash saved to: $out/bin/$HASH_FILENAME"
    echo "To update repository, copy this file to: nix/expected-hashes/$HASH_FILENAME"

    runHook postInstallCheck
  '';
in
rustPlatform.buildRustPackage rec {
  pname = "cosmian-kms-server-${libcTag}";
  inherit version;
  auditable = false;


  src = filteredSrc;

  # Vendoring turns out to differ between fips/non-fips feature sets for this
  # workspace (non-fips pulls extra feature-gated crates: PQC, Covercrypt, etc.), so
  # each gets its own tracked hash file, discovered the standard Nix way (build once
  # with the placeholder below, copy the real hash reported in the mismatch error).
  cargoHash =
    let
      vendorFile = ./expected-hashes + "/server.vendor.musl-${baseVariant}.sha256";
      placeholder = "sha256-BBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    in
    if builtins.pathExists vendorFile then
      let
        trimmed = lib.replaceStrings [ "\n" "\r" " " "\t" ] [ "" "" "" "" ] (builtins.readFile vendorFile);
      in
      assert trimmed != placeholder && trimmed != "";
      trimmed
    else
      builtins.throw "Expected server vendor cargo hash file not found: nix/expected-hashes/server.vendor.musl-${baseVariant}.sha256";
  cargoSha256 = cargoHash;

  buildType = "release";

  # Build-time tools must come from `buildPackages` (runs on the builder), not from
  # `pkgsMusl` directly (which would mean "cross-compile git/file/etc. themselves for
  # the musl target" — wrong, and needlessly expensive).
  nativeBuildInputs = with pkgsMusl.buildPackages; [
    pkg-config
    git
    file # binary inspection
    coreutils # sha256sum
    binutils # readelf
  ];

  buildInputs = [ opensslLink ];

  OPENSSL_DIR = opensslLink;
  OPENSSL_LIB_DIR = "${opensslLink}/lib";
  OPENSSL_INCLUDE_DIR = "${opensslLink}/include";
  OPENSSL_NO_VENDOR = 1;
  OPENSSL_STATIC = "1";

  SOURCE_DATE_EPOCH = "1";
  ZERO_AR_DATE = "1";
  CARGO_INCREMENTAL = "0";
  RUSTFLAGS =
    let
      remap = lib.concatStringsSep " " [
        "--remap-path-prefix"
        "/build=/cosmian-src"
        "--remap-path-prefix"
        "/tmp=/cosmian-src"
      ];
      crtStatic = "-C target-feature=${if muslCrtStatic then "+crt-static" else "-crt-static"}";
    in
    lib.concatStringsSep " " [
      remap
      crtStatic
      "-C symbol-mangling-version=v0"
      "-C link-arg=-Wl,--build-id=none"
      "-C debuginfo=0"
      "-C strip=symbols"
    ];

  buildPhase = ''
    echo "== cargo build cosmian_kms_server (release, ${muslTriple}, ${libcTag}) =="
    cargo build --release -p cosmian_kms_server --target ${muslTriple} --no-default-features \
      ${lib.optionalString (features != [ ]) "--features ${lib.concatStringsSep "," features}"}
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p "$out/bin"
    install -m755 "target/${muslTriple}/release/cosmian_kms" "$out/bin/cosmian_kms"
    ${lib.optionalString (!muslCrtStatic) ''
      # Point the dynamic variant at the real Alpine musl loader path (not the Nix
      # store's), exactly mirroring the glibc build's ELF-interpreter patch step.
      patchelf --set-interpreter "${muslLoader}" "$out/bin/cosmian_kms"
    ''}
    runHook postInstall
  '';

  postInstall = ''
    ${lib.optionalString (ui != null) ''
      mkdir -p "$out/usr/local/cosmian/ui/dist"
      cp -R "${ui}/dist/"* "$out/usr/local/cosmian/ui/dist/"
    ''}

    ${lib.optionalString isFips ''
      mkdir -p "$out/usr/local/cosmian/lib"
      cp -r "${openssl312_}/usr/local/cosmian/lib/ossl-modules" "$out/usr/local/cosmian/lib/"
      cp -r "${openssl312_}/usr/local/cosmian/lib/ssl" "$out/usr/local/cosmian/lib/"
    ''}

    ${lib.optionalString (!isFips && !muslCrtStatic) ''
      # Dynamic non-FIPS musl build only: ship the legacy provider module so it can be
      # dlopen'd (the fully static variant can never dlopen it — see muslCrtStatic doc
      # comment above — so it is intentionally omitted there).
      mkdir -p "$out/usr/local/cosmian/lib/ossl-modules"
      mkdir -p "$out/usr/local/cosmian/lib/ssl"
      if [ -d "${openssl36_}/usr/local/cosmian/lib/ossl-modules" ]; then
        cp -r "${openssl36_}/usr/local/cosmian/lib/ossl-modules/"* "$out/usr/local/cosmian/lib/ossl-modules/" 2>/dev/null || true
      fi
      if [ -f "${openssl36_}/usr/local/cosmian/lib/ssl/openssl.cnf" ]; then
        cp "${openssl36_}/usr/local/cosmian/lib/ssl/openssl.cnf" "$out/usr/local/cosmian/lib/ssl/"
      fi
    ''}

    cat > "$out/bin/build-info.txt" <<EOF
    KMS Server ${variant}
    Version: ${version}
    Target: ${muslTriple}
    OpenSSL (link): ${opensslLink} (static)
    ${lib.optionalString isFips "FIPS provider: from OpenSSL 3.1.2 (usr/local/cosmian/lib)"}
    EOF
  '';

  passthru = {
    inherit variant isFips muslCrtStatic;
    opensslPath = opensslLink;
    uiPath = ui;
    inherit version;
    hostTriple = muslTriple;
  };

  meta = with lib; {
    description = "Cosmian KMS - musl/Alpine-compatible Linux ${archTag} build (${variant})";
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

  # Cross-compiled test binaries can't reliably execute inside the Nix sandbox for
  # every architecture combination (notably aarch64 cross-built from an x86_64
  # builder); real functional validation happens via the Alpine-container crypto
  # smoke test in CI instead (see .github/workflows/packaging-docker.yml... actually
  # packaging.yml's musl job).
  doCheck = false;
  dontCargoCheck = true;
  cargoCheckHook = "";
  cargoNextestHook = "";
  dontUseCargoParallelTests = true;
  doInstallCheck = true;
  dontInstallCheck = false;
  configurePhase = ''
    export CARGO_HOME="$(pwd)/.cargo-home"
  '';
  inherit installCheckPhase;
}

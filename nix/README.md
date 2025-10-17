# Nix OpenSSL 3.1.2 + FIPS

This directory contains a simple Nix derivation that builds OpenSSL 3.1.2 statically with the FIPS provider enabled and generates `ssl/fipsmodule.cnf`.

Two ways to provide OpenSSL to the dev shell:

- Default (recommended on macOS arm64): build locally under `.local/openssl-3.1.2` using the helper script, then just run `nix-shell`.
- Optional (reproducible via Nix): set `USE_NIX_OPENSSL=1` to let the shell consume the Nix-built OpenSSL.

## Usage

- Local OpenSSL (default):
    - Build once:
        - scripts/build_openssl_3_1_2.sh .local/openssl-3.1.2
    - Enter shell:
        - nix-shell

- Nix-provided OpenSSL (opt-in):
    - Enter shell with the toggle:
        - USE_NIX_OPENSSL=1 nix-shell

The shell validates on entry:

- Version is exactly 3.1.2
- Static libs exist (libcrypto.a, libssl.a)
- FIPS provider module exists (lib/ossl-modules/fips.{so|dylib})
- `ssl/fipsmodule.cnf` exists

## Apple Silicon note

If your Nix installation is x86_64-darwin (Rosetta), the Nix derivation will build x86_64 OpenSSL. Our shell checks that the library architecture matches the host. On Apple Silicon machines:

- If your host is arm64 but Nix is x86_64-darwin, the `USE_NIX_OPENSSL=1` path will fail fast with an arch mismatch. Use the default local OpenSSL path instead, or install/use an aarch64-darwin Nix.
- Once Nix is native aarch64-darwin, `USE_NIX_OPENSSL=1 nix-shell` will produce an arm64 OpenSSL and pass the check.

## What's built

The derivation output layout mirrors a typical `OPENSSL_DIR` tree:

- $out/bin/openssl
- $out/include
- $out/lib/{libcrypto.a,libssl.a}
- $out/lib/ossl-modules/fips.{so|dylib}
- $out/ssl/fipsmodule.cnf
- $out/lib/pkgconfig/{openssl.pc,libcrypto.pc,libssl.pc}

You can inspect the store path via `echo $OPENSSL_DIR` after entering the shell with `USE_NIX_OPENSSL=1`.

## Build

### Crypto
- Bump the CMVP-validated OpenSSL FIPS provider to 3.5.9 (FIPS 140-3, CMVP #5586), built separately from the main OpenSSL 3.6.5 and loaded at runtime ([#1502](https://github.com/Cosmian/kms/issues/1502))
- Pin the OpenSSL main and FIPS provider versions and SHA-256 once, in `crate/crypto/openssl_versions.json`; `crate/crypto/build.rs`, the Nix build (`nix/openssl.nix` `opensslEntry`), the packaging and smoke-test scripts (`.mise/lib/openssl.sh`), the SBOM targets and the Windows FIPS provider script derive their URL, tarball, prefix and expected version from it. Bump procedure: edit that file ([`resources/tarballs/README.md`](../resources/tarballs/README.md))
- Fix `build.rs` choosing the provider library extension from the build host instead of the target OS
- Write `fipsmodule.cnf` of the cargo and Windows FIPS builds with the `openssl fipsinstall` defaults, like the release packages (`make install_fips` / `nmake install_fips` wrote the pedantic config); existing `target/openssl-fips-provider-*` trees are migrated on the next build. A failing provider self-test now fails the build

### Packaging
- Stage the packaged OpenSSL files under the version-less `target/openssl-fips-linux` / `target/openssl-non-fips-linux` symlinks referenced by the `cargo-deb` and `cargo-generate-rpm` assets of `cosmian_kms_server` and `ckms`
- Pre-fetch both OpenSSL tarballs (main and FIPS provider) for offline Nix packaging, and locate the FIPS provider store path of the macOS DMG by its pinned version
- Rename the SBOM targets `openssl_3_1_2` / `openssl_3_6_5` to `openssl_fips` / `openssl_main` (output under `sbom/openssl_fips/` and `sbom/openssl_main/`)

### Nix
- Share the OpenSSL environment and FIPS / non-FIPS provider install snippets between `nix/kms-server.nix`, `nix/kms-server-musl.nix` and `nix/cli-musl.nix` (`nix/common.nix`); fix the wrong 3.6.5 hash of `shell.nix`

## CI

- Windows FIPS provider: build the pinned 3.5.9 provider instead of 3.1.2, and key its cache on `crate/crypto/openssl_versions.json`

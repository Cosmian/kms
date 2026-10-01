# Alpine Linux (musl) support

## Features

### Packaging

- Publish Linux **musl** release tarballs for `cosmian_kms` (server) and `ckms` (CLI),
  built via Nix (`nix/kms-server-musl.nix`, `nix/cli-musl.nix`) and validated end-to-end
  against real `alpine:3.20`/`3.21`/`latest` containers — no `gcompat` shim required:
  - **FIPS**: dynamically-linked musl (`ld-musl-<arch>.so.1`), keeping `dlopen` available
    so the FIPS provider loads exactly like the GLIBC build. Requires
    `apk add --no-cache libgcc` on Alpine (rustc always emits an explicit `-lgcc_s` for
    this target; confirmed not fixable via `-static-libgcc` on stable Rust).
  - **non-FIPS**: fully static musl (`+crt-static`, Rust's own default for this target).
    Zero extra `apk` packages required, including on `FROM scratch`.
  - Published for `x86_64` and `aarch64`, signed (GPG), checksummed (SHA-256), with SBOM,
    matching the existing `pkcs11-zip` artifact treatment
    (`mise run package:musl-tarball --component server|cli --variant fips|non-fips`).
- Add a CI-only reproducibility cross-check (`mise run test:musl-crosscheck`,
  `test:musl-openssl-prebuild`) that builds the same target via plain `cargo` +
  system `musl-gcc` (no Nix) — never signed or published, purely a second,
  independent build path to catch Nix-specific musl bugs.
- Add an Alpine-container smoke test (`.mise/scripts/test/test_alpine_musl.sh`) run in
  CI against `alpine:3.20`/`3.21`/`latest`: verifies the FIPS-provider / legacy-provider
  log lines, round-trips AES/RSA/EC via `ckms`, and (non-FIPS) exercises PQC —
  ML-KEM-1024, ML-DSA-87, and SLH-DSA-SHAKE-256f as a musl thread-stack-size
  regression canary.

### Known limitations (documented, not bugs)

- HSM backends (Utimaco, Proteccio, SmartCard HSM, Crypt2Pay) are not supported on the
  musl tarballs — vendor PKCS#11 drivers are glibc-only shared libraries.
- non-FIPS (fully static musl): old PKCS#12/RC2 import is unsupported — musl's static
  libc cannot `dlopen` the legacy OpenSSL provider module. All other algorithms,
  including PQC and Covercrypt, are unaffected.

## Improvements

### Server

- `openssl_providers.rs`: a legacy-OpenSSL-provider load failure (expected on fully
  static musl, where `dlopen` can never succeed) no longer aborts server startup —
  it is now logged as a warning and the server continues with the always-available
  default provider. Previously this was a hard `?`-propagated error.
- `openssl_providers.rs`: the non-FIPS provider `OnceLock` now also remembers a
  deliberate "legacy provider unavailable" outcome, so repeated calls to
  `init_openssl_providers()` (e.g. once per Actix worker thread) do not re-attempt
  the failing `dlopen` or re-log the warning on every call.

## Documentation

- `README.md`: new "Alpine Linux (musl)" section documenting the FIPS/non-FIPS musl
  linking modes, the `libgcc` requirement, and the HSM/legacy-PKCS#12 limitations.
- `documentation/docs/installation/installation_getting_started.md`: new "Alpine
  Linux" install tab with Dockerfile examples for both variants.

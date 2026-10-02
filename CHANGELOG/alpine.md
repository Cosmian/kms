# Alpine Linux (musl) support

## Features

### Packaging

- Publish Alpine Linux **`.apk`** packages for `cosmian_kms` (server, with OpenRC service
  and `/etc/cosmian/kms.toml`) and `ckms` (CLI),
  built via Nix (`nix/kms-server-musl.nix`, `nix/cli-musl.nix`) and validated end-to-end
  against real `alpine:3.20`/`3.21`/`latest` containers — no `gcompat` shim required:
  - **FIPS**: dynamically-linked musl (`ld-musl-<arch>.so.1`), keeping `dlopen` available
    so the FIPS provider loads exactly like the GLIBC build. The package depends on
    `libgcc` (rustc always emits an explicit `-lgcc_s` for
    this target; confirmed not fixable via `-static-libgcc` on stable Rust).
  - **non-FIPS**: fully static musl (`+crt-static`, Rust's own default for this target).
    Zero extra `apk` packages required, including on `FROM scratch`.
  - Published for `x86_64` and `aarch64`, signed (GPG detached `.asc`), checksummed
    (SHA-256), with SBOM, built with `nfpm`
    (`mise run package:apk --variant fips|non-fips [--component all|server|cli]`).
- Add a CI-only reproducibility cross-check (`mise run test:musl-crosscheck`,
  `test:musl-openssl-prebuild`) that builds the same target via plain `cargo` +
  system `musl-gcc` (no Nix) — never signed or published, purely a second,
  independent build path to catch Nix-specific musl bugs.
- Add an Alpine-container smoke test (`.mise/scripts/test/test_alpine_musl.sh`) that
  `apk add`s the packages, run in CI against `alpine:3.20`/`3.21`/`latest`: verifies the FIPS-provider / legacy-provider
  log lines, round-trips AES/RSA/EC via `ckms`, and (non-FIPS) exercises PQC —
  ML-KEM-1024, ML-DSA-87, and SLH-DSA-SHAKE-256f as a musl thread-stack-size
  regression canary.
- Add a third, independent validation path (`mise run test:alpine-native-build`, CI job
  `alpine-native-build`, x86_64 only — see below): builds `cosmian_kms` and `ckms`
  *natively* inside a real `alpine:3.21` container using Alpine's own apk-provided
  gcc/musl/openssl-dev end-to-end, with no cross-compilation at all. GitHub Actions has
  no hosted Alpine runner OS, but a job can set `container: alpine:X.Y` to achieve this.
  Never signed or published — purely a third way to catch musl-portability bugs that
  the other two paths (which both cross-compile from Ubuntu) could miss.

### Known limitations (documented, not bugs)

- `alpine-native-build` is x86_64-only: GitHub Actions does not yet support JS-based
  actions (e.g. `actions/checkout`) inside Alpine containers on arm64 runners
  ([actions/runner#1637](https://github.com/actions/runner/issues/1637)). aarch64 musl
  coverage is unaffected — still provided independently by `musl-crosscheck` and the
  Nix-built artifacts' `test-alpine-musl` smoke test.

- HSM backends (Utimaco, Proteccio, SmartCard HSM, Crypt2Pay) are not supported on the
  Alpine packages — vendor PKCS#11 drivers are glibc-only shared libraries.
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

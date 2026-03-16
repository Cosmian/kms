# Cosmian KMS — AI Agent Guide

Cosmian KMS is a high-performance, open-source FIPS 140-3 compliant Key Management System written in Rust.
It implements KMIP 2.1 over HTTP/TLS and supports AES, RSA, EC, ML-KEM, ML-DSA, SLH-DSA, Covercrypt, and more.

## Build & Test cheatsheet

```bash
# Build (FIPS mode is the default)
cargo build
cargo build --features non-fips   # non-FIPS: extra algorithms, legacy provider, PQC

# Test
cargo test-fips                    # alias: test --lib --workspace
cargo test-non-fips                # alias: test --lib --workspace --features non-fips
cargo test -p cosmian_kms_server   # single package
cargo test -p cosmian_kms_cli

# Lint
cargo clippy-all                   # alias: clippy --workspace --all-targets --all-features -- -D warnings
cargo format                       # alias: fmt --all -- --check

# Run
cargo run --bin cosmian_kms -- --database-type sqlite --sqlite-path /tmp/kms-data

# Probe (expect a KMIP validation error, not a 404)
curl -s -X POST -H "Content-Type: application/json" -d '{}' http://localhost:9998/kmip/2_1
```

DB test environment variables (start backends with `docker compose up -d`):

- `KMS_POSTGRES_URL=postgresql://kms:kms@127.0.0.1:5432/kms`
- `KMS_MYSQL_URL=mysql://kms:kms@localhost:3306/kms`
- `KMS_SQLITE_PATH=data/shared`

Notes:

- MySQL tests are currently disabled in CI
- Redis-findex tests are skipped in FIPS mode

## Workspace layout

```text
crate/
  access/           cosmian_kms_access        — access-control utilities
  cli/              cosmian_kms_cli            — CLI client binary
  clients/
    ckms/           ckms                       — CLI command tree
    pkcs11/                                    — PKCS#11 client
  client_utils/     cosmian_kms_client_utils   — shared client helpers
  crypto/           cosmian_kms_crypto         — crypto primitives, build.rs (builds OpenSSL 3.6.0)
  hsm/              HSM PKCS#11 loaders (softhsm2, utimaco, proteccio, crypt2pay, smartcardhsm)
  interfaces/       cosmian_kms_interfaces     — Database/HSM traits
  kmip/             cosmian_kmip               — KMIP 0 & 2.1 protocol types
  kmip-derive/      kmip-derive                — proc-macros for KMIP
  kms_client/       cosmian_kms_client         — HTTP client library
  server/           cosmian_kms_server         — server binary + lib (main codebase)
  server_database/  cosmian_kms_server_database — DB backends (SQLite, PostgreSQL, Redis-findex)
  test_kms_server/  test_kms_server            — in-process test server helper
  wasm/             cosmian_kms_client_wasm    — WASM client

.github/            CI workflows and scripts
documentation/      MkDocs documentation source
nix/                Nix build expressions and expected hashes
pkg/                deb/rpm service files and configs
resources/          Server config templates
test_data/          Test fixtures
ui/                 Web UI (FIPS flavour)
ui_non_fips/        Web UI (non-FIPS flavour)
```

## KMIP request flow

```text
HTTP client
  |
  v
crate/server/src/routes/kmip.rs               — Actix-web handler, deserializes TTLV
  |
  v
crate/server/src/core/operations/dispatch.rs  — matches TTLV tag -> operation function
  |
  v
crate/server/src/core/operations/<op>.rs      — one file per KMIP operation (41 total)
  |
  v
crate/server/src/core/kms/mod.rs              — KMS struct (params, database, crypto_oracles, HSM)
  |
  +-- crate/server_database/                  — object & permission stores
  +-- crate/crypto/                           — cryptographic primitives
```

Enterprise routes also handled:

- `crate/server/src/routes/aws_xks/`   — AWS XKS
- `crate/server/src/routes/azure_ekm/` — Azure EKM
- `crate/server/src/routes/google_cse/` — Google CSE
- `crate/server/src/routes/ms_dke/`    — Microsoft DKE

## Key file map

| Intent | File |
|---|---|
| Add/change a KMIP operation | `crate/server/src/core/operations/<operation>.rs` |
| KMIP operation dispatcher   | `crate/server/src/core/operations/dispatch.rs` |
| KMS struct definition       | `crate/server/src/core/kms/mod.rs` |
| Server config & CLI flags   | `crate/server/src/config/` |
| Server startup sequence     | `crate/server/src/start_kms_server.rs` |
| OpenSSL provider init       | `crate/server/src/openssl_providers.rs` |
| HTTP routes                 | `crate/server/src/routes/` |
| Middlewares (auth, logging) | `crate/server/src/middlewares/` |
| KMIP protocol types         | `crate/kmip/src/` |
| Crypto primitives           | `crate/crypto/src/` |
| OpenSSL build script        | `crate/crypto/build.rs` |
| DB backend implementations  | `crate/server_database/src/` |
| CLI commands                | `crate/clients/ckms/src/` |

## Feature flags

| Flag | Default | Effect |
|---|---|---|
| *(none / fips)* | **on** | FIPS-140-3 mode; only NIST-approved algorithms; loads FIPS provider |
| `non-fips`      | off     | Legacy OpenSSL provider, Covercrypt, Redis-findex, PQC CLI module, AES-XTS |

Use `--features non-fips` to enable all non-approved algorithms.

## OpenSSL handling

**There is no external OpenSSL prerequisite.** OpenSSL 3.6.0 is downloaded, SHA256-verified, and
built from source by `crate/crypto/build.rs` into `target/` on first build. Subsequent builds use
the cache. You do not need to install OpenSSL manually.

At runtime, `crate/server/src/openssl_providers.rs` initializes the correct OpenSSL provider:

- FIPS mode: loads the FIPS provider once via `OnceLock`.
- non-FIPS mode: loads the legacy provider on top of the default provider.

The helper `apply_openssl_dir_env_if_needed()` sets `OPENSSL_MODULES` and `OPENSSL_CONF` in the
process environment before any `Provider::try_load()` call — critical so OpenSSL can locate
`legacy.so` and `fips.so` from the build tree.

## Nix packaging

Deb and RPM packages are built via Nix. Vendor hash files live in `nix/expected-hashes/`.
After updating the package version or `Cargo.lock`, regenerate the vendor hashes:

```bash
# Fake-hash trick: put a wrong hash to get the correct hash from the error output
echo "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" \
  > nix/expected-hashes/server.vendor.dynamic.sha256

# Trigger the build — it will fail and print the correct hash to copy back
.github/scripts/nix.sh --variant non-fips --link dynamic 2>&1 | grep "got:"
```

Repeat for all four combinations (`fips`/`non-fips` × `dynamic`/`static`).

## GitHub issues and pull requests

Read issues and PRs using `gh` without a pager:

```bash
gh issue view <number> --repo Cosmian/kms
gh pr view <number> --repo Cosmian/kms
```

## Coding rules

- Keep functions under 100 lines; refactor larger ones.
- Rust imports must always be at the top of each file.
- Do not ignore or skip errors in tests or package builds — investigate and fix.
- Update `CHANGELOG.md` for every user-visible change (follow the existing entry format).

## Debugging

Run the server with maximum logging when investigating issues:

```bash
RUST_LOG="cosmian_kms_server=trace,cosmian_kms_server_database=trace" \
  cargo run --bin cosmian_kms -- --database-type sqlite --sqlite-path /tmp/kms-data
```

Add the failing crate to `RUST_LOG` if the problem originates elsewhere.

## Docker

```bash
docker pull ghcr.io/cosmian/kms:latest
docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest
# Web UI at http://localhost:9998/ui
```

## Common issues

- **Usage mask errors**: the key does not have the required usage mask (e.g. `Encrypt`, `Sign`).
  Check the `CryptographicUsageMask` attribute on the object.
- **`legacy.so` / `fips.so` not found**: `OPENSSL_MODULES` is not pointing at the built OpenSSL
  modules directory. `apply_openssl_dir_env_if_needed()` in `openssl_providers.rs` should fix this
  automatically; check that it is called before any `Provider::try_load()`.
- **Stale Nix vendor hashes**: after updating `Cargo.lock` or bumping the package version,
  regenerate all four hash files using the fake-hash trick above.

# Cosmian KMS — AI Agent Instructions

> **Canonical file**: `.github/copilot-instructions.md` — `CLAUDE.md` and `AGENTS.md` at the repo root are symlinks to this file. **Always edit this file directly.**

Cosmian KMS is a high-performance, source available **FIPS 140-3** compliant Key
Management System written in **Rust**. It implements **KMIP 2.1** over HTTP/TLS
and supports AES, RSA, EC, ML-KEM, ML-DSA, SLH-DSA, Covercrypt, and more.

---

## Specifications and standards

Always fetch the **latest published version** of any specification before implementing or referencing it. Never rely on a draft, a locally-cached copy, or a version number recalled from memory.

| Standard family | Canonical source |
| --------------- | ---------------- |
| IETF RFCs | `https://www.rfc-editor.org/rfc/rfcXXXX.html` |
| KMIP | OASIS specification pages |
| NIST algorithms & FIPS | `https://csrc.nist.gov/` |
| X.509 / ASN.1 OIDs | `https://oid-rep.orange-labs.fr/` or `https://oidref.com/` |

> **AI agent rule**: when implementing or commenting on cryptographic standards (RFCs, NIST FIPS, KMIP spec), use the `fetch_webpage` tool to retrieve the live document and verify section numbers, OIDs, algorithm identifiers, and normative requirements before writing code or comments. Do **not** rely on training-data knowledge of a specification — always fetch it.

---

## Build & test cheatsheet

```bash
# ── Build ────────────────────────────────────────────────────────────────
cargo build                          # FIPS mode (default)
cargo build --features non-fips      # non-FIPS: extra algorithms, PQC, Covercrypt

# ── Test (cargo aliases defined in .cargo/config.toml) ───────────────────
cargo test-fips                      # test --lib --workspace
cargo test-non-fips                  # test --lib --workspace --features non-fips
cargo test -p cosmian_kms_server     # single crate
cargo test -p cosmian_kms_cli

# ── Lint ─────────────────────────────────────────────────────────────────
cargo clippy-all                     # clippy --workspace --all-targets --all-features -- -D warnings
cargo format                         # fmt --all -- --check

# ── Run locally ──────────────────────────────────────────────────────────
cargo run --bin cosmian_kms -- --database-type sqlite --sqlite-path /tmp/kms-data

# ── Smoke-test (expect 422, not 404) ────────────────────────────────────
curl -s -X POST -H "Content-Type: application/json" -d '{}' http://localhost:9998/kmip/2_1
```

### Cargo aliases (`.cargo/config.toml`)

| Alias           | Expands to                                                       |
| --------------- | ---------------------------------------------------------------- |
| `format`        | `fmt --all -- --check`                                           |
| `build-all`     | `build --workspace --all-targets --all-features --bins`          |
| `test-fips`     | `test --lib --workspace`                                         |
| `test-non-fips` | `test --lib --workspace --features non-fips`                     |
| `clippy-all`    | `clippy --workspace --all-targets --all-features -- -D warnings` |

### Database test environment

Start backends with `docker compose up -d`, then set:

| Variable           | Value                                     |
| ------------------ | ----------------------------------------- |
| `KMS_POSTGRES_URL` | `postgresql://kms:kms@127.0.0.1:5432/kms` |
| `KMS_MYSQL_URL`    | `mysql://kms:kms@localhost:3306/kms`      |
| `KMS_SQLITE_PATH`  | `data/shared`                             |

> MySQL tests are currently disabled in CI.
> Redis-findex tests are skipped in FIPS mode.

### Pre-commit hooks

Never commit without using pre-commit hooks enabled:

```sh
pip install pre-commit conventional-pre-commit
pre-commit install
pre-commit install --install-hooks -t commit-msg
```

Do not ever commit without fixing pre-commit hook errors. Do not use `git commit --no-verify` or the SKIP environment variable to bypass hooks.

---

## Workspace layout

```text
crate/
  access/           cosmian_kms_access         — access-control utilities
  clients/
    clap/           cosmian_kms_cli_actions    — CLI actions library (clap commands)
    client/         cosmian_kms_client         — HTTP client library
    client_utils/   cosmian_kms_client_utils   — shared client helpers
    ckms/           ckms                       — CLI binary (subcommands live here)
    pkcs11/
      module/       cosmian_pkcs11_module      — PKCS#11 module implementation
      provider/     cosmian_pkcs11             — PKCS#11 provider binary
    wasm/           cosmian_kms_client_wasm    — WASM client for the web UI
  crypto/           cosmian_kms_crypto         — crypto primitives; build.rs builds OpenSSL 3.6.0
  hsm/
    base_hsm/       cosmian_kms_base_hsm       — base HSM traits and common code
    softhsm2/       softhsm2_pkcs11_loader     — SoftHSM2
    utimaco/        utimaco_pkcs11_loader      — Utimaco
    proteccio/      proteccio_pkcs11_loader    — Proteccio
    crypt2pay/      crypt2pay_pkcs11_loader    — Crypt2Pay
    smartcardhsm/   smartcardhsm_pkcs11_loader — SmartCard HSM
  interfaces/       cosmian_kms_interfaces     — Database/HSM traits
  kmip/             cosmian_kmip               — KMIP 2.1 protocol types
  kmip-derive/      kmip-derive                — proc-macros for KMIP serialisation
  server/           cosmian_kms_server         — server binary + lib (main codebase)
  server_database/  cosmian_kms_server_database — DB backends (SQLite, PostgreSQL, Redis-findex)
  test_kms_server/  test_kms_server            — in-process test server helper

.github/            CI workflows (.github/workflows/) and helper scripts (.github/scripts/)
cbom/               Cryptographic Bill of Materials (CBOM)
cli_documentation/  CLI-specific MkDocs documentation (separate MkDocs site)
documentation/      MkDocs documentation source
monitoring/         Grafana / Prometheus / OTLP monitoring stack
nix/                Nix build expressions and expected vendor hashes
pkg/                deb/rpm service files and configs
resources/          Server config templates
sbom/               Software Bill of Materials (SBOM)
scripts/            Project scripts
test_data/          Test fixtures (submodule)
ui/                 Web UI source (React + Vite + Playwright E2E tests)
ui_non_fips/        Pre-built non-FIPS web UI bundle (committed)
```

---

## KMIP request flow

```text
HTTP client
  │
  ▼
crate/server/src/routes/kmip.rs               — Actix-web handler, deserialises TTLV
  │
  ▼
crate/server/src/core/operations/dispatch.rs  — matches TTLV tag → operation function
  │
  ▼
crate/server/src/core/operations/<op>.rs      — one file per KMIP operation
  │
  ▼
crate/server/src/core/kms/mod.rs              — KMS struct (params, database, crypto_oracles, HSM)
  │
  ├── crate/server_database/                  — object & permission stores
  └── crate/crypto/                           — cryptographic primitives
```

Enterprise routes:

- `crate/server/src/routes/aws_xks/` — AWS XKS
- `crate/server/src/routes/azure_ekm/` — Azure EKM
- `crate/server/src/routes/google_cse/` — Google CSE
- `crate/server/src/routes/ms_dke/` — Microsoft DKE

You must always verify that changes related to KMIP protocol are compliant with KMIP specifications (HTML files found in crate/kmip/src)

---

## Key file map

| Intent                      | File(s)                                           |
| --------------------------- | ------------------------------------------------- |
| Add/change a KMIP operation | `crate/server/src/core/operations/<operation>.rs` |
| KMIP operation dispatcher   | `crate/server/src/core/operations/dispatch.rs`    |
| KMS struct definition       | `crate/server/src/core/kms/mod.rs`                |
| Server config & CLI flags   | `crate/server/src/config/`                        |
| Server startup              | `crate/server/src/start_kms_server.rs`            |
| OpenSSL provider init       | `crate/server/src/openssl_providers.rs`           |
| HTTP routes                 | `crate/server/src/routes/`                        |
| Middlewares (auth, logging) | `crate/server/src/middlewares/`                   |
| KMIP protocol types         | `crate/kmip/src/`                                 |
| Crypto primitives           | `crate/crypto/src/`                               |
| OpenSSL build script        | `crate/crypto/build.rs`                           |
| DB backend implementations  | `crate/server_database/src/`                      |
| CLI actions (clap commands) | `crate/clients/clap/src/`                         |
| CLI binary entry point      | `crate/clients/ckms/src/`                         |
| WASM bindings               | `crate/clients/wasm/src/`                         |
| Web UI source               | `ui/src/`                                         |
| E2E tests (Playwright)      | `ui/tests/e2e/`                                   |
| E2E test helpers            | `ui/tests/e2e/helpers.ts`                         |

---

## Feature flags

| Flag            | Default | Effect                                                                                       |
| --------------- | ------- | -------------------------------------------------------------------------------------------- |
| *(none / fips)* | **on**  | FIPS-140-3 mode; only NIST-approved algorithms; loads FIPS provider                          |
| `non-fips`      | off     | Legacy OpenSSL provider, Covercrypt, Redis-findex, PQC CLI module, AES-XTS                   |
| `interop`       | **on**  | Enables extra KMIP interoperability test operations (on by default; do not disable in tests) |
| `insecure`      | off     | Skips OAuth token expiration check and allows self-signed TLS — **dev/test only**            |
| `timeout`       | off     | Makes the server binary expire at a compile-time-chosen date                                 |

Use `--features non-fips` to enable all non-approved algorithms.

---

## OpenSSL handling

**No external OpenSSL needed.** OpenSSL 3.6.0 is downloaded, SHA-256-verified,
and built from source by `crate/crypto/build.rs` into `target/` on first build.

At runtime, `crate/server/src/openssl_providers.rs` initialises the correct provider:

- **FIPS**: loads the FIPS provider once via `OnceLock`.
- **non-FIPS**: loads the legacy provider on top of the default provider.

`apply_openssl_dir_env_if_needed()` sets `OPENSSL_MODULES` and `OPENSSL_CONF`
**before** any `Provider::try_load()` call.

---

## CI overview

Do not skip or ignore tests.

### Entry point

All CI runs go through **Nix** via:

```bash
bash .github/scripts/nix.sh [--variant fips|non-fips] [--link static|dynamic] COMMAND [args]
```

### Test types (`nix.sh test <type>`)

| Type            | FIPS?  | Notes                                |
| --------------- | ------ | ------------------------------------ |
| `sqlite`        | yes    | Default DB backend                   |
| `psql`          | yes    | Requires PostgreSQL                  |
| `mysql`         | yes    | Disabled in CI                       |
| `percona`       | yes    | Percona XtraDB                       |
| `mariadb`       | yes    | MariaDB                              |
| `wasm`          | yes    | WASM package build + tests           |
| `google_cse`    | yes    | Requires OAuth creds                 |
| `gcp_cmek`      | yes    | GCP CMEK wrapping                    |
| `otel_export`   | yes    | OpenTelemetry metrics                |
| `hsm [backend]` | yes    | softhsm2 / utimaco / proteccio / all |
| `redis`         | **no** | Redis-findex (non-FIPS only)         |
| `pykmip`        | **no** | PyKMIP + Synology DSM                |
| `aws_xks`       | **no** | AWS XKS                              |
| `azure_ekm`     | **no** | Azure EKM                            |
| `ui`            | **no** | Playwright E2E                       |

---

## Web UI & Playwright E2E tests

**Stack**: React 19 + Vite 7 + Ant Design 5 + Tailwind CSS 4 + Playwright + pnpm

The UI must be seen as a mirror of the `ckms` CLI tool. All features added to the `ckms` CLI tool must be synced on the Web UI.

### Running UI tests

```bash
# Full end-to-end:
bash .github/scripts/nix.sh --variant non-fips test ui

# Manually from ui/:
cd ui && CI=true PLAYWRIGHT_BASE_URL="http://127.0.0.1:5173" pnpm run test:e2e
```

### UI test layers

| Layer       | Runner     | Location                | Config                           |
| ----------- | ---------- | ----------------------- | -------------------------------- |
| E2E         | Playwright | `ui/tests/e2e/`         | `ui/playwright.config.ts`        |
| Integration | Vitest     | `ui/tests/integration/` | `ui/tests/vitest.int.config.ts`  |
| Unit        | Vitest     | `ui/tests/unit/`        | `ui/tests/vitest.unit.config.ts` |

### UI test conventions

- Use `data-testid` attributes to locate elements.
- Ant Design `<Select>` portals render in `document.body`; use the helpers in `helpers.ts`.
- Use regex-based assertions with `toHaveText()` — Playwright's `toHaveText` does not support an `exact` option.
- E2E timeouts are generous (60 s) because CI runs 10 parallel workers against one KMS server.

### UI actions structure

`ui/src/actions/` contains 14 feature modules, each mapping to a group of KMIP operations.
When adding a new UI feature, add it under the matching module (or create a new one):

```text
ui/src/actions/
  Access/         — Grant, List, Obtained, Revoke permissions
  Attributes/     — Delete, Get, Modify, Set object attributes
  Certificates/   — Certify, Decrypt, Encrypt, Export, Import, Validate
  CloudProviders/ — AWS / Azure key export and import (KEK/BYOK)
  Covercrypt/     — Covercrypt encrypt, decrypt, master key, user key
  EC/             — Elliptic Curve key creation, encrypt/decrypt, sign/verify
  Keys/           — CSE info, derive key, export, import, symmetric key creation
  MAC/            — Compute and Verify message authentication codes
  Objects/        — Destroy, list owned, revoke, opaque objects, secret data
  PQC/            — Post-quantum encapsulate/decapsulate, sign/verify
  RSA/            — RSA key creation, encrypt/decrypt, sign/verify
  Symmetric/      — Symmetric encrypt, decrypt, hash
```

Update `ui/tests/e2e/README.md` according to `ui/tests/e2e/` tests.

---

## GitHub CLI

**Always use `GH_PAGER=cat`** to prevent `gh` from spawning an interactive pager. The repository is `Cosmian/kms`.

```bash
GH_PAGER=cat gh issue view <number> --repo Cosmian/kms
GH_PAGER=cat gh pr view <number> --repo Cosmian/kms
GH_PAGER=cat gh pr checks <number> --repo Cosmian/kms
GH_PAGER=cat gh run view <run-id> --repo Cosmian/kms --log-failed
```

---

## Coding rules

- **Function length**: keep functions under 100 lines; extract helpers for longer ones.
- **Imports**: Rust `use` statements go at the top of each file, never inline inside function bodies.
- **Error handling**: use `?` propagation; never use `.unwrap()` in production code; never ignore errors in tests.
- **Feature flags**: gate non-FIPS code with `#[cfg(feature = "non-fips")]` at the function level, not inline inside function bodies.
- **Unsafe code**: avoid unless strictly necessary; every `unsafe` block requires a `// SAFETY:` comment.
- **Clippy**: all code must pass `cargo clippy --workspace --all-targets --all-features -- -D warnings` with zero warnings.
- **Tests**: write unit tests in a `#[cfg(test)]` submodule close to the code they exercise.
- **Documentation**: add `///` doc comments to all public items; internal helpers should explain *why*, not just *what*.
- **Naming**: follow Rust idioms — `snake_case` for functions/variables, `PascalCase` for types, `SCREAMING_SNAKE_CASE` for constants.
- **Logging**: use `trace!` for per-request detail, `debug!` for internal state, `info!` for lifecycle events; `warn!`/`error!` only for operator-actionable problems.
- **CHANGELOG**: update `CHANGELOG/<branch_name_without_slashes>.md` for every user-visible change (see "Updating CHANGELOG.md").
- **Commit scope**: make minimal, focused changes. Don't refactor surrounding code alongside a bug fix.
- **TypeScript (UI)**: `tsconfig.app.json` enforces `strict: true`, `noUnusedLocals: true`, `noUnusedParameters: true`.

### Test vectors synchronization

When adding, removing, or modifying test vectors under `test_data/vectors/`:

1. Update `crate/test_kms_server/README.md` to reflect the current test vector structure.
2. If a new vector directory or manifest is added, register the corresponding test function in `crate/test_kms_server/src/vector_runner.rs`.
3. Keep the README's table/listing in sync with the actual directory tree.

### Server configuration & wizard synchronization

Every field of `ClapConfig` in `crate/server/src/config/command_line/clap_config.rs` (and its sub-structs) **must** have a corresponding configuration step in the server wizard at `crate/server/src/config/wizard/`.

When modifying `ClapConfig` or any of its nested config structs:

1. Add or update the corresponding wizard step in the appropriate `*_wizard.rs` file under `crate/server/src/config/wizard/`.
2. If a new config sub-struct is added, create a new `*_wizard.rs` file and register it in `crate/server/src/config/wizard/mod.rs`.
3. Update `resources/kms.toml` and `crate/server/kms_template.toml` if the field should appear in the reference config.

---

## Updating CHANGELOG.md

> **IMPORTANT — file location**: Changes go in `CHANGELOG/<branch_name_without_slashes>.md`
> (replace `/` with `_` in the branch name, e.g. branch `feature/foo` → `CHANGELOG/feature_foo.md`).
> The **root `CHANGELOG.md` is generated by `git-cliff` and must NEVER be edited manually.**
> If the branch-specific file does not exist yet, create it.

For each change, add a **one-line summary** in the branch-specific file. Use the sections convention: `Features`, `Bug Fixes`, `Build`, `Refactor`, `Documentation`, `Testing`, `CI`, `Security`. Under a section, regroup by sub-feature or component when multiple entries relate to the same area.

Add the GitHub PR or issue link at the EOL: `([#XXX](https://github.com/Cosmian/kms/issues/XXX))`.

Add at the bottom `Closes #xxx` lines as needed to automatically close related issues.

---

## Nix packaging

Deb and RPM packages are built via Nix. Vendor hash files live in `nix/expected-hashes/`.

> **AI agent note — Nix hash mismatch**: When CI reports a hash mismatch, first verify
> that `Cargo.lock` or `ui/pnpm-lock.yaml` actually changed intentionally in this PR.
> If not, revert the lock file. If the dependency change is intentional, retrieve the
> correct hash from the CI log (`got: sha256-...`) and update `nix/expected-hashes/`.

---

## Documentation synchronization rules

When making user-visible changes, keep documentation synchronized:

- `documentation/docs/` contains the detailed, canonical documentation.
- `documentation/mkdocs.yml` is the navigation and structure source of truth.
- `README.md` is a concise summary and entry point only.

Required behavior:

1. If a feature is added or behavior is changed, add or update detailed docs under `documentation/docs/`.
2. Update `documentation/mkdocs.yml` so the new/updated page appears in the correct section.
3. Update `README.md` with a brief summary and links to the detailed docs.
4. Keep `README.md` TOC and section naming aligned with `documentation/mkdocs.yml` top-level structure.
5. Avoid duplicating full documentation in `README.md`.

### Integration documentation alignment

**Source of truth for navigation structure**: `documentation/mkdocs.yml`

When adding a new integration:

1. Add the doc file under the correct `documentation/docs/integrations/` subdirectory.
2. Add the nav entry in `documentation/mkdocs.yml` under the correct group.
3. Add a row to the matching README table with a correct relative link starting with `./documentation/docs/integrations/...`.
4. Never put an integration in a different category in README than it appears in mkdocs.yml.

# Cosmian KMS — AI Agent Instructions

> **Canonical file**: `.github/copilot-instructions.md` — `CLAUDE.md` and `AGENTS.md` at the repo root are symlinks to this file. **Always edit this file directly.**

Cosmian KMS is a high-performance, source available **FIPS 140-3** compliant Key
Management System written in **Rust**. It implements **KMIP 1.x and 2.x** over HTTP/TLS
and supports AES, RSA, EC, ML-KEM, ML-DSA, SLH-DSA, Covercrypt, and more.

---

## Specifications and standards

Always fetch the **latest published version** of any specification before implementing or referencing it. Never rely on a draft, a locally-cached copy, or a version number recalled from memory.

| Standard family        | Canonical source                                           |
| ---------------------- | ---------------------------------------------------------- |
| IETF RFCs              | `https://www.rfc-editor.org/rfc/rfcXXXX.html`              |
| KMIP                   | OASIS specification pages                                  |
| NIST algorithms & FIPS | `https://csrc.nist.gov/`                                   |
| X.509 / ASN.1 OIDs     | `https://oid-rep.orange-labs.fr/` or `https://oidref.com/` |

> **AI agent rule — mandatory**: Before writing ANY code or comment that references a cryptographic standard, use the `fetch_webpage` tool to retrieve the live document. Verify section numbers, OIDs, algorithm identifiers, and normative requirements directly from the source. Do **not** rely on training-data knowledge of a specification — always fetch it.

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
  crypto/           cosmian_kms_crypto         — crypto primitives; build.rs builds OpenSSL 3.6.2
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

KMIP specifications are in ./kmip git submodule.

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
| _(none / fips)_ | **on**  | FIPS-140-3 mode; only NIST-approved algorithms; loads FIPS provider                          |
| `non-fips`      | off     | Legacy OpenSSL provider, Covercrypt, Redis-findex, PQC CLI module, AES-XTS                   |
| `interop`       | **on**  | Enables extra KMIP interoperability test operations (on by default; do not disable in tests) |
| `insecure`      | off     | Skips OAuth token expiration check and allows self-signed TLS — **dev/test only**            |
| `timeout`       | off     | Makes the server binary expire at a compile-time-chosen date                                 |

Use `--features non-fips` to enable all non-approved algorithms.

---

## OpenSSL handling

**No external OpenSSL needed.** OpenSSL 3.6.2 is downloaded, SHA-256-verified,
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

`ui/src/actions/` contains 16 feature modules, each mapping to a group of KMIP operations or REST endpoints.
When adding a new UI feature, add it under the matching module (or create a new one):

```text
ui/src/actions/
  Access/         — Grant, List, Obtained, Revoke permissions
  Attributes/     — Delete, Get, Modify, Set object attributes
  Certificates/   — Certify, Decrypt, Encrypt, Export, Import, Validate
  CloudProviders/ — AWS / Azure key export and import (KEK/BYOK)
  Covercrypt/     — Covercrypt encrypt, decrypt, master key, user key
  EC/             — Elliptic Curve key creation, encrypt/decrypt, sign/verify
  FPE/            — Format Preserving Encryption key creation, encrypt/decrypt (non-FIPS)
  Keys/           — CSE info, derive key, export, import, symmetric key creation
  MAC/            — Compute and Verify message authentication codes
  Objects/        — Destroy, list owned, revoke, opaque objects, secret data
  PQC/            — Post-quantum encapsulate/decapsulate, sign/verify
  RSA/            — RSA key creation, encrypt/decrypt, sign/verify
  Symmetric/      — Symmetric encrypt, decrypt, hash
  Tokenize/       — Anonymization: hash, noise, word mask/tokenize, aggregation, scaling (non-FIPS)
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

## Mandatory per-prompt checklist

After **every** code-changing prompt, execute the following steps **in order** before declaring done. Do not skip any step, and do not ask the user whether to run them — run them unconditionally.

### 0. Follow Coding rules

### 1. CHANGELOG update (always)

Determine the current branch: `git branch --show-current`.
Write a one-line entry to `CHANGELOG/<branch_name_with_slashes_replaced_by_underscores>.md`.
Create the file if it does not exist. Use the section convention: `Features`, `Bug Fixes`,
`Refactor`, `Testing`, `Security`, `Documentation`. Add a PR/issue link when known.

### 2. Test vector (for every behavioral change)

For every new feature, bug fix, or behavioral guard added:

1. Add a test vector under `test_data/vectors/` that directly exercises the new behavior.
   - Negative tests → `test_data/vectors/negative/`.
   - HSM-specific tests → `test_data/vectors/hsm/`.
2. Register the new vector in `crate/test_kms_server/src/vector_runner.rs`.
3. Run `cargo test -p test_kms_server <test_fn_name>` and confirm it passes.
4. Update `crate/test_kms_server/README.md`: add the new vector to the table and update the total vector count at the top of the table.

### 3. Clippy and format (always)

```bash
cargo clippy-all   # clippy --workspace --all-targets --all-features -- -D warnings
```

Fix every warning reported. Do not suppress with `#[allow]` unless there is a documented,
irreducible reason — and then add an inline comment explaining why.

Do not miss the reformat using:

```bash
cargo fmt --all
```

### 4. Tests (always)

Verify if non-regression vectors (test_data/vectors) are up-to-date and if relevant, add non-regression vectors to always improve the coverage.

```bash
cargo test-non-fips   # test --lib --workspace --features non-fips
```

Fix every failing test. Never skip or mark tests as `#[ignore]` to make the suite green.

### 5. Documentation (when behavior or user interface changes)

If the prompt adds or changes a user-visible feature, flag, endpoint, or configuration option:

- Update or add a page under `documentation/docs/`.
- Register the page in `documentation/mkdocs.yml`.
- Update `README.md` with a brief summary and link (no full duplication).

### 6. Update SECURITY.md on security-related changes (when applicable)

If the prompt adds a new security feature, hardens an existing one, or fixes a security bug, update `SECURITY.md` with a brief summary of the change and its impact on users. Link to the relevant CHANGELOG entry and test vector.

### 7. List of synchronization rules (when applicable)

#### 7.1 Server SPA routes ↔ React Router ↔ Menu items

When adding or renaming a UI feature path:

1. **`crate/server/src/start_kms_server.rs`** — add the top-level path pattern to the `spa_routes` array (e.g. `"/fpe{_:.*}"`). Without this, browser refreshes on deep links return 404.
2. **`ui/src/App.tsx`** — add nested `<Route path="..." element={<Component />} />` declarations.
3. **`ui/src/menuItems.tsx`** — add or update the `baseMenu` entry; the `key` field must match the route path prefix (e.g. `"fpe"`).

#### 7.2 Server REST endpoints ↔ OpenAPI ↔ Route registration

When adding or modifying a REST endpoint:

1. **`crate/server/src/routes/<module>/`** — implement the handler(s).
2. **`crate/server/src/routes/mod.rs`** — declare `pub mod <module>;`.
3. **`crate/server/src/start_kms_server.rs`** — import the module, create a `web::scope(...)` or `.service(...)`, and register with the Actix `App`. Apply the correct middleware stack (Cors → auth extractors → EnsureAuth; remember LIFO order).
4. **`crate/server/documentation/openapi.yaml`** — add or update the path, request/response schemas, and tags.
5. Use crate/test_kms_server/src/openapi_validation.rs tests to validate changes on Swagger/OpenAPI side.

#### 7.3 KMIP operations: types → dispatch → implementation

When adding a new KMIP operation:

1. **`crate/kmip/src/kmip_2_1/kmip_operations.rs`** — define request/response types and add the variant to the `Operation` enum.
2. **`crate/server/src/core/operations/dispatch.rs`** — add the match arm routing the tag to the handler function.
3. **`crate/server/src/core/operations/<operation>.rs`** — implement the handler (create the file and register it in `mod.rs`).

#### 7.4 CLI ↔ Web UI feature parity

The `ckms` CLI and the Web UI must mirror each other:

1. **`crate/clients/clap/src/actions/<module>/`** — CLI action implementation.
2. **`crate/clients/ckms/src/commands.rs`** — register the new subcommand in `CliCommands` enum.
3. **`ui/src/actions/<Module>/`** — create corresponding React component(s).
4. **`ui/src/App.tsx`** — import the component and add `<Route>` entry.
5. **`ui/src/menuItems.tsx`** — add menu item.
6. **`crate/server/src/start_kms_server.rs`** — add SPA route if new top-level path.

In addition, for each ckms subcommands changes, add corresponding tests on ckms in crate/clients/ckms/src/tests.

#### 7.5 WASM bindings ↔ Web UI

When the UI needs a new KMIP request builder or response parser:

1. **`crate/clients/wasm/src/wasm.rs`** — add `#[wasm_bindgen]` exported function (e.g. `create_fpe_key_ttlv_request`).
2. **`ui/src/wasm/pkg/`** — rebuild with `wasm-pack build --target web` (auto-generates TS types).
3. **UI component** — import and call the new WASM function.

#### 7.6 Server configuration ↔ Wizard ↔ TOML templates

When modifying `ClapConfig` or its sub-structs:

1. **`crate/server/src/config/command_line/clap_config.rs`** — struct field with `#[clap(...)]`.
2. **`crate/server/src/config/wizard/<*>_wizard.rs`** — add/update the corresponding interactive step. If a new sub-struct is added, create a new wizard file and register in `wizard/mod.rs`.
3. **`resources/kms.toml`** — update the reference config.
4. **`crate/server/kms_template.toml`** — update the template included in tarballs.
5. **`pkg/kms.toml`** — update the service deployment config.

#### 7.7 Server wizard ↔ Client wizard

When the server wizard (`crate/server/src/config/wizard/`) changes:

- Keep `crate/clients/client/src/config.rs` (client config struct) consistent so the client can serialize/deserialize settings the server now expects.

#### 7.8 Feature flags: non-FIPS gating across the stack

When implementing a non-FIPS-only feature:

1. **Server implementation** — `#[cfg(feature = "non-fips")]` at function/module level.
2. **`crate/server/src/start_kms_server.rs`** — scope registration wrapped in `#[cfg(feature = "non-fips")] { ... }`.
3. **`crate/server/src/core/operations/dispatch.rs`** — dispatch arm gated if needed.
4. **CLI actions** — `#[cfg(feature = "non-fips")]` on module or function.
5. **WASM bindings** — `#[cfg(feature = "non-fips")]` on exported function.
6. **UI** — hide menu items/routes when FIPS mode is active (check `branding` or `FIPS_MODE` env var).
7. **E2E tests** — `test.skip(FIPS_MODE, "...")` in Playwright specs.
8. **Test vectors** — place in `test_data/vectors/non-fips/` or gate runner with `#[cfg(feature = "non-fips")]`.

#### 7.9 Authentication middleware consistency

When adding or modifying an auth method:

1. **Config struct** — `crate/server/src/config/` (e.g. `IdpAuthConfig`).
2. **Wizard step** — `crate/server/src/config/wizard/auth_wizard.rs`.
3. **Middleware** — `crate/server/src/middlewares/` (e.g. `JwtAuth`, `TlsAuth`, `ApiTokenAuth`).
4. **All scopes** — every authenticated scope in `start_kms_server.rs` must wrap the new middleware with `Condition::new(use_<auth>, <Middleware>)`.
5. **`EnsureAuth::new`** — the `auth_is_configured` boolean must be `use_jwt_auth || use_cert_auth || use_api_token_auth` for every scope (except mTLS-only scopes like Azure EKM).

#### 7.10 Test vectors: directory → runner → README

For every feature or bug fix:

1. **`test_data/vectors/<category>/<vector_name>/`** — create directory with `manifest.toml` and TTLV-JSON step files.
2. **`crate/test_kms_server/src/vector_runner.rs`** — add `#[tokio::test]` function.
3. **`crate/test_kms_server/README.md`** — add row to the table and update the total count.

#### 7.11 Nix vendor hashes ↔ lock files

When `Cargo.lock` or `ui/pnpm-lock.yaml` change:

- Update the corresponding files in `nix/expected-hashes/` with the correct `sha256-...` hash from CI output.
- Hash files: `server.vendor.{static,dynamic}.sha256`, `cli.vendor.{static,dynamic}.{darwin,linux}.sha256`, `ui.vendor.{fips,non-fips}.sha256`, `ui.pnpm.{darwin,linux}.sha256`.

#### 7.12 Cloud provider integrations

When adding AWS XKS / Azure EKM / Google CSE / MS DKE support:

1. **Config** — struct in `crate/server/src/config/`.
2. **Wizard** — step in `crate/server/src/config/wizard/advanced_wizard.rs`.
3. **Routes** — module in `crate/server/src/routes/<provider>/`, declared in `routes/mod.rs`.
4. **Scope registration** — `start_kms_server.rs` with correct auth middleware.
5. **OpenAPI** — `crate/server/documentation/openapi.yaml`.
6. **CLI actions** — `crate/clients/clap/src/actions/<provider>/`.
7. **UI actions** — `ui/src/actions/CloudProviders/`.

#### 7.13 HSM backend support

When adding a new HSM model:

1. **PKCS#11 loader crate** — `crate/hsm/<model>/`.
2. **HSM model enum** — `crate/server/src/config/` (or `crate/hsm/base_hsm/`).
3. **Wizard** — `crate/server/src/config/wizard/hsm_wizard.rs`.
4. **Test vectors** — `test_data/vectors/hsm/<model>/`.
5. **CI** — add matrix entry in `.github/workflows/test_all.yml`.

#### 7.14 Documentation ↔ mkdocs ↔ README

When behaviour or user interface changes:

1. **`documentation/docs/`** — add or update the relevant `.md` page.
2. **`documentation/mkdocs.yml`** — add the nav entry under the correct section.
3. **`README.md`** — add a brief summary with a link (no full duplication).
4. **`cli_documentation/docs/`** — if CLI-visible, run `ckms markdown` to regenerate.

#### 7.15 CLI documentation auto-generation

When CLI commands or flags change:

- Run `cargo run --bin ckms -- markdown cli_documentation/docs/main_commands.md` to regenerate.
- Commit the regenerated file — manual edits will be overwritten.

#### 7.16 E2E test documentation

When Playwright E2E tests are added or removed:

- Update `ui/tests/e2e/README.md` to reflect the current spec files, FIPS-skip table, and test coverage.

#### 7.17 OpenSSL version updates

When upgrading OpenSSL:

1. **`crate/crypto/build.rs`** — update version, download URL, and SHA-256 hash.
2. **`crate/server/src/openssl_providers.rs`** — verify provider init is compatible.
3. **`cbom/cbom.cdx.json`** — update the Cryptographic Bill of Materials.
4. **`sbom/`** — update the Software Bill of Materials.

> These previous steps are **not optional suggestions**. They are part of every response that
> touches code. An incomplete response is one that skips any of them.

---

## Coding rules

- **Function length**: try to keep functions under 50 lines unless it's more relevant to go longer; extract helpers for longer ones.
- **Clones**: avoid unnecessary clones; prefer references and borrowing.
- **Use Rust Generics and Traits** to abstract over common patterns and avoid code duplication.
- **Use Rust macros** to eliminate boilerplate, especially for repetitive match blocks and trait implementations.
- **Imports**: Rust `use` statements go at the top of each file, never inline inside function bodies.
- **Error handling**: use `?` propagation; never use `.unwrap()` in production code; never ignore errors in tests.
- **Feature flags**: gate non-FIPS code with `#[cfg(feature = "non-fips")]` at the function level, not inline inside function bodies.
- **Unsafe code**: avoid unless strictly necessary; every `unsafe` block requires a `// SAFETY:` comment.
- **Live database/backend tests**: when working on a feature that requires a live backend, run `docker compose up -d` from the repository root (services available: `postgres` :5432, `mysql` :3306, `percona` :3307, `mariadb` :3308, `redis` :6379, `otel-collector` :4317/4318/8889). Start only what's needed with `docker compose up -d <service>`. If the command fails or Docker is unavailable, inform the user.
- **Clippy**: all code must pass `cargo clippy --workspace --all-targets --all-features -- -D warnings` with zero warnings.
- **Tests**: write unit tests in a `#[cfg(test)]` submodule close to the code they exercise.
- **Documentation**: add `///` doc comments to all public items; internal helpers should explain _why_, not just _what_.
- **Naming**: follow Rust idioms — `snake_case` for functions/variables, `PascalCase` for types, `SCREAMING_SNAKE_CASE` for constants.
- **Logging**: use `trace!` for per-request detail, `debug!` for internal state, `info!` for lifecycle events; `warn!`/`error!` only for operator-actionable problems.
- **CHANGELOG**: update `CHANGELOG/<branch_name_without_slashes>.md` for every user-visible change (see "Updating CHANGELOG.md").
- **Commit scope**: make minimal, focused changes. Don't refactor surrounding code alongside a bug fix.
- **TypeScript (UI)**: `tsconfig.app.json` enforces `strict: true`, `noUnusedLocals: true`, `noUnusedParameters: true`.

### Test vectors

For every feature added or bug fixed, a test vector **must** be added to `test_data/vectors/` **unless** one the following conditions is met:
- The behavior being tested is not observable in a KMIP HTTP response (e.g., metric emission, in-process state changes).
- The new vector would exercise the same KMIP operations already covered by existing vectors,
  just with a new name to "document" a feature, without catching a regression that no
  other vector would catch.
- The vector will always pass regardless of weather the new feature works.

If none of these apply, the vector **must** be added as follows :
1. Model the vector on existing examples in `test_data/vectors/`.
2. Register the corresponding test function in `crate/test_kms_server/src/vector_runner.rs`.
3. Run the test and confirm it passes: `cargo test -p test_kms_server <fn_name>`.
4. Update `crate/test_kms_server/README.md` to keep the table in sync with the directory tree.

### Server configuration & wizard synchronization

Every field of `ClapConfig` in `crate/server/src/config/command_line/clap_config.rs` (and its sub-structs) **must** have a corresponding configuration step in the server wizard at `crate/server/src/config/wizard/`.

When modifying `ClapConfig` or any of its nested config structs:

1. Add or update the corresponding wizard step in the appropriate `*_wizard.rs` file under `crate/server/src/config/wizard/`.
2. If a new config sub-struct is added, create a new `*_wizard.rs` file and register it in `crate/server/src/config/wizard/mod.rs`.
3. Update `resources/kms.toml` and `crate/server/kms_template.toml` if the field should appear in the reference config.

---

## Updating CHANGELOG.md

> **IMPORTANT — mandatory on every code-changing prompt. Do not skip.**
> File location: `CHANGELOG/<branch_name_without_slashes>.md`
> (replace `/` with `_`, e.g. branch `feature/foo` → `CHANGELOG/feature_foo.md`).
> The **root `CHANGELOG.md` is generated by `git-cliff` and must NEVER be edited manually.**
> Create the branch-specific file if it does not exist yet.
> Determine the branch name by running `git branch --show-current` — never guess.

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

# Cosmian KMS — AI Agent Instructions

## 1. Repository high level view

> **Canonical file**: `AGENTS.md` (or `CLAUDE.md` which is a symlink to this file) explains project structure, build commands, CI workflows, coding conventions, and troubleshooting steps.

Cosmian KMS is a high-performance, source available **FIPS 140-3** compliant Key
Management System written in **Rust**. It implements **KMIP 2.1 and 1.4** over HTTP/TLS
and supports AES, RSA, EC, ML-KEM, ML-DSA, SLH-DSA, Covercrypt, and more.

---

## 2. Build, test, and local run

### Build & test cheatsheet

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
cargo format                         # fmt --all -- --check (check-only; exits non-zero if files need reformatting, makes no changes)
cargo fmt --all                      # apply formatting (actually rewrites files — use this in the workflow)

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

---

## 3. Repository map


### Workspace layout

```text
crate/
  access/           cosmian_kms_access         — access-control utilities
  clients/
    clap/           cosmian_kms_cli_actions    — CLI actions library (clap commands)
    client/         cosmian_kms_client         — HTTP client library
    client_utils/   cosmian_kms_client_utils   — shared client helpers
    ckms/           ckms                       — CLI binary (subcommands live here)
    pkcs11/
      loader/       cosmian_pkcs11_verify      — diagnostic binary to verify PKCS#11 module loadability
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
```

---

### KMIP request flow

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

### Key file map

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

### Feature flags

| Flag            | Default | Effect                                                                                       |
| --------------- | ------- | -------------------------------------------------------------------------------------------- |
| _(none / fips)_ | **on**  | FIPS-140-3 mode; only NIST-approved algorithms; loads FIPS provider                          |
| `non-fips`      | off     | Legacy OpenSSL provider, Covercrypt, Redis-findex, PQC CLI module, AES-XTS                   |
| `interop`       | **on**  | Enables extra KMIP interoperability test operations (on by default; do not disable in tests) |
| `insecure`      | off     | Skips OAuth token expiration check and allows self-signed TLS — **dev/test only**            |
| `timeout`       | off     | Makes the server binary expire at a compile-time-chosen date                                 |

Use `--features non-fips` to enable all non-approved algorithms.

---

## 4. Coding rules

- **Function length**: Keep functions under 50 lines. Exceptions are permitted only when: (a) the function is a straight-line state machine or match dispatch that cannot be meaningfully split, or (b) splitting would require passing more than 5 parameters to helpers. In all other cases, extract helpers.
- **Clones**: avoid unnecessary clones; prefer references and borrowing.
- **Use Rust Generics and Traits** to abstract over common patterns and avoid code duplication.
- **Use Rust macros** to eliminate boilerplate, especially for repetitive match blocks and trait implementations.
- **Imports**: Rust `use` statements go at the top of each file, never inline inside function bodies.
- **Error handling**: use `?` propagation; never use `.unwrap()` in production code; never ignore errors in tests.
- **Feature flags**: gate non-FIPS code with `#[cfg(feature = "non-fips")]` at the function level, not inline inside function bodies.
- **Unsafe code**: avoid unless strictly necessary; every `unsafe` block requires a `// SAFETY:` comment.
- **Clippy**: all code must pass `cargo clippy --workspace --all-targets --all-features -- -D warnings` with zero warnings. 
- **Clippy `#[allow]` policy**: follow this decision tree for every new `#[allow(clippy::...)]`:
  1. **Can it and SHOULD IT be fixed?** → Fix it. No allow needed.
  2. **Cannot be fixed, but there is a code-specific reason to keep it** (e.g. variable names
     mandated by a spec, an inherently lossy conversion with a proven safe invariant) →
     Keep the allow and add a precise inline comment on the same or next line explaining
     **why** the lint cannot be satisfied and why the code is correct despite it.
  3. **Cannot be decided** → Report the undecided lint to the user with the exact warning text and location, in the prompt's report.
- **Tests**: write unit tests in a `#[cfg(test)]` submodule close to the code they exercise.
- **Documentation**: add `///` doc comments to all public items; internal helpers should explain _why_, not just _what_.
- **Naming**: follow Rust idioms — `snake_case` for functions/variables, `PascalCase` for types, `SCREAMING_SNAKE_CASE` for constants.
- **Logging**: use `trace!` for per-request detail, `debug!` for internal state, `info!` for lifecycle events; `warn!`/`error!` only for operator-actionable problems.
- **Commit scope**: make minimal, focused changes. Don't refactor surrounding code alongside a bug fix.
- **TypeScript (UI)**: `tsconfig.app.json` enforces `strict: true`, `noUnusedLocals: true`, `noUnusedParameters: true`.
- **Live database/backend tests**: when working on a feature that requires a live backend, run docker compose up -d from the repository root (services available: postgres :5432, mysql :3306, percona :3307, mariadb :3308, redis :6379, otel-collector :4317/4318/8889). Start only what's needed with docker compose up -d <service>. If the command fails or Docker is unavailable, inform the user.

---

## 5. Execution workflow

After **every** code-changing prompt, execute the following steps **in order** before declaring done. Do not skip any step, and do not ask the user whether to run them — run them unconditionally.

### 1. Tests (always)

Run only the tests that directly exercise the changed code. Never run the full test suite unless the feature is fully developed and a global sanity check is needed. When code changes affect only a certain scope, target that scope.

```bash
# Example: running tests after editing Redis backend's behavior
docker compose up -d
cargo test -p cosmian_kms_server_database --features non-fips test_db_redis_with_findex
```

Fix every failing test. Never skip or mark tests as `#[ignore]` to make the suite green.

### 2. Test vector (for every behavioral change)

For every new feature, bug fix, or behavioral guard added:

1. Add a test vector under `test_data/vectors/` that directly exercises the new behavior.
   - Negative tests → `test_data/vectors/negative/`.
   - HSM-specific tests → `test_data/vectors/hsm/`.
2. Register the new vector in `crate/test_kms_server/src/vector_runner.rs`.
3. Run `cargo test -p test_kms_server <test_fn_name>` and confirm it passes.
4. Update `crate/test_kms_server/README.md`: add the new vector to the table and update the total vector count at the top of the table.

Skip this step only if the change is purely refactoring with no behavioral difference (i.e., all existing test vectors still pass unchanged and no new observable output is produced). In all other cases, add a vector. Do not add test vectors that duplicate what existing vectors already cover with no additional code involved.

### 3. Clippy and formatting (always)

```bash
cargo clippy-all   # clippy --workspace --all-targets --all-features -- -D warnings
```

Fix every warning reported. Do not suppress with `#[allow]` unless there is a documented,
irreducible reason — and then add an inline comment explaining why.

Do not miss the reformat using:

```bash
cargo fmt --all
```


### 4. Apply synchronization rules (consult the trigger table below)

Scan the table to identify which sub-rules apply to your task, then execute only those sub-rules.

| Task type | Sub-rules to apply |
|---|---|
| New/modified KMIP operation | 4.3, 4.10 |
| New/modified REST endpoint | 4.2, 4.10 |
| New/modified CLI command/flag | 4.4, 4.15 |
| New/modified UI feature | 4.1, 4.4, 4.5 (if WASM needed) |
| Non-FIPS-only feature | 4.8 |
| Auth method change | 4.9 |
| Server config/wizard change | 4.6, 4.7 |
| Cloud provider integration | 4.12 |
| HSM backend | 4.13 |
| Documentation/behavior change | 4.14 |
| Playwright E2E test change | 4.16 |
| OpenSSL upgrade | 4.17 |
| `Cargo.lock` or `pnpm-lock.yaml` change | 4.11 |

#### 4.1 Server SPA routes ⇔ React Router ⇔ Menu items

When adding or renaming a UI feature path:

1. **`crate/server/src/start_kms_server.rs`** — add the top-level path pattern to the `spa_routes` array (e.g. `"/fpe{_:.*}"`). Without this, browser refreshes on deep links return 404.
2. **`ui/src/App.tsx`** — add nested `<Route path="..." element={<Component />} />` declarations.
3. **`ui/src/menuItems.tsx`** — add or update the `baseMenu` entry; the `key` field must match the route path prefix (e.g. `"fpe"`).

#### 4.2 Server REST endpoints ⇔ OpenAPI ⇔ Route registration

When adding or modifying a REST endpoint:

1. **`crate/server/src/routes/<module>/`** — implement the handler(s).
2. **`crate/server/src/routes/mod.rs`** — declare `pub mod <module>;`.
3. **`crate/server/src/start_kms_server.rs`** — import the module, create a `web::scope(...)` or `.service(...)`, and register with the Actix `App`. Apply the correct middleware stack (Cors → auth extractors → EnsureAuth; remember LIFO order).
4. **`crate/server/documentation/openapi.yaml`** — add or update the path, request/response schemas, and tags.
5. Use crate/test_kms_server/src/openapi_validation.rs tests to validate changes on Swagger/OpenAPI side.

#### 4.3 KMIP operations: types → dispatch → implementation

When adding a new KMIP operation:

1. **`crate/kmip/src/kmip_2_1/kmip_operations.rs`** — define request/response types and add the variant to the `Operation` enum.
2. **`crate/server/src/core/operations/dispatch.rs`** — add the match arm routing the tag to the handler function.
3. **`crate/server/src/core/operations/<operation>.rs`** — implement the handler (create the file and register it in `mod.rs`).

#### 4.4 CLI ⇔ Web UI feature parity

The `ckms` CLI and the Web UI must mirror each other:

1. **`crate/clients/clap/src/actions/<module>/`** — CLI action implementation.
2. **`crate/clients/ckms/src/commands.rs`** — register the new subcommand in `CliCommands` enum.
3. **`ui/src/actions/<Module>/`** — create corresponding React component(s).
4. **`ui/src/App.tsx`** — import the component and add `<Route>` entry.
5. **`ui/src/menuItems.tsx`** — add menu item.
6. **`crate/server/src/start_kms_server.rs`** — add SPA route if new top-level path.

In addition, for each ckms subcommands changes, add corresponding tests on ckms in crate/clients/ckms/src/tests.

#### 4.5 WASM bindings ⇔ Web UI

When the UI needs a new KMIP request builder or response parser:

1. **`crate/clients/wasm/src/wasm.rs`** — add `#[wasm_bindgen]` exported function (e.g. `create_fpe_key_ttlv_request`).
2. **`ui/src/wasm/pkg/`** — rebuild with `wasm-pack build --target web` (auto-generates TS types).
   > If `wasm-pack` is not installed or the build fails, do not proceed with UI changes. Report the error to the user and install with: `cargo install wasm-pack`.
3. **UI component** — import and call the new WASM function.

#### 4.6 Server configuration ⇔ Wizard ⇔ TOML templates

When modifying `ClapConfig` or its sub-structs:

1. **`crate/server/src/config/command_line/clap_config.rs`** — struct field with `#[clap(...)]`.
2. **`crate/server/src/config/wizard/<*>_wizard.rs`** — add/update the corresponding interactive step. If a new sub-struct is added, create a new wizard file and register in `wizard/mod.rs`.
3. **`resources/kms.toml`** — update the reference config.
4. **`crate/server/kms_template.toml`** — update the template included in tarballs.
5. **`pkg/kms.toml`** — update the service deployment config.

#### 4.7 Server wizard ⇔ Client wizard

When the server wizard (`crate/server/src/config/wizard/`) changes:

- Keep `crate/clients/client/src/config.rs` (client config struct) consistent so the client can serialize/deserialize settings the server now expects.

#### 4.8 Feature flags: non-FIPS gating across the stack

When implementing a non-FIPS-only feature:

1. **Server implementation** — `#[cfg(feature = "non-fips")]` at function/module level.
2. **`crate/server/src/start_kms_server.rs`** — scope registration wrapped in `#[cfg(feature = "non-fips")] { ... }`.
3. **`crate/server/src/core/operations/dispatch.rs`** — dispatch arm gated if needed.
4. **CLI actions** — `#[cfg(feature = "non-fips")]` on module or function.
5. **WASM bindings** — `#[cfg(feature = "non-fips")]` on exported function.
6. **UI** — hide menu items/routes when FIPS mode is active (check `branding` or `FIPS_MODE` env var).
7. **E2E tests** — `test.skip(FIPS_MODE, "...")` in Playwright specs.
8. **Test vectors** — place in `test_data/vectors/non-fips/` or gate runner with `#[cfg(feature = "non-fips")]`.

#### 4.9 Authentication middleware consistency

When adding or modifying an auth method:

1. **Config struct** — `crate/server/src/config/` (e.g. `IdpAuthConfig`).
2. **Wizard step** — `crate/server/src/config/wizard/auth_wizard.rs`.
3. **Middleware** — `crate/server/src/middlewares/` (e.g. `JwtAuth`, `TlsAuth`, `ApiTokenAuth`).
4. **All scopes** — every authenticated scope in `start_kms_server.rs` must wrap the new middleware with `Condition::new(use_<auth>, <Middleware>)`.
5. **`EnsureAuth::new`** — the `auth_is_configured` boolean must be `use_jwt_auth || use_cert_auth || use_api_token_auth` for every scope (except mTLS-only scopes like Azure EKM).

#### 4.10 Test vectors: directory → runner → README

For every feature or bug fix:

1. **`test_data/vectors/<category>/<vector_name>/`** — create directory with `manifest.toml` and TTLV-JSON step files.
2. **`crate/test_kms_server/src/vector_runner.rs`** — add `#[tokio::test]` function.
3. **`crate/test_kms_server/README.md`** — add row to the table and update the total count.

#### 4.11 Nix vendor hashes ⇔ lock files

When `Cargo.lock` or `ui/pnpm-lock.yaml` change:

- Update the corresponding files in `nix/expected-hashes/` with the correct `sha256-...` hash from CI output.
- Hash files: `server.vendor.{static,dynamic}.sha256`, `cli.vendor.{static,dynamic}.{darwin,linux}.sha256`, `ui.vendor.{fips,non-fips}.sha256`, `ui.pnpm.{darwin,linux}.sha256`.

#### 4.12 Cloud provider integrations

When adding AWS XKS / Azure EKM / Google CSE / MS DKE support:

1. **Config** — struct in `crate/server/src/config/`.
2. **Wizard** — step in `crate/server/src/config/wizard/advanced_wizard.rs`.
3. **Routes** — module in `crate/server/src/routes/<provider>/`, declared in `routes/mod.rs`.
4. **Scope registration** — `start_kms_server.rs` with correct auth middleware.
5. **OpenAPI** — `crate/server/documentation/openapi.yaml`.
6. **CLI actions** — `crate/clients/clap/src/actions/<provider>/`.
7. **UI actions** — `ui/src/actions/CloudProviders/`.

#### 4.13 HSM backend support

When adding a new HSM model:

1. **PKCS#11 loader crate** — `crate/hsm/<model>/`.
2. **HSM model enum** — `crate/server/src/config/` (or `crate/hsm/base_hsm/`).
3. **Wizard** — `crate/server/src/config/wizard/hsm_wizard.rs`.
4. **Test vectors** — `test_data/vectors/hsm/<model>/`.
5. **CI** — add matrix entry in `.github/workflows/test_all.yml`.

#### 4.14 Documentation ⇔ mkdocs ⇔ README

When behaviour or user interface changes:

1. **`documentation/docs/`** — add or update the relevant `.md` page.
2. **`documentation/mkdocs.yml`** — add the nav entry under the correct section.
3. **`README.md`** — add a brief summary with a link (no full duplication).
4. **`cli_documentation/docs/`** — if CLI-visible, run `ckms markdown` to regenerate.

#### 4.15 CLI documentation auto-generation

When CLI commands or flags change:

- Run `cargo run --bin ckms -- markdown cli_documentation/docs/main_commands.md` to regenerate.
- Commit the regenerated file — manual edits will be overwritten.

#### 4.16 E2E test documentation

When Playwright E2E tests are added or removed:

- Update `ui/tests/e2e/README.md` to reflect the current spec files, FIPS-skip table, and test coverage.

#### 4.17 OpenSSL version updates

When upgrading OpenSSL:

1. **`crate/crypto/build.rs`** — update version, download URL, and SHA-256 hash.
2. **`crate/server/src/openssl_providers.rs`** — verify provider init is compatible.
3. **`cbom/cbom.cdx.json`** — update the Cryptographic Bill of Materials.
4. **`sbom/`** — update the Software Bill of Materials.

> These previous steps are **not optional suggestions**. They are part of every response that
> touches code. An incomplete response is one that skips any of them.

### 5. Update SECURITY.md on security-related changes (when applicable)
If the prompt adds a new security feature, hardens an existing one, or fixes a security bug, update SECURITY.md with a brief summary of the change and its impact on users. Link to the relevant CHANGELOG entry and test vector.

### 6. Post-task self-review

#### When to run this

- After completing each task or subtask in a multi-step plan.
- If the diff is >200 lines OR touches >2 files.
- Before marking **the last** todo item as "completed".

#### Checklist

If any answer is "yes", fix it before finishing.

1. **Scope audit** — _"Did I change any file or code path that is not strictly required
   by the task I was asked to perform?"_
   Compare each modified file against the task description. Remove any change that was
   not requested and is not a direct, necessary consequence of the requested change.

2. **Security-posture delta** — _"Did any change widen the attack surface compared to
   the codebase before my changes ? Did any change cause a vulnerability ? Did I enform the user of any compromise or security concern that is in this code ?"

3. **Feature-flag consistency** — _"Are my additions gated behind the same feature
   flags as the surrounding code?"_

4. **Diff review** — Run `git diff --stat` and `git diff` before declaring done.
   Every hunk must be explainable by the task. If a hunk surprises you, investigate
   and revert if it is not justified.

### 7. Updating CHANGELOG.md

> File location: `CHANGELOG/<branch_name_without_slashes>.md`
> (replace `/` with `_`, e.g. branch `feature/foo` → `CHANGELOG/feature_foo.md`).
> The **root `CHANGELOG.md` is generated by `git-cliff` and must NEVER be edited manually.**
> Create the branch-specific file if it does not exist yet.
> Determine the branch name by running `git branch --show-current` — never guess.

Update CHANGELOG/<branch_name_without_slashes>.md only when the change is high-level and worth a release note, such as a new feature, a user-visible behavior change, a bug fix, a security change, a compatibility change, or a significant refactor that materially affects users or operators. Skip changelog entries for routine implementation work, local cleanup, formatting, minor refactors, and test-only changes unless they affect observable behavior. Use the sections convention: `Features`, `Bug Fixes`, `Build`, `Refactor`, `Documentation`, `Testing`, `CI`, `Security`. Under a section, regroup by sub-feature or component when multiple entries relate to the same area.

**Decision rule**: If the change alters any of: public API signatures, CLI flags/output, config file keys, default behavior, supported algorithms, or error messages visible to operators — write a changelog entry. Otherwise skip.

If appliable and the feature's code is complete, add the GitHub PR or issue link at the EOL: `([#XXX](https://github.com/Cosmian/kms/issues/XXX))`. Add at the bottom `Closes #xxx` lines as needed to automatically close related issues.

---

## 6. Documentation guidelines

### Documentation (when behavior or user interface changes)

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


### Technical examples: sourcing rule

Source technical examples in strict priority:

1. **Copy-paste from test `assert_eq!` (or similar) in codebase** (highest priority)
2. **Live KMS output** launch a debug instance and use it to produce the result
3. **Mathematically derived** (applies only for deteministed operations)
4. **User-provided** 

**If none applies**: Leave example blank with placeholder `"<result>"` and report to user: "Example not sourced — could not find test assertion, live KMS output, derivation, or user value for: [description]".

**Never invent examples**.

### Integration documentation alignment

**Source of truth for navigation structure**: `documentation/mkdocs.yml`

When adding a new integration:

1. Add the doc file under the correct `documentation/docs/integrations/` subdirectory.
2. Add the nav entry in `documentation/mkdocs.yml` under the correct group.
3. Add a row to the matching README table with a correct relative link starting with `./documentation/docs/integrations/...`.
4. Never put an integration in a different category in README than it appears in mkdocs.yml.

### Specifications and standards

When implementing a **new algorithm, OID, or protocol feature**, verify identifiers and normative requirements against the canonical source before writing code. Do not rely on training-data recall for section numbers, OIDs, or algorithm identifiers — use the documents the user provides, fetch the document using `fetch_webpage` tool or ask the user about the matter. If you need to fetch a specification, use: rfc-editor.org for IETF RFCs, the OASIS specification pages for KMIP, csrc.nist.gov for NIST/FIPS algorithms, and oidref.com for X.509/ASN.1 OIDs.

---

## 7. Operational reference

### 7.1 UI-specific rules

**Stack**: React 19 + Vite 7 + Ant Design 5 + Tailwind CSS 4 + Playwright + pnpm

The UI must be seen as a mirror of the `ckms` CLI tool. All features added to the `ckms` CLI tool must be synced on the Web UI.

#### Running UI tests

```bash
# Full end-to-end:
bash .github/scripts/nix.sh --variant non-fips test ui

# Manually from ui/:
cd ui && CI=true PLAYWRIGHT_BASE_URL="http://127.0.0.1:5173" pnpm run test:e2e
```

#### UI test layers

| Layer       | Runner     | Location                | Config                           |
| ----------- | ---------- | ----------------------- | -------------------------------- |
| E2E         | Playwright | `ui/tests/e2e/`         | `ui/playwright.config.ts`        |
| Integration | Vitest     | `ui/tests/integration/` | `ui/tests/vitest.int.config.ts`  |
| Unit        | Vitest     | `ui/tests/unit/`        | `ui/tests/vitest.unit.config.ts` |

#### UI test conventions

- Use `data-testid` attributes to locate elements.
- Ant Design `<Select>` portals render in `document.body`; use the helpers in `helpers.ts`.
- Use regex-based assertions with `toHaveText()` — Playwright's `toHaveText` does not support an `exact` option.
- E2E timeouts are generous (60 s) because CI runs 10 parallel workers against one KMS server.

#### UI actions structure

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

### 7.2 CI and packaging

#### Entry point

All CI runs go through **Nix** via:

```bash
bash .github/scripts/nix.sh [--variant fips|non-fips] [--link static|dynamic] COMMAND [args]
```

#### Test types (`nix.sh test <type>`)

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

### 7.3 OpenSSL handling

**No external OpenSSL needed.** OpenSSL 3.6.0 is downloaded, SHA-256-verified,
and built from source by `crate/crypto/build.rs` into `target/` on first build.

At runtime, `crate/server/src/openssl_providers.rs` initialises the correct provider:

- **FIPS**: loads the FIPS provider once via `OnceLock`.
- **non-FIPS**: loads the legacy provider on top of the default provider.

`apply_openssl_dir_env_if_needed()` sets `OPENSSL_MODULES` and `OPENSSL_CONF`
**before** any `Provider::try_load()` call.

---

### 7.4 Debugging and common issues

- Enable the adequate level of tracing for a more verbose output, example:
```bash
RUST_LOG="cosmian_kms_server=trace,cosmian_kms_server_database=trace" \
  cargo run --bin cosmian_kms -- --database-type sqlite --sqlite-path /tmp/kms-data
```
Add the failing crate to `RUST_LOG` if the problem originates elsewhere.
- **During debugging**: whenever you add temporary code (a log, a hardcoded value, a
relaxed auth/CORS/TLS config, a test-only endpoint), mark it immediately with a comment:
`// TODO: debug — remove before shipping`. This makes residue findable at a glance.
- When working on some feature, run the tests that actually use that feature or (if no direct test) are the most related - Do not run the full test suite to check if a certain new addition is correct.

### 7.5 GitHub CLI usage

**Always use `GH_PAGER=cat`** to prevent `gh` from spawning an interactive pager. The repository is `Cosmian/kms`.

```bash
GH_PAGER=cat gh issue view <number> --repo Cosmian/kms
GH_PAGER=cat gh pr view <number> --repo Cosmian/kms
GH_PAGER=cat gh pr checks <number> --repo Cosmian/kms
GH_PAGER=cat gh run view <run-id> --repo Cosmian/kms --log-failed
```

### 7.6 Nix packaging

Deb and RPM packages are built via Nix. Vendor hash files live in `nix/expected-hashes/`.

> **AI agent note — Nix hash mismatch**: When CI reports a hash mismatch, first verify
> that `Cargo.lock` or `ui/pnpm-lock.yaml` actually changed intentionally in this PR.
> If not, revert the lock file. If the dependency change is intentional, retrieve the
> correct hash from the CI log (`got: sha256-...`) and update `nix/expected-hashes/`.

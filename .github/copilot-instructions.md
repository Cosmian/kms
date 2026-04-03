# Cosmian KMS — AI Agent Instructions

> **Purpose of this file**: This is the single source of truth for any AI agent
> (Copilot, Cursor, Cline, etc.) working on the Cosmian KMS codebase. It
> explains project structure, build commands, CI workflows, coding conventions,
> and troubleshooting steps so the agent can act autonomously and correctly.

Cosmian KMS is a high-performance, source available **FIPS 140-3** compliant Key
Management System written in **Rust**. It implements **KMIP 2.1** over HTTP/TLS
and supports AES, RSA, EC, ML-KEM, ML-DSA, SLH-DSA, Covercrypt, and more.

---

## 1. Build & test cheatsheet

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

| Alias | Expands to |
|---|---|
| `format` | `fmt --all -- --check` |
| `build-all` | `build --workspace --all-targets --all-features --bins` |
| `test-fips` | `test --lib --workspace` |
| `test-non-fips` | `test --lib --workspace --features non-fips` |
| `clippy-all` | `clippy --workspace --all-targets --all-features -- -D warnings` |

### Database test environment

Start backends with `docker compose up -d`, then set:

| Variable | Value |
|---|---|
| `KMS_POSTGRES_URL` | `postgresql://kms:kms@127.0.0.1:5432/kms` |
| `KMS_MYSQL_URL` | `mysql://kms:kms@localhost:3306/kms` |
| `KMS_SQLITE_PATH` | `data/shared` |

> MySQL tests are currently disabled in CI.
> Redis-findex tests are skipped in FIPS mode.

### Pre-commit hooks

Never commit without using pre-commit hooks enabled:

```sh
pip install pre-commit conventional-pre-commit
pre-commit install
pre-commit install --install-hooks -t commit-msg
```

Do not ever commit without fixing pre-commit hook errors. If the hooks are failing, investigate and fix the underlying issue instead of bypassing them. Do not use `git commit --no-verify` or similar options to skip hooks. The hooks are there to maintain code quality and consistency, and bypassing them can lead to issues in the codebase. Always address the root cause of any hook failures before committing your changes.

Do not use either SKIP environment variable to bypass pre-commit hooks.

---

## 2. Workspace layout

```text
crate/
  access/           cosmian_kms_access         — access-control utilities
  cli/              cosmian_kms_cli            — CLI client binary
  clients/
    ckms/           ckms                       — CLI command tree (subcommands live here)
    pkcs11/                                    — PKCS#11 client
  client_utils/     cosmian_kms_client_utils   — shared client helpers
  crypto/           cosmian_kms_crypto         — crypto primitives; build.rs builds OpenSSL 3.6.0
  hsm/              HSM PKCS#11 loaders (softhsm2, utimaco, proteccio, crypt2pay, smartcardhsm)
  interfaces/       cosmian_kms_interfaces     — Database/HSM traits
  kmip/             cosmian_kmip               — KMIP 2.1 protocol types
  kmip-derive/      kmip-derive                — proc-macros for KMIP serialisation
  kms_client/       cosmian_kms_client         — HTTP client library
  server/           cosmian_kms_server         — server binary + lib (main codebase)
  server_database/  cosmian_kms_server_database — DB backends (SQLite, PostgreSQL, Redis-findex)
  test_kms_server/  test_kms_server            — in-process test server helper
  wasm/             cosmian_kms_client_wasm    — WASM client for the web UI

.github/            CI workflows (.github/workflows/) and helper scripts (.github/scripts/)
documentation/      MkDocs documentation source
nix/                Nix build expressions and expected vendor hashes
pkg/                deb/rpm service files and configs
resources/          Server config templates
test_data/          Test fixtures (submodule)
ui/                 Web UI source (React + Vite + Playwright E2E tests)
ui_non_fips/        Pre-built non-FIPS web UI bundle (committed)
```

---

## 3. KMIP request flow

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
crate/server/src/core/operations/<op>.rs      — one file per KMIP operation (41 total)
  │
  ▼
crate/server/src/core/kms/mod.rs              — KMS struct (params, database, crypto_oracles, HSM)
  │
  ├── crate/server_database/                  — object & permission stores
  └── crate/crypto/                           — cryptographic primitives
```

Enterprise routes:

- `crate/server/src/routes/aws_xks/`   — AWS XKS
- `crate/server/src/routes/azure_ekm/` — Azure EKM
- `crate/server/src/routes/google_cse/` — Google CSE
- `crate/server/src/routes/ms_dke/`    — Microsoft DKE

You must always verify that changes related to KMIP protocol are compliant with KMIP specifications (HTML files found in crate/kmip/src)

---

## 4. Key file map

When you need to change something, start here:

| Intent | File(s) |
|---|---|
| Add/change a KMIP operation | `crate/server/src/core/operations/<operation>.rs` |
| KMIP operation dispatcher | `crate/server/src/core/operations/dispatch.rs` |
| KMS struct definition | `crate/server/src/core/kms/mod.rs` |
| Server config & CLI flags | `crate/server/src/config/` |
| Server startup | `crate/server/src/start_kms_server.rs` |
| OpenSSL provider init | `crate/server/src/openssl_providers.rs` |
| HTTP routes | `crate/server/src/routes/` |
| Middlewares (auth, logging) | `crate/server/src/middlewares/` |
| KMIP protocol types | `crate/kmip/src/` |
| Crypto primitives | `crate/crypto/src/` |
| OpenSSL build script | `crate/crypto/build.rs` |
| DB backend implementations | `crate/server_database/src/` |
| CLI commands | `crate/clients/ckms/src/` |
| WASM bindings | `crate/wasm/src/` |
| Web UI source | `ui/src/` |
| E2E tests (Playwright) | `ui/tests/e2e/` |
| E2E test helpers | `ui/tests/e2e/helpers.ts` |

---

## 5. Feature flags

| Flag | Default | Effect |
|---|---|---|
| *(none / fips)* | **on** | FIPS-140-3 mode; only NIST-approved algorithms; loads FIPS provider |
| `non-fips` | off | Legacy OpenSSL provider, Covercrypt, Redis-findex, PQC CLI module, AES-XTS |

Use `--features non-fips` to enable all non-approved algorithms.

---

## 6. OpenSSL handling

**No external OpenSSL needed.** OpenSSL 3.6.0 is downloaded, SHA-256-verified,
and built from source by `crate/crypto/build.rs` into `target/` on first build.
Subsequent builds use the cached artefact.

At runtime, `crate/server/src/openssl_providers.rs` initialises the correct provider:

- **FIPS**: loads the FIPS provider once via `OnceLock`.
- **non-FIPS**: loads the legacy provider on top of the default provider.

`apply_openssl_dir_env_if_needed()` sets `OPENSSL_MODULES` and `OPENSSL_CONF` in
the process environment **before** any `Provider::try_load()` call — critical so
OpenSSL can locate `legacy.so` / `fips.so` from the build tree.

---

## 7. CI overview

As pre-requisite, do not skip or ignore tests

### Entry point

All CI runs go through **Nix** via a single script:

```bash
bash .github/scripts/nix.sh [--variant fips|non-fips] [--link static|dynamic] COMMAND [args]
```

### Test types (`nix.sh test <type>`)

| Type | FIPS? | Script | Notes |
|---|---|---|---|
| `sqlite` | yes | `test_sqlite.sh` | Default DB backend |
| `psql` | yes | `test_psql.sh` | Requires PostgreSQL |
| `mysql` | yes | `test_mysql.sh` | Disabled in CI |
| `percona` | yes | `test_percona.sh` | Percona XtraDB |
| `mariadb` | yes | `test_maria.sh` | MariaDB |
| `wasm` | yes | `test_wasm.sh` | WASM package build + tests |
| `google_cse` | yes | `test_google_cse.sh` | Requires OAuth creds |
| `gcp_cmek` | yes | `test_gcp_cmek.sh` | GCP CMEK wrapping |
| `otel_export` | yes | `test_otel_export.sh` | OpenTelemetry metrics |
| `hsm [backend]` | yes | `test_hsm_*.sh` | softhsm2 / utimaco / proteccio / all |
| `redis` | **no** | `test_redis.sh` | Redis-findex (non-FIPS only) |
| `pykmip` | **no** | `test_pykmip.sh` | PyKMIP + Synology DSM |
| `aws_xks` | **no** | `aws_xks_test.sh` | AWS XKS |
| `azure_ekm` | **no** | `azure_ekm_test.sh` | Azure EKM |
| `ui` | **no** | `test_ui.sh` | Playwright E2E (see §8) |

### Package types (`nix.sh package [type]`)

`deb`, `rpm`, `dmg` — or omit the type to build all packages for the current platform.

### Docker (`nix.sh docker`)

```bash
bash .github/scripts/nix.sh docker --variant non-fips --load --test
```

### Workflow files

| Workflow | Purpose |
|---|---|
| `main.yml` → `main_base.yml` | Push/PR trigger; runs clippy, cargo-deny, cargo-test, test_all, docs |
| `test_all.yml` | Nix-based test matrix: 15 types × 2 variants + HSM matrix |
| `packaging.yml` | Multi-platform packaging (Linux/ARM/macOS), GPG-signed |
| `packaging-docker.yml` | Docker image builds (fips + non-fips) |
| `test_windows.yml` | Windows-only build + test |
| `build_windows.yml` | Windows server + UI builder |

---

## 8. Web UI & Playwright E2E tests

**Stack**: React 19 + Vite 7 + Ant Design 5 + Tailwind CSS 4 + Playwright + pnpm

The UI must be seen as a mirror of the `ckms` CLI tool. All features added to the `ckms` CLI tool or development must be synced on the Web UI.

### Running UI tests

```bash
# Full end-to-end (builds WASM, UI, starts KMS + Vite, runs Playwright):
bash .github/scripts/nix.sh --variant non-fips test ui

# Alternative: manually from ui/ after building WASM + UI:
cd ui && CI=true PLAYWRIGHT_BASE_URL="http://127.0.0.1:5173" pnpm run test:e2e
```

### E2E test flow (`test_ui.sh`)

1. Build WASM: `wasm-pack build --target web --features non-fips`
2. Copy `crate/wasm/pkg/` → `ui/src/wasm/pkg/`
3. Install deps: `pnpm install --frozen-lockfile`
4. Build UI: `VITE_KMS_URL=http://127.0.0.1:9998 pnpm run build` (runs `tsc -b && vite build`)
5. Install Playwright browser: `pnpm exec playwright install chromium`
6. Start KMS server on port 9998 (SQLite, non-fips features)
7. Start Vite preview on port 5173
8. Run Playwright: `PLAYWRIGHT_WORKERS=10 pnpm run test:e2e`
9. Parse KMS server logs for ERROR/WARN and report

Update ui/tests/e2e/README.md according to ui/tests/e2e/ tests.

### Key UI test files

- `ui/playwright.config.ts` — Playwright config (workers, retries, base URL)
- `ui/tests/e2e/helpers.ts` — shared test helpers (navigation, form submission, Ant Design select interactions)
- `ui/tests/e2e/*.spec.ts` — test specs grouped by feature
- `ui/tsconfig.node.json` — TypeScript config for Playwright / Vite config files
- `ui/tsconfig.app.json` — TypeScript config for the React app (`noUnusedLocals: true`, `strict: true`)

### UI test conventions

- Use `data-testid` attributes to locate elements (e.g. `[data-testid="submit-btn"]`).
- Ant Design `<Select>` portals render in `document.body`; use the helpers in `helpers.ts` to interact with them.
- Use regex-based assertions (not `{ exact: true }`) with `toHaveText()` — Playwright's `toHaveText` does not support an `exact` option.
- E2E timeouts are generous (60 s for responses) because CI runs 10 parallel workers against one KMS server.

---

## 9. GitHub CLI — reading issues, PRs, and CI failures

**Always use `GH_PAGER=cat`** to prevent `gh` from spawning an interactive pager
(which hangs in non-interactive terminal sessions):

```bash
# View an issue
GH_PAGER=cat gh issue view <number> --repo Cosmian/kms

# View a pull request (description, status checks, review state)
GH_PAGER=cat gh pr view <number> --repo Cosmian/kms

# View PR diff
GH_PAGER=cat gh pr diff <number> --repo Cosmian/kms

# List recent PR checks / CI status
GH_PAGER=cat gh pr checks <number> --repo Cosmian/kms

# View a specific CI run's logs (find run ID from `gh pr checks` output)
GH_PAGER=cat gh run view <run-id> --repo Cosmian/kms --log-failed

# List recent workflow runs
GH_PAGER=cat gh run list --repo Cosmian/kms --limit 10

# Read CI failure logs for a specific job
GH_PAGER=cat gh run view <run-id> --repo Cosmian/kms --job <job-id> --log
```

### Investigating a CI failure — step by step

1. **Get the failing checks**: `GH_PAGER=cat gh pr checks <pr-number> --repo Cosmian/kms`
2. **Find the failed run ID** from the output (look for ✗ / fail status).
3. **Read failed logs**: `GH_PAGER=cat gh run view <run-id> --repo Cosmian/kms --log-failed`
4. **Identify the root cause** in the log output (compiler error, test assertion, timeout, etc.).
5. **Reproduce locally** using the matching `nix.sh` command, e.g.:
   `bash .github/scripts/nix.sh --variant non-fips test sqlite`
6. **Fix, commit, push** — CI will re-run automatically on the PR.

---

## 10. Coding rules

- **Function length**: keep functions under 100 lines; extract helpers for longer ones.
- **Imports**: Rust `use` statements go at the top of each file, never inline.
- **Error handling**: never ignore or skip errors in tests or builds — investigate and fix.
- **CHANGELOG**: update `CHANGELOG.md` for every user-visible change. Add a single-line entry
  in the top section (the next-release block). Follow the formatting and style of existing entries.
- **Commit scope**: make minimal, focused changes. Don't refactor surrounding code or add
  unrelated improvements alongside a bug fix.
- **TypeScript (UI)**: `tsconfig.app.json` enforces `strict: true`, `noUnusedLocals: true`,
  `noUnusedParameters: true`. Fix all type errors before committing UI changes.

---

## 11. Updating CHANGELOG.md

For each change, add a **one-line summary** in `CHANGELOG/<branch_name_without_slashes>.md` that will be committed (replace in branch name `/` with `_`), except if the change is already described in it. Use the formatting style of existing entries and respect the existing sections convention (Features, Bug Fixes, Build, Refactor, Documentation, Testing, CI, Security). Under a CHANGELOG section, try regrouping by sub-feature or component if multiple entries relate to the same area (e.g. "KMIP operations", "Web UI", "PostgreSQL backend"). This helps maintain readability as the number of entries grows.

In addition, add when possible the GitHub PR or GitHub issue related and add on this CHANGELOG.md item at the EOL a link like this ([#XXX](https://github.com/Cosmian/kms/issues/XXX)) or ([#XXX](https://github.com/Cosmian/kms/pull/XXX)).

Finally, add at bottom of the file if not already exists, the as many "Closes #xxx" it requires to automatically close the related issues when the PR is merged.

---

## 12. Debugging

### Server logging

```bash
RUST_LOG="cosmian_kms_server=trace,cosmian_kms_server_database=trace" \
  cargo run --bin cosmian_kms -- --database-type sqlite --sqlite-path /tmp/kms-data
```

Add the failing crate to `RUST_LOG` if the problem originates elsewhere.

### Docker

```bash
docker pull ghcr.io/cosmian/kms:latest
docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest
# Web UI at http://localhost:9998/ui
```

---

## 13. Nix packaging

Deb and RPM packages are built via Nix. Vendor hash files live in `nix/expected-hashes/`.
After updating the package version or `Cargo.lock`, regenerate the vendor hashes:

```bash
# Fake-hash trick: put a wrong hash to get the correct hash from the error output
echo "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" \
  > nix/expected-hashes/server.vendor.dynamic.sha256

# Trigger the build — it will fail and print the correct hash; copy it back
.github/scripts/nix.sh --variant non-fips --link dynamic 2>&1 | grep "got:"
```

Repeat for all four combinations (`fips`/`non-fips` × `dynamic`/`static`).

---

## 14. Common issues

| Symptom | Cause | Fix |
|---|---|---|
| Usage mask errors (`Encrypt`, `Sign` denied) | Key missing required `CryptographicUsageMask` | Check the object's attributes |
| `legacy.so` / `fips.so` not found | `OPENSSL_MODULES` not set | Ensure `apply_openssl_dir_env_if_needed()` in `openssl_providers.rs` is called before `Provider::try_load()` |
| Stale Nix vendor hashes | `Cargo.lock` or version changed | Regenerate all four hash files (see §13) |
| `gh` command hangs | Interactive pager opened | Use `GH_PAGER=cat gh ...` |
| Playwright `toHaveText` type error with `exact` | Unsupported option in Playwright | Use anchored regex instead: `toHaveText(/^\s*Label\s*$/)` |
| TypeScript unused-variable error in UI tests | `noUnusedLocals: true` in tsconfig | Remove the variable or prefix with `_` |

---

## 15. Documentation synchronization rules

When making user-visible changes, keep documentation synchronized across these three sources:

- `documentation/docs/` contains the detailed, canonical documentation.
- `documentation/mkdocs.yml` is the navigation and structure source of truth.
- `README.md` is a concise summary and entry point only.

Required behavior for any AI agent:

1. If a feature is added or behavior is changed, add or update detailed docs under `documentation/docs/`.
2. Update `documentation/mkdocs.yml` so the new/updated page appears in the correct section.
3. Update `README.md` with a brief summary (not full details) and links to the detailed docs.
4. Keep `README.md` TOC and section naming aligned with `documentation/mkdocs.yml` top-level structure.
5. Avoid duplicating full documentation in `README.md`; keep README content short and navigational.

### Integration documentation alignment rules

The integrations section is the most commonly extended area. Keep these four views in sync at all times:

**Source of truth for navigation structure**: `documentation/mkdocs.yml`

**Canonical integration file paths**:

- Cloud providers: `documentation/docs/integrations/cloud_providers/<provider>/`
    - AWS: `cloud_providers/aws/` (xks.md, byok.md, fargate.md)
    - Azure: `cloud_providers/azure/` (ekm.md, byok.md)
    - GCP: `cloud_providers/google_gcp/` (cmek.md, csek.md)
    - Google Workspace CSE: `cloud_providers/google_workspace_client_side_encryption_cse/`
    - Microsoft 365 DKE: `cloud_providers/microsoft_365_double_key_encryption_dke/`
- Databases: `documentation/docs/integrations/databases/`
    - mongodb.md, mysql.md, percona.md, ms_sql_server.md, oracle_tde.md, snowflake_native_app/
- Storage: `documentation/docs/integrations/storage/`
    - vcenter.md, synology_dsm.md, veeam.md, user_defined_function_for_pyspark_databricks_in_python/
    - Disk encryption: `documentation/docs/integrations/disk_encryption/`
        - veracrypt.md, luks.md, cryhod.md
- Other: `documentation/docs/integrations/`
    - openssh.md, pykmip.md, smime.md

**README.md `## 🔗 Integrations` section categories must mirror mkdocs.yml exactly:**

| README section | mkdocs.yml grouping | Files location |
|---|---|---|
| ☁️ Cloud Provider — External Key Management | `Cloud providers:` | `integrations/cloud_providers/` |
| 🗄️ Database Integrations | `Databases:` | `integrations/databases/` |
| 💿 Disk Encryption | `Disk encryption:` (under `Storage:`) | `integrations/disk_encryption/` |
| 💾 Storage Integrations | `Storage:` | `integrations/storage/` |
| 🔗 Other Integrations | `Other:` | `integrations/` root |

**When adding a new integration**:

1. Add the doc file under the correct `documentation/docs/integrations/` subdirectory.
2. Add the nav entry in `documentation/mkdocs.yml` under the correct group.
3. Add a row to the matching README table with a correct relative link starting with `./documentation/docs/integrations/...`.
4. README links must use the full path relative to repo root (e.g. `./documentation/docs/integrations/databases/ms_sql_server.md`), not shortened or incorrect paths.

**documentation/docs/index.md** should not be updated with new integrations; it is a high-level overview and the README is the main entry point for users to discover integrations.

**Never** put an integration in a different category in README than it appears in mkdocs.yml, or leave it out of the README table if it has a mkdocs page.

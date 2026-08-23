# Eviden KMS — AI Agent Instructions

## 1. Repository high level view

> **Instruction files** ([official docs](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/add-custom-instructions/add-repository-instructions)):
>
> - `AGENTS.md` / `CLAUDE.md` — **agent instructions**: read by GitHub Copilot agent, Claude, Deepseek, Qwen, and generic agents when performing autonomous tasks. Contains the full project reference.
> - `.github/copilot-instructions.md` — **repository-wide instructions**: a concise summary injected into every GitHub Copilot Chat request. Keep it short (≤2 pages).
> - `.github/instructions/*.instructions.md` — **per-file coding rules**: automatically applied by agents when editing matching files (see `applyTo` in each file's YAML frontmatter).
>
> These are separate files. When changing project-wide rules, update both `AGENTS.md` and `.github/copilot-instructions.md`.

### Per-file instruction files index

The following files in `.github/instructions/` are automatically applied by agents when editing matching file types:

| File | `applyTo` | Covers |
|------|-----------|--------|
| `rust.instructions.md` | `**/*.rs` | Core Rust rules (errors, unsafe, Clippy, tests, docs) |
| `rust-server.instructions.md` | `crate/server/**/*.rs` | KMIP operations, routes, middleware |
| `rust-crypto.instructions.md` | `crate/crypto/**/*.rs` | FIPS-approved algorithms, OpenSSL provider |
| `rust-kmip.instructions.md` | `crate/kmip/**/*.rs` | KMIP 2.1 protocol types and serialisation |
| `rust-database.instructions.md` | `crate/server_database/**/*.rs` | SQLite, PostgreSQL, Redis-findex backends |
| `database-tables.instructions.md` | `crate/server_database/src/stores/sql/*.sql` | Keep `documentation/docs/configuration/database/tables.md` in sync with SQL schema changes |
| `ui-routes.instructions.md` | `ui/src/App.tsx`, `ui/src/menuItems.tsx`, `ui/src/actions/**/*.tsx`, `ui/src/pages/**/*.tsx` | Sync rule 4.1 — server SPA routes ⇔ React Router ⇔ menu items |
| `routes.instructions.md` | `crate/server/src/routes/**/*.rs` | Sync rule 4.2 — REST endpoint handlers ⇔ OpenAPI ⇔ route registration |
| `kmip-operations.instructions.md` | `crate/kmip/src/**/*.rs`, `crate/server/src/core/operations/**/*.rs` | Sync rule 4.3 — KMIP operation types ⇔ dispatcher ⇔ handler |
| `cli-ui-sync.instructions.md` | `crate/clients/clap/**/*.rs`, `crate/clients/ckms/**/*.rs`, `ui/src/actions/**/*.ts`, `ui/src/actions/**/*.tsx` | Sync rules 4.4 + 4.15 — CLI ⇔ Web UI parity, CLI doc regeneration |
| `wasm.instructions.md` | `crate/clients/wasm/**/*.rs` | Sync rule 4.5 — WASM exports ⇔ regenerated TS types ⇔ UI consumers |
| `server-config.instructions.md` | `crate/server/src/config/**/*.rs` | Sync rules 4.6 + 4.7 — clap flags ⇔ wizard ⇔ TOML templates ⇔ client wizard |
| `middlewares.instructions.md` | `crate/server/src/middlewares/**/*.rs`, `crate/server/src/config/wizard/auth_wizard.rs` | Sync rule 4.9 — auth config ⇔ wizard ⇔ middleware ⇔ scope wiring |
| `test-vectors.instructions.md` | `test_data/vectors/**`, `crate/test_kms_server/**/*.rs` | Sync rule 4.10 — test vector directory ⇔ runner ⇔ README |
| `lockfile-hashes.instructions.md` | `Cargo.lock`, `ui/pnpm-lock.yaml` | Sync rule 4.11 — Nix vendor hashes ⇔ lock files |
| `cloud-providers.instructions.md` | `crate/server/src/routes/aws_xks/**`, `azure_ekm/**`, `google_cse/**`, `ms_dke/**` | Sync rule 4.12 — cloud provider routes ⇔ config ⇔ wizard ⇔ CLI ⇔ UI |
| `hsm.instructions.md` | `crate/hsm/**/*.rs` | Sync rule 4.13 — PKCS#11 loader ⇔ HSM model enum ⇔ wizard ⇔ test vectors ⇔ CI matrix |
| `openssl-build.instructions.md` | `crate/crypto/build.rs` | Sync rule 4.17 — OpenSSL build script ⇔ provider init ⇔ CBOM/SBOM |
| `rust-cli.instructions.md` | `crate/clients/**/*.rs` | CLI actions, WASM bindings, PKCS#11 |
| `typescript-ui.instructions.md` | `ui/src/**/*.{ts,tsx}` | React 19, Ant Design 5, Tailwind 4, WASM |
| `i18n.instructions.md` | `ui/src/i18n/**/*.{ts,json}` | Locale bundles, en/zh-CN parity, useTranslation/Trans |
| `playwright.instructions.md` | `ui/tests/e2e/**/*.ts` | Playwright E2E test conventions; sync rule 4.16 — E2E test documentation |
| `bash.instructions.md` | `**/*.sh` | Shell scripts, MISE tasks, reusable scripts |
| `mise.instructions.md` | `.mise/**, scripts/**, .github/reusable_scripts/**` | MISE task headers, lib usage, variant flags |
| `github-actions.instructions.md` | `.github/workflows/**, .github/actions/**` | CI/CD YAML conventions |
| `toml.instructions.md` | `**/*.toml` | Cargo.toml, workspace, config TOML |
| `python.instructions.md` | `**/*.py` | Documentation scripts, test helpers |
| `markdown.instructions.md` | `**/*.md` | README, CHANGELOG, skill/instruction docs |
| `docs.instructions.md` | `documentation/**/*.md`, `README.md` | mdBook site (Diátaxis framework); sync rule 4.14 — documentation ⇔ mdBook ⇔ README |
| `nix.instructions.md` | `nix/**/*.nix` | Nix build expressions, vendor hashes |
| `docker.instructions.md` | `nix/docker.nix, nix/k8s-images.nix, .mise/scripts/docker-compose.yml, .mise/scripts/test/test_docker_image.sh, .mise/lib/k8s.sh, .mise/tasks/build/docker, .mise/tasks/test/docker, .mise/tasks/test/k8s/**, charts/cosmian-kms/**/*` | Docker image build/test (Nix), docker-compose, Helm chart, Kubernetes helpers |

Eviden KMS is a high-performance, source available **FIPS 140-3** compliant Key
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

### Pre-commit hooks

Never commit without using pre-commit hooks enabled:

```bash
pip install pre-commit conventional-pre-commit
pre-commit install
pre-commit install --install-hooks -t commit-msg
```

Do not ever commit without fixing pre-commit hook errors. Do not use git commit --no-verify or the SKIP environment variable to bypass hooks.

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

.github/            CI workflows (.github/workflows/) and helper scripts
.mise/              MISE tasks and scripts (single source of truth for all automation)
cbom/               Cryptographic Bill of Materials (CBOM)
documentation/docs/kms_clients/  CLI documentation (integrated into main docs)
documentation/      mdBook documentation source
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

**Cardinal rules** — non-negotiable, apply to every change:

- **No `.unwrap()`** in production code. Use `?` propagation everywhere; never ignore errors in tests.
- **No inline feature gating**: `#[cfg(feature = "non-fips")]` goes at the function or module level, never inside a function body.
- **Unsafe code**: every `unsafe` block requires a `// SAFETY:` comment explaining the invariant that makes it sound.
- **Clippy**: zero warnings (`cargo clippy-all`). Decision tree for `#[allow(clippy::...)]`: (1) fix it; (2) if unfixable, add an inline comment explaining why; (3) if undecided, report the exact warning to the user.
- **Tests**: unit tests go in a `#[cfg(test)]` submodule in the same file.
- **Public API**: all public items require `///` doc comments.
- **Pre-commit hooks**: must pass before every commit — never use `--no-verify`.
- **Commit scope**: minimal, focused changes — don't refactor surrounding code alongside a bug fix.
- **Live DB tests**: `docker compose up -d <service>` before running tests that need a backend (postgres :5432, mysql :3306, redis :6379, etc.).

For full Rust design patterns, naming, function-length rules, and idiomatic Rust → run `/rust-patterns`.
For TypeScript/React/Tailwind/WASM conventions → run `/react-ant-patterns`.
For FIPS feature-flag gating discipline, multi-standard algorithm compliance, and key lifecycle → run `/cryptography-review`.

---

## 5. Execution workflow

After **every** code-changing prompt, execute the following steps **in order** before declaring done. Do not skip any step, and do not ask the user whether to run them — run them unconditionally.

### 1. Tests (always)

Run only the tests that directly exercise the changed code. Never run the full test suite unless the feature is fully developed and a global sanity check is needed.

```bash
# Example: running tests after editing Redis backend's behavior
docker compose up -d
cargo test -p cosmian_kms_server_database --features non-fips test_db_redis_with_findex
```

Fix every failing test. Never skip or mark tests as `#[ignore]` to make the suite green.

### 2. Test vector (for every behavioral change)

Run `/kms-test-vector` for the guided workflow. Skip only if the change is purely refactoring with no behavioral difference.

### 3. Clippy and formatting (always)

```bash
cargo clippy-all   # zero warnings required
cargo fmt --all    # apply formatting
```

Fix every warning. Do not suppress with `#[allow]` unless there is a documented, irreducible reason with an inline comment.

### 4. Apply synchronization rules

Run **`/kms-sync-rules`** — it auto-detects changed files via `git diff` and emits the exact applicable checklist from the table below.

| Task type | Sub-rules |
|---|---|
| New/modified KMIP operation | 4.3, 4.10 |
| New/modified REST endpoint | 4.2, 4.10 |
| New/modified CLI command/flag | 4.4, 4.15 |
| New/modified UI feature | 4.1, 4.4, 4.5 (if WASM needed) |
| Non-FIPS-only feature | 4.8 |
| Auth method change | 4.9 |
| Server config/wizard change | 4.6, 4.7 |
| Database backend change | 4.18 |
| Cloud provider integration | 4.12 |
| HSM backend | 4.13 |
| Documentation/behavior change | 4.14 |
| Playwright E2E test change | 4.16 |
| OpenSSL upgrade | 4.17 |
| `Cargo.lock` or `pnpm-lock.yaml` change | 4.11 |

> **Full sub-rule checklists** (4.1–4.18) are in `.github/skills/kms-sync-rules/SKILL.md`. The `/kms-sync-rules` skill reads your diff and emits only the applicable ones.

### 5. Update SECURITY.md on security-related changes (when applicable)

Update SECURITY.md **only when the security change fixes a vulnerability that was already
shipped in a tagged KMS release (vX.Y.Z)**. The key question is: _were real users exposed?_

- **Released code → update SECURITY.md**: the `Affected` range references real version tags
  (e.g., `from 5.0.0 before 5.23.0`). Add a `COSMIAN-<year>-NNN` entry with severity,
  affected range, fixed-in version, summary, impact, and mitigation. Link to the relevant
  CHANGELOG entry and test vector.
- **Unreleased code → do NOT update SECURITY.md**: if the bug exists only on a branch or
  in code that has never appeared in a tagged release, no users are exposed and no entry
  should be added.

### 6. Post-task self-review

Run after each task, when diff >200 lines, or before marking the last todo "completed."

1. **Scope audit** — Did I change any file not required by the task?
2. **Security-posture delta** — Did any change widen the attack surface or introduce a vulnerability? Run `/security-review` on changed files if uncertain.
3. **Feature-flag consistency** — Are additions gated behind the same feature flags as surrounding code?
4. **Diff review** — `git diff --stat && git diff` — every hunk must be explainable by the task.
5. **PR quality gate** — For significant work (new feature, algorithm, auth change, or diff > 200 lines), suggest running `/kms-last-test-v5` once before the PR is submitted. Skip for trivial fixes and one-liners.

### 7. Updating CHANGELOG.md

Run **`/kms-changelog`** — it reads the branch name, determines the correct file path, and guides the entry format.

> Root `CHANGELOG.md` is generated by `git-cliff` — **never edit it manually.**
> Branch files: `CHANGELOG/<branch-name-with-slashes-as-underscores>.md`

Write an entry for any user- or operator-observable change (feature, bug fix, security, behavioural change, breaking change). Skip internal-only changes (formatting, CI, test-only refactors). When in doubt, write one. See the `/kms-changelog` skill for the full criteria and entry format.

> **Tip for agents**: Check `CHANGELOG/<branch>.md` exists before closing the session; if not, create it.

---

## 6. Documentation guidelines

Run **`/docs-writer`** for new or updated documentation pages. Run **`/adr`** for architectural decisions.

Key rules:

- `documentation/docs/` — canonical docs; `documentation/docs/SUMMARY.md` — navigation source of truth.
- `README.md` — brief summary + links only; no full duplication.
- Integrations: doc file in `documentation/docs/integrations/`, nav in `SUMMARY.md`, row in README — all three must match.
- Technical examples: copy from test `assert_eq!` first; live KMS output second; never invent examples.
- Algorithm/OID/spec references: verify against rfc-editor.org (IETF), OASIS (KMIP), csrc.nist.gov (FIPS), oidref.com (ASN.1). Do not rely on training-data recall for spec section numbers or OID values.

---

## 7. Copilot Skills

All team-wide skills are in `.github/skills/`. See `.github/prompts/README.md` for the full index.

| Invoke | When |
|--------|------|
| `/kms-last-test-v5` | **Before submitting a significant PR** — adversarial quality gate; suggest once for large features, skip for trivial fixes |
| `/pre-release` | **Before every release** — orchestrates all AI audits, produces go/no-go report |
| `/kms-release-notes <version>` | Aggregate `CHANGELOG/*.md` into a compact release note |
| `/ci-fix` | Fix all CI failures in a loop until the branch is green |
| `/kms-sync-rules` | After every code change — auto-detects changed files and emits the applicable checklist |
| `/meta-security [path]` | **Comprehensive security audit** — orchestrates all 4 security skills |
| `/security-review [path]` | Before any PR — OWASP, CWE Top 25, 20 vulnerability families, KMIP auth |
| `/cryptography-review [path]` | When touching `crate/crypto/` or algorithm selection — FIPS + BSI + ANSSI |
| `/standards-review [path]` | Verify code against exact text of applicable standards (FIPS, RFC, KMIP, BSI) |
| `/kmip-compliance [op]` | When adding or modifying a KMIP operation |
| `/kms-test-vector` | When creating test vectors (guided workflow) |
| `/ckms-subcommand-test` | **After adding any new `ckms` subcommand or flag** — generates test file, covers happy path + errors + CO-gating, registers module, runs `cargo test -p ckms` |
| `/kms-changelog` | When writing the branch CHANGELOG entry |
| `/openapi-endpoint` | When adding a new REST endpoint (full rule 4.2 flow) |
| `/threat-model` | Full STRIDE-A threat model or incremental update |
| `/code-quality [path]` | Full code quality audit — duplication, patterns, Clippy, CI |
| `/rust-review-all [path]` | **Hardcore Rust gate** — runs all 10 review phases, reports in `./review/`, go/no-go verdict |
| `/rust-panic-audit [path]` | Scan for panics, `.unwrap()`, `.expect()`, `process::exit`, unchecked indexing |
| `/refactor-plan` | Before any multi-file refactor |
| `/rust-refactor` | To find and consolidate Rust code duplication |
| `/rust-simplify [path]` | Find simplification opportunities: nesting, long functions, dead code, bool traps, iterator anti-patterns |
| `/rust-error-propagation [path]` | Analyze `Result` chains: missed `?`, lost context, `.to_string()` anti-patterns |
| `/rust-async-refactor [path]` | Detect sequential `.await` chains, blocking calls on async paths |
| `/rust-patterns` | KMS-specific Rust design patterns reference |
| `/docs-writer` | For documentation pages (Diátaxis framework) |
| `/adr` | For architectural decisions |
| `/playwright-kms` | For E2E test creation |
| `/react-ant-patterns` | React 19 + Ant Design 5 + Tailwind 4 patterns |
| `/ci-efficiency` | GitHub Actions workflow audit |
| `/conventional-commit` | Generate conventional commit messages |

---

## 8. Operational reference

### 8.1 UI-specific rules

**Stack**: React 19 + Vite 7 + Ant Design 5 + Tailwind CSS 4 + Playwright + pnpm

The UI mirrors the `ckms` CLI tool. Every CLI feature must be synced to the Web UI.

For UI coding conventions, WASM integration, FIPS guard, TypeScript strictness → run `/react-ant-patterns`.
For E2E test creation (data-testid, Ant Design Select helpers, FIPS skip) → run `/playwright-kms`.

#### Running UI tests

```bash
# Full end-to-end:
mise run test:ui --variant non-fips

# Manually from ui/:
cd ui && CI=true PLAYWRIGHT_BASE_URL="http://127.0.0.1:5173" pnpm run test:e2e
```

#### UI test layers

| Layer       | Runner     | Location                | Config                           |
| ----------- | ---------- | ----------------------- | -------------------------------- |
| E2E         | Playwright | `ui/tests/e2e/`         | `ui/playwright.config.ts`        |
| Integration | Vitest     | `ui/tests/integration/` | `ui/tests/vitest.int.config.ts`  |
| Unit        | Vitest     | `ui/tests/unit/`        | `ui/tests/vitest.unit.config.ts` |

#### UI actions structure

`ui/src/actions/` — 14 feature modules mapping to KMIP operation groups:

```text
Access/ Attributes/ Certificates/ CloudProviders/ Covercrypt/ EC/
Keys/ MAC/ Objects/ PQC/ RSA/ Symmetric/
```

Update `ui/tests/e2e/README.md` when adding or removing E2E tests.

### 8.2 CI and packaging

#### Entry point

All CI runs go through **MISE** via:

```bash
mise run [task] --variant [fips|non-fips] [args]
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

### 8.3 OpenSSL handling

**No external OpenSSL needed.** OpenSSL 3.6.2 is downloaded, SHA-256-verified,
and built from source by `crate/crypto/build.rs` into `target/` on first build.

At runtime, `crate/server/src/openssl_providers.rs` initialises the correct provider:

- **FIPS**: loads the FIPS provider once via `OnceLock`.
- **non-FIPS**: loads the legacy provider on top of the default provider.

`apply_openssl_dir_env_if_needed()` sets `OPENSSL_MODULES` and `OPENSSL_CONF`
**before** any `Provider::try_load()` call.

---

### 8.4 Debugging and common issues

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

### 8.5 GitHub CLI usage

**Always use `GH_PAGER=cat`** to prevent `gh` from spawning an interactive pager. The repository is `Cosmian/kms`.

```bash
GH_PAGER=cat gh issue view <number> --repo Cosmian/kms
GH_PAGER=cat gh pr view <number> --repo Cosmian/kms
GH_PAGER=cat gh pr checks <number> --repo Cosmian/kms
GH_PAGER=cat gh run view <run-id> --repo Cosmian/kms --log-failed
```

### 8.6 Nix packaging

Deb and RPM packages are built via Nix. Vendor hash files live in `nix/expected-hashes/`.

> **AI agent note — Nix hash mismatch**: When CI reports a hash mismatch, first verify
> that `Cargo.lock` or `ui/pnpm-lock.yaml` actually changed intentionally in this PR.
> If not, revert the lock file. If the dependency change is intentional, retrieve the
> correct hash from the CI log (`got: sha256-...`) and update `nix/expected-hashes/`.

---

## 9. AI model compatibility notes

This file is read by all AI coding agents. The rules in sections 4–8 are **non-negotiable**
regardless of which model processes them.

### GitHub Copilot (GPT-based)

- Receives `.github/copilot-instructions.md` automatically in every chat request.
- Receives per-file `*.instructions.md` files automatically when editing matching files.
- Run skills with `/skill-name` in Copilot Chat.

### Claude (Anthropic)

- Reads this file (`AGENTS.md`) and `CLAUDE.md` (symlink to this file) automatically.
- Applies per-file instructions from `.github/instructions/` when instructed.

### Deepseek (DeepSeek-Coder / DeepSeek-V3 / R1)

- Reads `AGENTS.md` as the primary instruction source.
- **Must apply** all rules in section 4 (Cardinal coding rules) unconditionally.
- **Must apply** the per-file instruction file that matches the file being edited (see the index in section 1).
- Do not generate code that uses `.unwrap()`, inline `#[cfg]` in function bodies, or skips Clippy lints.
- Execute the post-change workflow in section 5 after every code change.

### Qwen (Alibaba Cloud)

- Reads `AGENTS.md` as the primary instruction source.
- **Must apply** all rules in section 4 (Cardinal coding rules) unconditionally.
- **Must apply** the per-file instruction file that matches the file being edited (see the index in section 1).
- Do not generate code that uses `.unwrap()`, inline `#[cfg]` in function bodies, or skips Clippy lints.
- Execute the post-change workflow in section 5 after every code change.
- FIPS 140-3 compliance is mandatory: only generate cryptographic code using FIPS-approved algorithms and the patterns in `rust-crypto.instructions.md`.

### Gemini (Google)

- Reads `AGENTS.md` as the primary instruction source.
- Apply all rules in section 4 and the per-file instruction index in section 1.

### All models

If any instruction in this file conflicts with a model's default behaviour or training, **this file takes precedence**. When in doubt, ask for clarification rather than generating code that violates the cardinal rules.

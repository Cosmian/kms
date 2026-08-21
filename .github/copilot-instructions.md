# Eviden KMS — Copilot Chat Instructions

Eviden KMS is a high-performance, source-available **FIPS 140-3** Key Management System
written in **Rust**. It implements **KMIP 2.1 and 1.4** over HTTP/TLS (Actix-web) and
supports AES, RSA, EC, ML-KEM, ML-DSA, SLH-DSA, Covercrypt, and more.

For autonomous agent work, full instructions are in `AGENTS.md`.
For the skills index, see `.github/skills/README.md`. Skills live in `.github/skills/`.

Per-file coding rules are in `.github/instructions/` and are applied automatically by
agents when editing matching file types (`applyTo` in each file's YAML frontmatter):

| Instruction file | Applies to |
|-----------------|------------|
| `rust.instructions.md` | All `*.rs` files |
| `rust-server.instructions.md` | `crate/server/**/*.rs` |
| `rust-crypto.instructions.md` | `crate/crypto/**/*.rs` |
| `rust-kmip.instructions.md` | `crate/kmip/**/*.rs` |
| `rust-database.instructions.md` | `crate/server_database/**/*.rs` |
| `database-tables.instructions.md` | `crate/server_database/src/stores/sql/*.sql` |
| `ui-routes.instructions.md` | `ui/src/App.tsx`, `ui/src/menuItems.tsx` |
| `routes.instructions.md` | `crate/server/src/routes/**/*.rs` |
| `kmip-operations.instructions.md` | `crate/server/src/core/operations/**/*.rs` |
| `cli-ui-sync.instructions.md` | `crate/clients/clap/**/*.rs`, `crate/clients/ckms/**/*.rs`, `ui/src/actions/**/*.{ts,tsx}` |
| `wasm.instructions.md` | `crate/clients/wasm/**/*.rs` |
| `server-config.instructions.md` | `crate/server/src/config/**/*.rs` |
| `middlewares.instructions.md` | `crate/server/src/middlewares/**/*.rs` |
| `test-vectors.instructions.md` | `test_data/vectors/**`, `crate/test_kms_server/**/*.rs` |
| `lockfile-hashes.instructions.md` | `Cargo.lock`, `ui/pnpm-lock.yaml` |
| `cloud-providers.instructions.md` | `crate/server/src/routes/{aws_xks,azure_ekm,google_cse,ms_dke}/**` |
| `hsm.instructions.md` | `crate/hsm/**/*.rs` |
| `openssl-build.instructions.md` | `crate/crypto/build.rs` |
| `rust-cli.instructions.md` | `crate/clients/**/*.rs` |
| `typescript-ui.instructions.md` | `ui/src/**/*.{ts,tsx}` |
| `i18n.instructions.md` | `ui/src/i18n/**/*.{ts,json}` |
| `playwright.instructions.md` | `ui/tests/e2e/**/*.ts` |
| `bash.instructions.md` | `**/*.sh` |
| `mise.instructions.md` | `.mise/**, scripts/**, .github/reusable_scripts/**` |
| `github-actions.instructions.md` | `.github/workflows/**, .github/actions/**` |
| `toml.instructions.md` | `**/*.toml` |
| `python.instructions.md` | `**/*.py` |
| `markdown.instructions.md` | `**/*.md` |
| `docs.instructions.md` | `documentation/**/*.md` |
| `nix.instructions.md` | `nix/**/*.nix` |
| `docker.instructions.md` | `nix/docker.nix, nix/k8s-images.nix, .mise/scripts/docker-compose.yml, charts/cosmian-kms/**/*` |

---

## Key directories

| Path | Contents |
|------|----------|
| `crate/server/` | Server binary and library (main codebase) |
| `crate/kmip/` | KMIP 2.1 protocol types |
| `crate/crypto/` | Crypto primitives; `build.rs` builds OpenSSL 3.6.2 |
| `crate/clients/clap/` | CLI actions (clap commands) |
| `crate/clients/ckms/` | CLI binary entry point |
| `crate/server_database/` | DB backends (SQLite, PostgreSQL, Redis-findex) |
| `ui/src/` | React 19 + Vite 7 + Ant Design 5 + Tailwind 4 web UI |
| `ui/tests/e2e/` | Playwright E2E tests |
| `.github/skills/` | Team-wide Copilot skills (slash commands) |

---

## Build and test

```bash
cargo build                          # FIPS mode (default)
cargo build --features non-fips      # non-FIPS: PQC, Covercrypt, AES-XTS
cargo clippy-all                     # zero warnings required
cargo fmt --all                      # apply formatting
cargo test -p <crate>                # targeted test (preferred)
cargo test-fips                      # full FIPS workspace test suite
cargo test-non-fips                  # full non-FIPS workspace test suite
```

No external OpenSSL needed — `crate/crypto/build.rs` downloads and builds OpenSSL 3.6.2.

---

## Cardinal coding rules

- No `.unwrap()` in production code — use `?` propagation.
- `#[cfg(feature = "non-fips")]` at function/module level only, never inside a function body.
- Every `unsafe` block requires a `// SAFETY:` comment.
- Zero Clippy warnings — fix warnings; never suppress with `#[allow]` without an inline justification.
- Unit tests go in a `#[cfg(test)]` submodule in the same file.
- All public items require `///` doc comments.
- Minimal, focused commits — never refactor unrelated code alongside a bug fix.

---

## Skills (slash commands in Copilot Chat)

| Command | When to use |
|---------|-------------|
| `/kms-sync-rules` | After every code change — auto-detects changed files |
| `/rust-review-all` | **Full Rust quality gate** — all review skills + reports in `./review/` |
| `/rust-panic-audit` | Scan for panics, `.unwrap()`, `process::exit`, brutal exits |
| `/meta-security` | **Comprehensive security audit** — orchestrates all 4 security skills |
| `/security-review` | Before any PR |
| `/cryptography-review` | When touching `crate/crypto/` or algorithm selection |
| `/standards-review` | Verify code against exact text of applicable standards |
| `/kmip-compliance` | When adding/modifying a KMIP operation |
| `/rust-patterns` | Rust design patterns for this codebase |
| `/rust-simplify` | Find simplification opportunities in Rust code |
| `/rust-error-propagation` | Audit `Result` propagation chains |
| `/react-ant-patterns` | UI coding conventions |
| `/kms-changelog` | Writing the branch CHANGELOG entry |
| `/threat-model` | STRIDE-A threat model |

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
| `rust.instructions.md` | `**/*.rs` |
| `rust-server.instructions.md` | `crate/server/**/*.rs` |
| `rust-crypto.instructions.md` | `crate/crypto/**/*.rs` |
| `rust-kmip.instructions.md` | `crate/kmip/**/*.rs` |
| `rust-security.instructions.md` | `crate/**/*.rs` |
| `rust-database.instructions.md` | `crate/server_database/**/*.rs` |
| `database-tables.instructions.md` | `**/*.sql` |
| `ui-routes.instructions.md` | `ui/src/App.tsx`, `ui/src/menuItems.tsx`, `ui/src/actions/**/*.tsx`, `ui/src/pages/**/*.tsx` |
| `routes.instructions.md` | `crate/server/src/routes/**/*.rs`, `crate/server/documentation/openapi.yaml` |
| `kmip-operations.instructions.md` | `crate/kmip/src/**/*.rs`, `crate/server/src/core/operations/**/*.rs` |
| `cli-ui-sync.instructions.md` | `crate/clients/clap/**/*.rs`, `crate/clients/ckms/**/*.rs`, `ui/src/actions/**/*.ts`, `ui/src/actions/**/*.tsx` |
| `wasm.instructions.md` | `crate/clients/wasm/**/*.rs` |
| `server-config.instructions.md` | `crate/server/src/config/**/*.rs` |
| `middlewares.instructions.md` | `crate/server/src/middlewares/**/*.rs`, `crate/server/src/config/wizard/auth_wizard.rs` |
| `test-vectors.instructions.md` | `test_data/vectors/**`, `crate/test_kms_server/**/*.rs` |
| `test-configs.instructions.md` | `**/*.sh`, `.mise/**`, `crate/test_kms_server/**/*.rs`, `crate/**/tests/**/*.rs`, `crate/server/src/config/**/*.rs`, `test_data/configs/**`, `test_data/spire/config/**` |
| `lockfile-hashes.instructions.md` | `Cargo.lock`, `ui/pnpm-lock.yaml` |
| `cloud-providers.instructions.md` | `crate/server/src/routes/aws_xks/**`, `crate/server/src/routes/azure_ekm/**`, `crate/server/src/routes/google_cse/**`, `crate/server/src/routes/ms_dke/**` |
| `hsm.instructions.md` | `crate/hsm/**/*.rs` |
| `openssl-build.instructions.md` | `crate/crypto/build.rs` |
| `dependencies.instructions.md` | `**/Cargo.toml`, `Cargo.lock`, `supply-chain/**`, `deny.toml`, `.cargo/audit.toml`, `ui/package.json`, `ui/pnpm-lock.yaml`, `crate/clients/wasm/package.json`, `**/requirements*.in`, `**/requirements*.txt`, `**/go.mod`, `**/go.sum`, `**/Dockerfile*`, `.github/dependabot.yml`, `.github/workflows/**`, `.github/actions/**` |
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
| `docs.instructions.md` | `documentation/**/*.md`, `README.md` |
| `nix.instructions.md` | `nix/**/*.nix` |
| `docker.instructions.md` | `nix/docker.nix`, `nix/k8s-images.nix`, `.mise/scripts/docker-compose.yml`, `.mise/scripts/test/test_docker_image.sh`, `.mise/lib/k8s.sh`, `.mise/tasks/build/docker`, `.mise/tasks/test/docker`, `.mise/tasks/test/k8s/**`, `charts/cosmian-kms/**/*`, `.github/workflows/packaging-docker.yml` |
| `mermaid.instructions.md` | `**/*.md` |
| `rust-security.instructions.md` | `crate/**/*.rs` |
| `test-configs.instructions.md` | `**/*.sh`, `.mise/**`, `crate/test_kms_server/**/*.rs`, `crate/**/tests/**/*.rs`, `crate/server/src/config/**/*.rs`, `test_data/configs/**`, `test_data/spire/config/**` |

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
- `#[cfg(feature = "non-fips")]` on a function, module, `impl`, struct field, enum variant or match arm; never on statements/blocks inside a function body, never `cfg!(..)` at runtime.
- Every `unsafe` block requires a `// SAFETY:` comment.
- Zero Clippy warnings — fix warnings; `#[allow]` / `#[expect]` is forbidden on new code (see `rust.instructions.md` § Clippy and lint suppression).
- Unit tests go in a `#[cfg(test)]` submodule in the same file.
- All public items require `///` doc comments.
- Minimal, focused commits — never refactor unrelated code alongside a bug fix.
- Randomness: every random byte comes from `KmsRng`; the root `clippy.toml` bans all other entropy sources and the ban is never suppressed — see `.github/instructions/rust.instructions.md` § Randomness.
- Regression test: every bug fix ships a test that fails before the fix (or the commit message says why not).
- Secrets: compare in constant time, keep in `Zeroizing`, never log — see `.github/instructions/rust-security.instructions.md`.
- Commit subjects: conventional-commit type + descriptive subject; never `fix: PR review`, `fix: commit`.

## Feature rollout order & commit layering

For any feature spanning server + CLI/UI: use one branch and one PR, but make independent
commits per layer, in this order: **server** (`crate/server/`, `crate/kmip/`), then **CLI**
(`crate/clients/`), then **Web UI** (`ui/`). Each commit must build and pass hooks on its own
and must not mix layers. Do not open separate or stacked PRs per layer. Pushed commits are
never rewritten (see force-push prohibition below): if a layer was bundled by mistake, leave
it and apply the layering to subsequent commits.

## Force-push prohibition

Agents must **never** force-push, under any circumstance — no `git push --force`/
`--force-with-lease`, no delete-and-recreate of a remote branch, and no rewriting a
remote ref via the GitHub web UI or REST/GraphQL API. If history diverges, merge or
branch again; never rewrite shared history. Applies to every branch.

---

## Skills (slash commands in Copilot Chat)

| Command | When to use |
|---------|-------------|
| `/issue-workflow` | Entry point for resolving a GitHub issue — scope, plan, implement, test, document, §5 workflow, PR, one-shot CI status, review feedback |
| `/kms-sync-rules` | After every code change — auto-detects changed files |
| `/kms-test-config` | When a test/script needs a KMS or Auth Verifier config — reuse/create complete fixtures in `test_data` |
| `/kms-docs-verify` | After writing/editing documentation — verify ckms commands, flags, env vars, config keys, versions, links against the code |
| `/rust-review-all` | **Full Rust quality gate** — KMS Caveman first, then applicable reviews and reports in `./review-YYYY-MM-DD/` |
| `/kms-caveman` | One read-only mechanical Rust triage pass before deeper Rust reviews; not a substitute for semantic or security review |
| `/rust-panic-audit` | Scan for panics, `.unwrap()`, `process::exit`, brutal exits |
| `/meta-security` | **Comprehensive security audit** — orchestrates all 4 security skills |
| `/security-review` | Before PRs affecting security-sensitive flows; only verified static UI/assets or documentation may use the incremental skip gate |
| `/cryptography-review` | When touching `crate/crypto/` or algorithm selection |
| `/standards-review` | Verify code against exact text of applicable standards |
| `/kmip-compliance` | When adding/modifying a KMIP operation |
| `/rust-patterns` | Rust design patterns for this codebase |
| `/rust-simplify` | Find simplification opportunities in Rust code |
| `/rust-error-propagation` | Audit `Result` propagation chains |
| `/react-ant-patterns` | UI coding conventions |
| `/ckms-subcommand-test` | **After adding a `ckms` subcommand or flag** — write + run integration tests |
| `/kms-pr-review` | Mandatory self-review — two-pass diff review that auto-applies confirmed fixes (≤ 2 cycles) |
| `/kms-pr-description` | Summarize the branch changes (What / Why / How / Tests / Docs) into the PR description via `gh pr edit` |
| `/kms-changelog` | Writing the branch CHANGELOG entry; `consolidate <version>` merges `CHANGELOG/*.md` into the root `CHANGELOG.md` entry and deletes them |
| `/threat-model` | STRIDE-A threat model |
| `/ci-fix` | Fix CI failures for a supplied run/job URL or HEAD; reruns lost hosted runners |

## Automatic skill routing

When a prompt matches a trigger below, read `.github/skills/<skill>/SKILL.md` and apply it to the matching part of the request before anything else; rows are in priority order. OMP sessions inject the skill automatically (`.omp/extensions/jev-orchestrator.ts`). Triggers are case-insensitive regexes in the JavaScript/Python common subset; write alternation as `\|`.

| Skill | Trigger |
|---|---|
| `/ci-fix` | `github\.com/Cosmian/kms/actions/runs/\d+` |
| `/ci-fix` | `\b(fix\|repair)\s+(the\s+)?ci\b` |
| `/issue-workflow` | `github\.com/Cosmian/kms/issues/\d+` |
| `/issue-workflow` | `\b(resolve\|fix\|implement)\s+(github\s+)?issue\s+#?\d+` |
| `/kms-pr-description` | `\bpr description\b` |
| `/kms-pr-review` | `\breview\s+(this\s+\|the\s+\|my\s+)?(pr\|pull request\|diff\|branch)\b` |
| `/kms-release-notes` | `\brelease notes\b` |
| `/pre-release` | `\bpre-?release\s+(gate\|check\|audit)\b` |
| `/kms-changelog` | `\bchangelog\b` |
| `/meta-security` | `\b(full\|complete\|meta)[- ]security audit\b` |
| `/threat-model` | `\bthreat[- ]model` |
| `/kms-test-vector` | `\b(create\|add\|new)\b.*\btest vectors?\b` |
| `/kms-adversarial-test` | `\badversarial test` |
| `/adr` | `\barchitectural decision record\b` |

## Credit-Saving Strategies

- Run `/kms-caveman` once before deeper Rust audits and reuse its findings; do not repeat overlapping mechanical scans.
- Gate specialized reviews on inspected diff scope and affected callers. A clean mechanical scan does not justify skipping security, crypto, or protocol reasoning.
- Full, release, and pre-release gates override focused-scope skips. State why any skill was inapplicable.
- Skills cannot select a model or guarantee latency. Do not claim token/percentage savings without observed usage data.
- `/kms-pr-review` Phase 1 overlaps `/kms-caveman`; if `/kms-caveman` already ran this session, feed its findings into `/kms-pr-review` instead of re-scanning.

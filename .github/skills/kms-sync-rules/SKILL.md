---
name: kms-sync-rules
description: 'Auto-detect changed files via git diff and emit only the applicable AGENTS.md synchronization sub-rules as a checklist. Use after every code change.'
---

# KMS Sync Rules (Auto-Detect)

Detect changed files and emit only the synchronization sub-rules that apply to your current changes.

## Step 1 — Detect Changes

Run the following to discover what has changed:

```bash
# Staged + unstaged changes (working tree):
git diff --name-only HEAD

# Only staged changes (about to be committed):
git diff --name-only --cached

# Changes on this branch vs develop baseline:
git diff --name-only origin/develop...HEAD 2>/dev/null || git diff --name-only HEAD~1
```

Collect the union of changed paths. If no files are detected, ask the user to describe what they changed.

## Step 2 — Map Paths to Sub-Rules

Apply this path → rule mapping to the detected file list:

| Path pattern | Sub-rules triggered |
|---|---|
| `crate/server/src/routes/**` (new/modified handler) | **4.2**, 4.10 |
| `crate/kmip/src/**` or `crate/server/src/core/operations/**` | **4.3**, 4.10 |
| `crate/clients/clap/src/**` or `crate/clients/ckms/src/**` | **4.4**, 4.15 |
| `ui/src/**` (new UI feature path) | **4.1**, 4.4 |
| `crate/clients/wasm/src/**` | **4.5** |
| `crate/server/src/config/**` | **4.6**, 4.7 |
| `crate/server_database/**` | **4.18** |
| `crate/server/src/middlewares/**` or `crate/server/src/config/wizard/auth_wizard.rs` | **4.9** |
| `test_data/vectors/**` or `crate/test_kms_server/**` | verify 4.10 completeness |
| `Cargo.lock` or `ui/pnpm-lock.yaml` | **4.11** |
| `crate/server/src/routes/aws_xks/**` or `azure_ekm/**` or `google_cse/**` or `ms_dke/**` | **4.12**, 4.10 |
| `crate/hsm/**` | **4.13** |
| `documentation/**` or `README.md` | **4.14** |
| `ui/tests/e2e/**` | **4.16** |
| `crate/crypto/build.rs` | **4.17** |

> **Automatic application via `applyTo`.** Most sub-rules below are also encoded as
> `.github/instructions/*.instructions.md` files with an `applyTo` frontmatter, so agents editing a
> matching file receive the checklist automatically without running this skill. This skill remains
> the authoritative on-demand reference and the single source of truth for the rule numbers.

Additional heuristic checks:

- If any changed Rust file contains `#[cfg(feature = "non-fips")]` changes → add **4.8**
- If `crate/clients/ckms/src/commands.rs` changed → add **4.15**
- If `crate/server/src/start_kms_server.rs` changed → verify 4.1, 4.2, 4.8, 4.9 as applicable
- If any changed file is in `crate/server/src/middlewares/`, `crate/server/src/core/operations/`, or `crate/crypto/src/` **and** the change fixes a security bug → remind: **update `SECURITY.md`** with a `COSMIAN-YYYY-NNN` entry (run `/security-review` to generate it)

## Step 3 — Emit the Applicable Checklist

Output **only** the sub-rules that were triggered. For each, print the full checklist from the reference below.

---

## Sub-Rule Reference

Full checklists live in `.github/instructions/`, which is normative and auto-attaches when the
agent edits a matching path. This table is a rule-number → instruction-file index only.

| Rule | Title | Trigger | Normative checklist |
|---|---|---|---|
| 4.1 | Server SPA routes ⇔ React Router ⇔ Menu items | `ui/src/**` (new page/action) | `ui-routes.instructions.md` |
| 4.2 | REST endpoints ⇔ OpenAPI ⇔ Route registration | `crate/server/src/routes/**` | `routes.instructions.md` |
| 4.3 | KMIP operations: types → dispatch → implementation | `crate/kmip/src/**`, `crate/server/src/core/operations/**` | `kmip-operations.instructions.md` |
| 4.4 | CLI ⇔ Web UI feature parity | `crate/clients/clap/src/**`, `crate/clients/ckms/src/**`, `ui/src/actions/**` | `cli-ui-sync.instructions.md` |
| 4.5 | WASM bindings ⇔ Web UI | `crate/clients/wasm/src/**` | `wasm.instructions.md` |
| 4.6 | Server configuration ⇔ Wizard ⇔ TOML templates | `crate/server/src/config/**` | `server-config.instructions.md` |
| 4.7 | Server wizard ⇔ Client wizard | `crate/server/src/config/wizard/**` | `server-config.instructions.md` |
| 4.8 | Non-FIPS gating across the stack | heuristic: `#[cfg(feature = "non-fips")]` diff, not a path | kept in this skill — see below |
| 4.9 | Auth middleware consistency | `crate/server/src/middlewares/**`, `crate/server/src/config/wizard/auth_wizard.rs` | `middlewares.instructions.md` |
| 4.10 | Test vectors: directory → runner → README | `test_data/vectors/**`, `crate/test_kms_server/**` | `test-vectors.instructions.md` |
| 4.11 | Nix vendor hashes ⇔ lock files | `Cargo.lock`, `ui/pnpm-lock.yaml` | `lockfile-hashes.instructions.md` |
| 4.12 | Cloud provider integrations | `crate/server/src/routes/{aws_xks,azure_ekm,google_cse,ms_dke}/**` | `cloud-providers.instructions.md` |
| 4.13 | HSM backend support | `crate/hsm/**` | `hsm.instructions.md` |
| 4.14 | Documentation ⇔ mdBook ⇔ README | `documentation/**`, `README.md` | `docs.instructions.md` |
| 4.15 | CLI documentation auto-generation | `crate/clients/ckms/src/**`, `crate/clients/clap/src/**` | `cli-ui-sync.instructions.md` |
| 4.16 | E2E test documentation | `ui/tests/e2e/**` | `playwright.instructions.md` |
| 4.17 | OpenSSL version updates | `crate/crypto/build.rs` | `openssl-build.instructions.md` |
| 4.18 | Database schema/backend ⇔ docs | `crate/server_database/**` | `rust-database.instructions.md` (table-level detail: `database-tables.instructions.md`) |

### Rule 4.8 — Non-FIPS gating across the stack

> Triggered by: non-fips feature changes detected in diff (heuristic, not a path — no instruction
> file exists because `applyTo` globs cannot match on diff content).

- [ ] Server implementation — `#[cfg(feature = "non-fips")]` at **function/module level**, not inline
- [ ] `crate/server/src/start_kms_server.rs` — scope wrapped in `#[cfg(feature = "non-fips")] { ... }`
- [ ] `crate/server/src/core/operations/dispatch.rs` — dispatch arm gated if needed
- [ ] CLI actions — `#[cfg(feature = "non-fips")]` on module or function
- [ ] WASM bindings — `#[cfg(feature = "non-fips")]` on exported function
- [ ] UI — menu items/routes hidden when FIPS mode active (`FIPS_MODE` env var)
- [ ] E2E tests — `test.skip(FIPS_MODE, "non-fips only")` in Playwright specs
- [ ] Test vectors — placed in `test_data/vectors/non-fips/` or runner gated with `#[cfg(feature = "non-fips")]`

### Rule 4.9 — Auth middleware consistency

*(triggered by: `crate/server/src/middlewares/**`, `crate/server/src/config/wizard/auth_wizard.rs`)*

- [ ] Config struct updated in `crate/server/src/config/`
- [ ] Wizard step added/updated in `crate/server/src/config/wizard/auth_wizard.rs`
- [ ] Middleware implemented in `crate/server/src/middlewares/`
- [ ] Every authenticated scope in `start_kms_server.rs` wraps the middleware with `Condition::new(use_<auth>, <Middleware>)`
- [ ] `EnsureAuth::new` boolean: `use_jwt_auth || use_cert_auth || use_api_token_auth` (every scope except mTLS-only)

### Rule 4.10 — Test vectors: directory → runner → README

> Triggered by: most code changes

- [ ] Directory created: `test_data/vectors/<category>/<name>/`
- [ ] `manifest.toml` and TTLV-JSON step files written
- [ ] Test function added to `crate/test_kms_server/src/vector_runner.rs`
- [ ] `crate/test_kms_server/README.md` row added + total count updated
- [ ] Run `/kms-test-vector` for guided workflow

### Rule 4.11 — Nix vendor hashes ⇔ lock files

*(triggered by: `Cargo.lock`, `ui/pnpm-lock.yaml`)*

- [ ] Update `nix/expected-hashes/` files with correct `sha256-...` hash from CI output
- Hash files: `server.vendor.{static,dynamic}.sha256`, `cli.vendor.{static,dynamic}.{darwin,linux}.sha256`, `ui.vendor.{fips,non-fips}.sha256`, `ui.pnpm.{darwin,linux}.sha256`

### Rule 4.12 — Cloud provider integrations

*(triggered by: `crate/server/src/routes/aws_xks/**`, `azure_ekm/**`, `google_cse/**`, `ms_dke/**`)*

- [ ] Config struct in `crate/server/src/config/`
- [ ] Wizard step in `crate/server/src/config/wizard/advanced_wizard.rs`
- [ ] Routes module in `crate/server/src/routes/<provider>/`, declared in `routes/mod.rs`
- [ ] Scope registered in `start_kms_server.rs` with correct auth middleware
- [ ] `crate/server/documentation/openapi.yaml` updated
- [ ] CLI actions in `crate/clients/clap/src/actions/<provider>/`
- [ ] UI actions in `ui/src/actions/CloudProviders/`

### Rule 4.13 — HSM backend support

*(triggered by: `crate/hsm/**`)*

- [ ] PKCS#11 loader crate in `crate/hsm/<model>/`
- [ ] HSM model enum updated in `crate/server/src/config/` or `crate/hsm/base_hsm/`
- [ ] Wizard step in `crate/server/src/config/wizard/hsm_wizard.rs`
- [ ] Test vectors in `test_data/vectors/hsm/<model>/`
- [ ] CI matrix entry added in `.github/workflows/test_all.yml`

### Rule 4.14 — Documentation ⇔ mkdocs ⇔ README

*(triggered by: `documentation/**`, `README.md`)*

- [ ] `documentation/docs/` — relevant `.md` page added/updated (run `/docs-writer`)
- [ ] `documentation/mkdocs.yml` — nav entry added under correct section
- [ ] `README.md` — brief summary + link added (no full duplication)
- [ ] `documentation/docs/kms_clients/` — CLI docs regenerated if CLI-visible (see Rule 4.15)

### Rule 4.15 — CLI documentation auto-generation

*(triggered by: `crate/clients/ckms/src/**`, `crate/clients/clap/src/**`)*

- [ ] Run: `cargo run --bin ckms -- markdown documentation/docs/kms_clients/cli/main_commands.md`
- [ ] Commit the regenerated file (manual edits will be overwritten next time)

### Rule 4.16 — E2E test documentation

*(triggered by: `ui/tests/e2e/**`)*

- [ ] Update `ui/tests/e2e/README.md` to reflect current spec files, FIPS-skip table, and test coverage

### Rule 4.17 — OpenSSL version updates

*(triggered by: `crate/crypto/build.rs`)*

- [ ] `crate/crypto/build.rs` — version, download URL, SHA-256 hash updated
- [ ] `crate/server/src/openssl_providers.rs` — provider init verified compatible
- [ ] `cbom/cbom.cdx.json` — Cryptographic Bill of Materials updated
- [ ] `sbom/` — Software Bill of Materials updated

### Rule 4.18 — Database schema/backend ⇔ docs

*(triggered by: `crate/server_database/**`)*

- [ ] `documentation/docs/configuration/database/configuration.md` — Databases overview updated if selection/configuration/TLS/migration behaviour changed
- [ ] `documentation/docs/configuration/database/tables.md` — tables and links updated if a table, column, or index was added/removed/renamed
- [ ] `documentation/docs/configuration/database/redis.md` — Redis-with-Findex page updated if the encryption model, key derivation, or data layout changed
- [ ] `documentation/docs/SUMMARY.md` and `documentation/nav.yml` — navigation updated if a page was added or removed

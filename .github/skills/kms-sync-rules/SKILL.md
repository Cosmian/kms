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

### Rule 4.1 — Server SPA routes ⇔ React Router ⇔ Menu items

*(triggered by: `ui/src/**` with new route, or `start_kms_server.rs` changes)*

- [ ] `crate/server/src/start_kms_server.rs` — add top-level path to `spa_routes` array (e.g. `"/newfeature{_:.*}"`)
- [ ] `ui/src/App.tsx` — add `<Route path="..." element={<Component />} />`
- [ ] `ui/src/menuItems.tsx` — add `baseMenu` entry; `key` must match route path prefix

### Rule 4.2 — REST endpoints ⇔ OpenAPI ⇔ Route registration

*(triggered by: `crate/server/src/routes/**`)*

- [ ] Handler implemented in `crate/server/src/routes/<module>/`
- [ ] `crate/server/src/routes/mod.rs` — `pub mod <module>;` declared
- [ ] `crate/server/src/start_kms_server.rs` — `web::scope(...)` or `.service(...)` registered
    - Middleware order: Cors → auth extractors → EnsureAuth (LIFO: wrap inner-first)
- [ ] `crate/server/documentation/openapi.yaml` — path, request/response schemas, tags added
- [ ] Run `crate/test_kms_server/src/openapi_validation.rs` tests to validate

### Rule 4.3 — KMIP operations: types → dispatch → implementation

*(triggered by: `crate/kmip/src/**`, `crate/server/src/core/operations/**`)*

- [ ] `crate/kmip/src/kmip_2_1/kmip_operations.rs` — request/response types defined; variant added to `Operation` enum
- [ ] `crate/server/src/core/operations/dispatch.rs` — match arm added for the new operation
- [ ] `crate/server/src/core/operations/<operation>.rs` — handler implemented
- [ ] Handler registered in `crate/server/src/core/operations/mod.rs`
- [ ] Run `/kmip-compliance <OperationName>` to validate spec compliance

### Rule 4.4 — CLI ⇔ Web UI feature parity

*(triggered by: `crate/clients/clap/**`, `crate/clients/ckms/**`, `ui/src/**`)*

- [ ] `crate/clients/clap/src/actions/<module>/` — CLI action implemented
- [ ] `crate/clients/ckms/src/commands.rs` — subcommand registered in `CliCommands` enum
- [ ] `ui/src/actions/<Module>/` — React component(s) created
- [ ] `ui/src/App.tsx` — `<Route>` entry added
- [ ] `ui/src/menuItems.tsx` — menu item added
- [ ] `crate/server/src/start_kms_server.rs` — SPA route added if new top-level path
- [ ] `crate/clients/ckms/src/tests.rs` — tests added for new subcommand

### Rule 4.5 — WASM bindings ⇔ Web UI

*(triggered by: `crate/clients/wasm/src/**`)*

- [ ] `crate/clients/wasm/src/wasm.rs` — `#[wasm_bindgen]` exported function added
- [ ] Rebuild WASM: `wasm-pack build --target web` (from `crate/clients/wasm/`)
- [ ] `ui/src/wasm/pkg/` — regenerated TS types committed
- [ ] UI component imports and calls the new WASM function

### Rule 4.6 — Server configuration ⇔ Wizard ⇔ TOML templates

*(triggered by: `crate/server/src/config/**`)*

- [ ] `crate/server/src/config/command_line/clap_config.rs` — struct field with `#[clap(...)]`
- [ ] `crate/server/src/config/wizard/<*>_wizard.rs` — interactive step added/updated
- [ ] `resources/kms.toml` — reference config updated
- [ ] `crate/server/kms_template.toml` — tarball template updated
- [ ] `pkg/kms.toml` — service deployment config updated

### Rule 4.7 — Server wizard ⇔ Client wizard

*(triggered by: `crate/server/src/config/wizard/**`)*

- [ ] `crate/clients/client/src/config.rs` — client config struct kept consistent

### Rule 4.8 — Non-FIPS gating across the stack

> Triggered by: non-fips feature changes detected in diff

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

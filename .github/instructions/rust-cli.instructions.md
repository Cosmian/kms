---
name: 'Rust CLI Clients'
description: 'CLI actions, binary entry point, WASM bindings, and PKCS#11 rules'
applyTo: 'crate/clients/**/*.rs'
---

# CLI client rules

## Directory structure

- **CLI actions** (clap subcommands): `crate/clients/clap/src/` — one module per feature area.
- **CLI binary** entry point: `crate/clients/ckms/src/` — dispatches to actions.
- **HTTP client library**: `crate/clients/client/` — shared between CLI and WASM.
- **WASM bindings**: `crate/clients/wasm/src/` — browser client used by the Web UI.
- **PKCS#11 provider**: `crate/clients/pkcs11/` — HSM-compatible interface.

## Sync rule: CLI ↔ Web UI

Every new CLI command or flag **must** be mirrored to the Web UI in `ui/src/actions/`.
The UI mirrors the `ckms` CLI tool feature-for-feature.

## Clap conventions

- Use `#[derive(Parser)]` for top-level commands, `#[derive(Subcommand)]` for subcommands.
- `#[derive(Args)]` for reusable argument groups.
- Help text (`/// doc comments`) becomes the CLI `--help` output — keep it user-facing.

## WASM considerations

- WASM builds cannot use `std::fs`, `std::net`, or `tokio::runtime`.
- Shared code in `crate/clients/client_utils/` — must compile for both native and `wasm32-unknown-unknown`.
- Test WASM builds with: `mise run test:ui:wasm --variant fips`

## Testing

### Quick reference

```bash
cargo test -p cosmian_kms_cli_actions          # unit tests inside clap actions
cargo test -p ckms                             # full integration test suite
cargo test -p ckms -- <filter>                 # single test or module, e.g. split_key
```

### Mandatory: no clap action without `ckms` binary tests

**No clap action may be added or extended without Rust integration tests that drive the `ckms` binary.** This covers a new subcommand (a `#[derive(Parser)]`/`#[derive(Args)]`/`#[derive(Subcommand)]` type or enum variant under `crate/clients/clap/src/actions/`), a new flag or `#[arg(...)]` field, a new accepted value of an existing flag, and a change of a flag's default.

- The tests live in `crate/clients/ckms/src/tests/<feature>/` and run the real binary through `run_ckms` / `run_ckms_expect_error` against a test KMS server. Unit tests inside `crate/clients/clap/` do not count: they never exercise argument parsing, the binary's configuration loading or the server round trip.
- The tests ship in the same change as the action, and in the same commit (CLI layer). Never defer them to a follow-up, never leave them `#[ignore]`d, never register a module that contains no test.
- Each new flag has a test that asserts an effect specific to that flag; a call whose result is discarded proves nothing.
- A change that adds a clap action and touches no file under `crate/clients/ckms/src/tests/` is incomplete: do not commit it, and flag it as a **High** finding in review.
- Run `/ckms-subcommand-test` for the guided workflow; its Step 0 lists the untested actions of the current diff.

### Test file layout

```text
crate/clients/ckms/src/tests/
  <feature>/              ← one directory per CLI feature area (e.g. symmetric/, split_key/)
    mod.rs                ← declare submodules; re-export helper functions used by other tests
    create_key.rs         ← one file per operation group (create, encrypt, rekey, …)
    <operation>.rs
  mod.rs                  ← register new <feature> module here
  utils/
    run.rs                ← run_ckms / run_ckms_expect_error / ckms_bin
    cmd_logs.rs           ← recover_cmd_logs
    extract_uids.rs       ← extract_uid from stdout
    mod.rs
```

When adding a new feature module, **register it in `crate/clients/ckms/src/tests/mod.rs`**:

```rust
#[cfg(feature = "non-fips")]   // ← add this gate if the feature is non-FIPS-only
mod my_new_feature;
```

### Test skeleton

Every integration test follows the same three-step pattern:

```rust
use test_kms_server::start_default_test_kms_server;   // or a variant with custom config
use crate::{
    error::result::CosmianResult,
    tests::utils::{owner_config, run_ckms, run_ckms_expect_error},
};

/// Public helper — call this from other test files to set up state.
pub(crate) fn create_my_object(cli_conf_path: &str, extra_args: &[&str]) -> CosmianResult<String> {
    let mut args = vec!["my-subcommand", "create"];
    args.extend_from_slice(extra_args);
    let stdout = run_ckms(cli_conf_path, &args)?;
    // Extract the object UID from stdout with extract_uid if applicable.
    Ok(stdout)
}

#[tokio::test]
async fn test_create_my_object_happy_path() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);
    create_my_object(&conf, &[])?;
    Ok(())
}

#[tokio::test]
async fn test_create_my_object_error_cases() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);
    let stderr = run_ckms_expect_error(&conf, &["my-subcommand", "create", "--invalid"])?;
    assert!(stderr.contains("expected error fragment"), "got: {stderr}");
    Ok(())
}
```

### Test server variants

Pick the server helper from [`rust.instructions.md` § Test KMS servers](rust.instructions.md#test-kms-servers); never start a server another way.

Import helpers from `crate/tests/utils::{owner_config, load_client_config, run_ckms, run_ckms_expect_error}`.

### Feature-gating tests

- Wrap the entire module registration in `#[cfg(feature = "non-fips")]` in `mod.rs` when the
  CLI feature is non-FIPS-only (e.g. Covercrypt, AES-XTS, Redis-findex).
- Within a FIPS-compatible module, gate individual test cases that exercise non-FIPS paths:
  `#[cfg(feature = "non-fips")]`.

### Coverage checklist for a new subcommand

- [ ] Happy path: create / invoke with default flags.
- [ ] All non-default flags exercised at least once.
- [ ] Error path: invalid flag value, object not found, permission denied.
- [ ] If the subcommand produces a UID: verify `extract_uid` parses it correctly.
- [ ] If the subcommand is CO-gated: test both a CO user (succeeds) and an operator (fails).
- [ ] Re-export any helper functions (`pub(crate)`) so other test modules can compose them.

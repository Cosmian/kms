# ckms Subcommand Integration Tests

Write and run integration tests for a new or modified `ckms` subcommand, following the
project's established test patterns.

## When to Use

- After adding a new `ckms` subcommand or new flags to an existing one.
- When a code review or CI failure indicates missing test coverage for a CLI command.
- When `/kms-sync-rules` emits sync rule 4.4 (CLI ↔ UI parity) and the CLI side has no tests.

---

## Step 0 — Identify the subcommand

Locate the implementation:

```bash
find crate/clients/clap/src/actions -name "*.rs" | xargs grep -l "struct.*Args\|#\[command\]" | sort
```

Read the clap struct to enumerate:
- The subcommand path (e.g. `sym keys create-split-key`)
- Every flag and its type, default value, required vs optional
- Feature gates: `#[cfg(feature = "non-fips")]` on the struct or its module

Also check the HTTP client wrapper in `crate/clients/client/src/kms_rest_client.rs` to
understand what the action calls server-side.

---

## Step 1 — Choose or create the test directory

The convention is one directory per CLI feature area:

```
crate/clients/ckms/src/tests/
  <feature>/        ← e.g. split_key/, rsa/, ec/
    mod.rs
    <operation>.rs  ← e.g. create_split_key.rs, join_split_key.rs
```

Check whether a directory for this feature area already exists:

```bash
ls crate/clients/ckms/src/tests/
```

- **Existing directory** → add a new file (or add tests to an existing file).
- **New feature area** → create the directory, `mod.rs`, and the first test file.

---

## Step 2 — Write the test file

### 2a. Imports

```rust
use test_kms_server::start_default_test_kms_server;   // adjust variant as needed
use crate::{
    error::result::CosmianResult,
    tests::utils::{owner_config, run_ckms, run_ckms_expect_error},
};
```

For CO-gated commands:
```rust
use test_kms_server::start_default_test_kms_server_with_crypto_officer_users;
use crate::tests::utils::load_client_config;
```

### 2b. Public helper function

Every operation file exposes a `pub(crate)` helper function so other test files can compose
it without duplicating the CLI call:

```rust
/// Create a split-key from `source_uid` into `n` shares.
///
/// `extra_args` are appended after the base subcommand args.
pub(crate) fn create_split_key(
    cli_conf_path: &str,
    source_uid: &str,
    n: u32,
    extra_args: &[&str],
) -> CosmianResult<Vec<String>> {
    let n_str = n.to_string();
    let mut args = vec!["sym", "keys", "create-split-key", "--key-id", source_uid,
                        "--split-key-parts", &n_str];
    args.extend_from_slice(extra_args);
    let stdout = run_ckms(cli_conf_path, &args)?;
    // Parse UIDs from stdout — adapt to actual output format.
    Ok(stdout.lines().filter_map(|l| {
        crate::tests::utils::extract_uids::extract_uid(l, "Unique identifier")
            .map(str::to_owned)
    }).collect())
}
```

### 2c. Happy path test(s)

```rust
#[tokio::test]
async fn test_<operation>_default() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);
    // Setup: create prerequisite objects.
    let key_id = crate::tests::symmetric::create_key::create_symmetric_key(&conf, &[])?;
    // Exercise the subcommand.
    let result = my_operation(&conf, &key_id, &[])?;
    // Assert invariants.
    assert!(!result.is_empty(), "expected non-empty result");
    Ok(())
}
```

### 2d. Flag coverage test(s)

One test per non-trivial flag combination that exercises different code paths:

```rust
#[tokio::test]
async fn test_<operation>_with_flags() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);
    let key_id = crate::tests::symmetric::create_key::create_symmetric_key(&conf, &[])?;
    // Exercise specific flag.
    my_operation(&conf, &key_id, &["--some-flag", "value"])?;
    Ok(())
}
```

### 2e. Error path test(s)

At minimum: one test that expects the CLI to fail (wrong input, missing permission, etc.):

```rust
#[tokio::test]
async fn test_<operation>_invalid_input_returns_error() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);
    let stderr = run_ckms_expect_error(&conf, &["sym", "keys", "my-op", "--invalid"])?;
    assert!(
        stderr.contains("expected fragment"),
        "unexpected error: {stderr}"
    );
    Ok(())
}
```

### 2f. CO-gated tests

When the command requires `crypto_officer_users`:

```rust
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_<operation>_requires_co_role() -> CosmianResult<()> {
    // Operator (not listed in crypto_officer_users) must be rejected.
    let ctx = start_default_test_kms_server_with_crypto_officer_users(
        vec!["owner.client.acme.com".to_owned()]
    ).await;
    let operator_conf = load_client_config("kmserver.client.acme.com.toml", ctx);
    let stderr = run_ckms_expect_error(&operator_conf, &["sym", "keys", "my-op", ...])?;
    assert!(stderr.contains("Unauthorized") || stderr.contains("permission"),
            "expected auth error, got: {stderr}");
    Ok(())
}
```

---

## Step 3 — Register the module

### New file in existing directory

Add to the directory's `mod.rs`:

```rust
mod my_new_file;
pub(crate) use my_new_file::my_helper_fn;  // re-export if needed by other modules
```

### New directory

1. Create `crate/clients/ckms/src/tests/<feature>/mod.rs` declaring submodules.
2. Add to `crate/clients/ckms/src/tests/mod.rs`:

```rust
// add feature gate if non-fips-only:
#[cfg(feature = "non-fips")]
mod <feature>;
```

---

## Step 4 — Run the new tests

```bash
# Run only the new tests (fast feedback):
cargo test -p ckms -- <feature>

# Run the full ckms suite to check for regressions:
cargo test -p ckms
```

Fix every failure before proceeding. Never mark tests `#[ignore]`.

---

## Step 5 — Coverage checklist

Verify before closing the task:

- [ ] Happy path: default flags succeed and produce a parseable output.
- [ ] Every non-default flag exercised at least once.
- [ ] At least one error case: invalid input, object not found, or permission denied.
- [ ] CO-gated commands: operator rejection test exists (`#[cfg(feature = "non-fips")]`).
- [ ] Helper function is `pub(crate)` and re-exported from `mod.rs` if other tests need it.
- [ ] New module registered in `crate/clients/ckms/src/tests/mod.rs` with correct feature gate.
- [ ] `cargo test -p ckms -- <feature>` passes with 0 failures.

---

## Reference: test utilities

| Helper | Location | Purpose |
|--------|----------|---------|
| `run_ckms(conf, args)` | `tests/utils/run.rs` | Run ckms, return stdout or propagate stderr as error |
| `run_ckms_expect_error(conf, args)` | `tests/utils/run.rs` | Run ckms, return stderr; fail if command succeeds |
| `ckms_bin()` | `tests/utils/run.rs` | Raw `Command` for ckms (use when building multi-step commands) |
| `recover_cmd_logs(cmd)` | `tests/utils/cmd_logs.rs` | Run a `Command`, capture stdout+stderr |
| `owner_config(ctx)` | `tests/utils/mod.rs` | Path to `owner.client.acme.com.toml` config |
| `load_client_config(name, ctx)` | `tests/utils/mod.rs` | Path to any test-cert config file |
| `extract_uid(stdout, label)` | `tests/utils/extract_uids.rs` | Parse a UID from a line like `Unique identifier: <uid>` |
| `start_default_test_kms_server()` | `test_kms_server` crate | Start an in-process KMS with SQLite + cert auth |
| `start_default_test_kms_server_with_crypto_officer_users(users)` | `test_kms_server` crate | Start KMS with CO role enabled |
| `start_default_test_kms_server_with_multi_crypto_officer_users()` | `test_kms_server` crate | Two-CO pre-configured setup |

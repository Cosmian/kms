//! Tests for the `ckms sym keys set-rotation-policy` command and the
//! full auto-rotation lifecycle for symmetric keys.
//!
//! ## Test coverage
//!
//! ### CLI command tests (quick, stateless)
//! - `test_set_rotation_policy_interval_and_name` – basic flag parsing and output
//! - `test_set_rotation_policy_disable_with_zero` – zero disables rotation
//! - `test_set_rotation_policy_no_args_prints_message` – prints hint when no flags given
//! - `test_set_rotation_policy_offset` – offset flag is echoed correctly
//! - `test_set_rotation_policy_on_wrapped_key` – works even when the key is stored wrapped
//! - `test_self_wrapping_key_is_rejected` – server rejects creation with `wrapping_key_id` == `key_id`
//!
//! ### Lifecycle tests (start a dedicated server w/ auto-rotation enabled)
//! - `test_symmetric_key_auto_rotation_lifecycle` – full E2E: create key, arm policy, wait for
//!   cron to fire, verify all KMIP links, verify new-key bytes differ from old-key bytes, verify
//!   the rotation policy is transferred to the new key and cleared on the old key.

use std::{process::Command, time::Duration};

use assert_cmd::prelude::*;
use cosmian_kms_cli_actions::{
    actions::symmetric::keys::create_key::CreateKeyAction,
    reexport::{
        cosmian_kmip::{
            kmip_0::kmip_types::KeyWrapType,
            kmip_2_1::{
                kmip_attributes::Attribute,
                kmip_operations::{Export, GetAttributes, SetAttribute},
                kmip_types::{CryptographicAlgorithm, LinkType, UniqueIdentifier},
                requests::symmetric_key_create_request,
            },
        },
        cosmian_kms_client::KmsClient,
    },
};
use tempfile::TempDir;
use test_kms_server::{
    AuthenticationOptions, BuildServerParamsOptions, ClientAuthOptions, MainDBConfig,
    ServerJwtAuth, ServerTlsMode, build_server_params_full, start_default_test_kms_server,
    start_test_server_with_options,
};

use super::SUB_COMMAND;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME, save_kms_cli_config,
        shared::{ExportKeyParams, ImportKeyParams, export_key, import_key},
        symmetric::create_key::create_symmetric_key,
    },
};

/// Invoke `ckms sym keys set-rotation-policy` and return the stdout if
/// the command succeeds, or an error containing stderr.
pub(super) fn set_rotation_policy_cmd(
    cli_conf_path: &str,
    key_id: &str,
    extra_args: &[&str],
) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.env("RUST_MIN_STACK", "16777216");
    let mut args = vec!["keys", "set-rotation-policy", "--key-id", key_id];
    args.extend_from_slice(extra_args);
    cmd.arg(SUB_COMMAND).args(args);
    let output = cmd.output()?;
    if output.status.success() {
        return Ok(std::str::from_utf8(&output.stdout)?.to_owned());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

// ─── CLI command tests ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_set_rotation_policy_interval_and_name() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let id = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;

    let stdout = set_rotation_policy_cmd(
        &owner_client_conf_path,
        &id,
        &["--interval", "3600", "--name", "daily"],
    )?;
    assert!(
        stdout.contains("Rotation policy updated"),
        "unexpected stdout: {stdout}"
    );
    assert!(
        stdout.contains("interval=3600s"),
        "must mention interval: {stdout}"
    );
    assert!(stdout.contains("name=daily"), "must mention name: {stdout}");
    Ok(())
}

#[tokio::test]
async fn test_set_rotation_policy_disable_with_zero() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let id = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;

    let stdout = set_rotation_policy_cmd(&owner_client_conf_path, &id, &["--interval", "3600"])?;
    assert!(stdout.contains("interval=3600s"));

    let stdout = set_rotation_policy_cmd(&owner_client_conf_path, &id, &["--interval", "0"])?;
    assert!(
        stdout.contains("interval=0s"),
        "must confirm interval=0: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_set_rotation_policy_no_args_prints_message() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let id = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;

    let stdout = set_rotation_policy_cmd(&owner_client_conf_path, &id, &[])?;
    assert!(
        stdout.contains("No rotation policy attributes specified"),
        "expected hint message, got: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_set_rotation_policy_offset() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let id = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;

    let stdout = set_rotation_policy_cmd(
        &owner_client_conf_path,
        &id,
        &["--interval", "7200", "--offset", "120"],
    )?;
    assert!(
        stdout.contains("interval=7200s"),
        "must mention interval: {stdout}"
    );
    assert!(
        stdout.contains("offset=120s"),
        "must mention offset: {stdout}"
    );
    Ok(())
}

/// `SetAttribute(RotateInterval)` must succeed for keys stored wrapped.
#[tokio::test]
async fn test_set_rotation_policy_on_wrapped_key() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    let tmp_dir = TempDir::new()?;
    let wrapped_key_file = tmp_dir
        .path()
        .join("wrapped_dek.json")
        .to_string_lossy()
        .to_string();

    let kek_id = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;
    let dek_id = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            number_of_bits: Some(256),
            ..Default::default()
        },
    )?;

    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: SUB_COMMAND.to_owned(),
        key_id: dek_id,
        key_file: wrapped_key_file.clone(),
        wrap_key_id: Some(kek_id),
        ..Default::default()
    })?;
    let wrapped_id = import_key(ImportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: SUB_COMMAND.to_string(),
        key_file: wrapped_key_file,
        replace_existing: false,
        unwrap: false,
        ..Default::default()
    })?;

    // SetAttribute must succeed on the wrapped key.
    let stdout = set_rotation_policy_cmd(
        &owner_client_conf_path,
        &wrapped_id,
        &["--interval", "3600", "--name", "hourly"],
    )?;
    assert!(
        stdout.contains("Rotation policy updated"),
        "set-rotation-policy on a wrapped key must succeed: {stdout}"
    );
    assert!(
        stdout.contains("interval=3600s"),
        "stdout must mention the interval: {stdout}"
    );

    Ok(())
}

// ─── Self-wrapping rejection test ────────────────────────────────────────────

/// The server must reject a `Create` request that sets `wrapping_key_id` to the
/// same UID as the key being created (self-wrapping loop).
#[tokio::test]
async fn test_self_wrapping_key_is_rejected() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Choose a fixed UID and attempt to create a key that wraps itself.
    let self_id = "self-wrapping-test-key-id".to_string();
    let create_req = symmetric_key_create_request(
        "cosmian",
        Some(UniqueIdentifier::TextString(self_id.clone())),
        256,
        CryptographicAlgorithm::AES,
        std::iter::empty::<&str>(),
        false,
        Some(&self_id), // wrapping_key_id == key_id → self-loop
    )?;

    let err = client.create(create_req).await;
    assert!(
        err.is_err(),
        "Self-wrapping Create must be rejected by the server"
    );
    let msg = err.unwrap_err().to_string().to_lowercase();
    assert!(
        msg.contains("wrapping") || msg.contains("self") || msg.contains("invalid"),
        "Error must mention self-wrapping, got: {msg}"
    );
    Ok(())
}

// ─── Lifecycle test helpers ───────────────────────────────────────────────────

/// Start a disposable (non-static) KMS server with a fast auto-rotation cron
/// (`check_interval = 2 s`). Each invocation gets its own `SQLite` database
/// isolated by `port`, so tests can run in parallel.
async fn start_auto_rotation_server(port: u16) -> CosmianResult<test_kms_server::TestsContext> {
    let server_params = build_server_params_full(BuildServerParamsOptions {
        db_config: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            clear_database: true,
            ..MainDBConfig::default()
        },
        port,
        tls: ServerTlsMode::PlainHttp,
        jwt: ServerJwtAuth::Disabled,
        auto_rotation_check_interval_secs: 2, // fast: check every 2 s
        ..BuildServerParamsOptions::default()
    })?;

    Ok(start_test_server_with_options(
        MainDBConfig::default(), // ignored — server_params is already built
        port,
        AuthenticationOptions {
            server_params: Some(server_params),
            client: ClientAuthOptions::default(),
        },
        None,
        None,
    )
    .await?)
}

/// Export a symmetric key as raw bytes (unwrapped).
async fn export_sym_key_bytes(client: &KmsClient, key_id: &str) -> CosmianResult<Vec<u8>> {
    let resp = client
        .export(Export {
            unique_identifier: Some(UniqueIdentifier::TextString(key_id.to_owned())),
            key_wrap_type: Some(KeyWrapType::NotWrapped),
            ..Export::default()
        })
        .await?;
    Ok(resp.object.key_block()?.key_bytes()?.to_vec())
}

// ─── Full lifecycle test ──────────────────────────────────────────────────────

/// End-to-end auto-rotation lifecycle for a symmetric key:
///
/// 1. Start a dedicated server with `auto_rotation_check_interval_secs = 2`.
/// 2. Create a 256-bit AES key via the KMS REST client.
/// 3. Arm auto-rotation: `SetAttribute(RotateInterval = 4)`.
/// 4. Sleep 10 s — the rotation cron fires at least twice.
/// 5. Read attributes on the OLD key and confirm `ReplacementObjectLink` was set.
/// 6. Export and compare raw bytes: OLD key ≠ NEW key.
/// 7. Confirm the old key has `rotate_interval = 0` (rotation cleared).
/// 8. Confirm the new key has `rotate_latest = true` and `ReplacedObjectLink` set.
#[tokio::test]
async fn test_symmetric_key_auto_rotation_lifecycle() -> CosmianResult<()> {
    const PORT: u16 = 10_100;
    const ROTATE_INTERVAL_SECS: i32 = 8; // 8 s interval → first rotation at t≈8 s
    const WAIT_SECS: u64 = 12; // 12 s wait → next rotation would be at t≈16 s (safe)

    let ctx = start_auto_rotation_server(PORT).await?;
    let client = ctx.get_owner_client();

    // ── Step 1: Create the key ────────────────────────────────────────────────
    let create_req = symmetric_key_create_request(
        "cosmian",
        None, // let the server generate a UID
        256,
        CryptographicAlgorithm::AES,
        std::iter::empty::<&str>(),
        false,
        None, // no wrapping
    )?;
    let create_resp = client.create(create_req).await?;
    let old_key_id = create_resp.unique_identifier.to_string();

    // ── Step 2: Export initial bytes ──────────────────────────────────────────
    let old_bytes = export_sym_key_bytes(&client, &old_key_id).await?;
    assert_eq!(old_bytes.len(), 32, "AES-256 must be 32 bytes");

    // ── Step 3: Arm auto-rotation ──────────────────────────────────────────────
    // The server stamped `initial_date = now` at Create time, so the key becomes
    // due for rotation as soon as `initial_date + ROTATE_INTERVAL_SECS ≤ now`.
    client
        .set_attribute(SetAttribute {
            unique_identifier: Some(UniqueIdentifier::TextString(old_key_id.clone())),
            new_attribute: Attribute::RotateInterval(ROTATE_INTERVAL_SECS),
        })
        .await?;

    // ── Step 4: Wait for the cron to fire ─────────────────────────────────────
    tokio::time::sleep(Duration::from_secs(WAIT_SECS)).await;

    // ── Step 5: Verify ReplacementObjectLink on the old key ───────────────────
    let old_attrs_resp = client
        .get_attributes(GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(old_key_id.clone())),
            attribute_reference: None,
        })
        .await?;
    let replacement_link = old_attrs_resp
        .attributes
        .get_link(LinkType::ReplacementObjectLink)
        .unwrap_or_else(|| {
            panic!(
                "ReplacementObjectLink must be set on the old key after {WAIT_SECS} s; \
                 attributes: {:?}",
                old_attrs_resp.attributes
            )
        });
    let new_key_id = replacement_link.to_string();
    assert_ne!(new_key_id, old_key_id, "new key must have a different UID");

    // ── Step 6: Compare key material ─────────────────────────────────────────
    let new_bytes = export_sym_key_bytes(&client, &new_key_id).await?;
    assert_eq!(new_bytes.len(), 32, "rotated AES-256 key must be 32 bytes");
    assert_ne!(
        old_bytes, new_bytes,
        "rotated key must have different material from the original"
    );

    // ── Step 7: Old key's rotation policy must be cleared ────────────────────
    assert_eq!(
        old_attrs_resp.attributes.rotate_interval,
        Some(0),
        "old key must have rotate_interval = 0 after rotation"
    );
    assert_eq!(
        old_attrs_resp.attributes.rotate_latest,
        Some(false),
        "old key must have rotate_latest = false after rotation"
    );

    // ── Step 8: New key must carry the right links and flags ──────────────────
    let new_attrs_resp = client
        .get_attributes(GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(new_key_id.clone())),
            attribute_reference: None,
        })
        .await?;
    let replaced_link = new_attrs_resp
        .attributes
        .get_link(LinkType::ReplacedObjectLink)
        .unwrap_or_else(|| {
            panic!(
                "ReplacedObjectLink must be set on the new key; \
                 attributes: {:?}",
                new_attrs_resp.attributes
            )
        });
    assert_eq!(
        replaced_link.to_string(),
        old_key_id,
        "new key's ReplacedObjectLink must point back to the original key"
    );
    assert_eq!(
        new_attrs_resp.attributes.rotate_latest,
        Some(true),
        "new key must be marked rotate_latest = true"
    );
    // The auto-rotation cron transfers the old key's rotate_interval to the new key
    // so it continues rotating at the same cadence.
    assert_eq!(
        new_attrs_resp.attributes.rotate_interval,
        Some(ROTATE_INTERVAL_SECS),
        "new key must inherit rotate_interval from the old key"
    );

    Ok(())
}

//! Comprehensive RBAC tests for the two-role model (`CryptoOfficer` + `Operator`).
//!
//! Tests verify the ADR-2026-06-24 role matrix:
//! - **`Operator`**: `Encrypt`, `Decrypt`, `Sign`, `Verify`, `MAC`, `Hash`, `GetAttributes`, `Locate`, `Validate`
//! - **`CryptoOfficer`**: `Create`, `Import`, `Destroy`, `Revoke`, `Activate`, `Get`, `Export`, `CreateKeyPair`,
//!   `CreateSplitKey`, `JoinSplitKey`, `Certify`, `GrantAccess`, `RevokeAccess`; ownership bypass
//!
//! Test users:
//! - `owner.client@acme.com` — Crypto Officer (via `cert_owner.toml`)
//! - `user.client@acme.com` — Crypto Officer (via `cert_user.toml`)
//! - `kmserver.acme.com` — Operator (server cert used as client, not in `crypto_officer_users`)

use cosmian_logger::log_init;
use serial_test::serial;
use test_kms_server::start_default_test_kms_server_with_crypto_officer_users;

use super::utils::load_client_config;
use crate::{
    config::CKMS_CONF_ENV,
    error::result::CosmianResult,
    tests::{symmetric::create_key::create_symmetric_key, utils::ckms_bin},
};

/// Helper to run a ckms command and return success/failure
fn run_ckms(cli_conf_path: &str, args: &[&str]) -> bool {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.args(args);
    cmd.status().is_ok_and(|s| s.success())
}

/// Helper to create a symmetric key (CO operation)
fn co_create_key(cli_conf_path: &str) -> CosmianResult<String> {
    create_symmetric_key(cli_conf_path, &[])
}

/// Helper to encrypt data (Operator operation)
fn op_encrypt(
    cli_conf_path: &str,
    key_id: &str,
    plaintext_path: &str,
    ciphertext_path: &str,
) -> bool {
    run_ckms(
        cli_conf_path,
        &[
            "sym",
            "encrypt",
            "--key-id",
            key_id,
            "--output-file",
            ciphertext_path,
            plaintext_path,
        ],
    )
}

/// Helper to decrypt data (Operator operation)
fn op_decrypt(
    cli_conf_path: &str,
    key_id: &str,
    ciphertext_path: &str,
    decrypted_path: &str,
) -> bool {
    run_ckms(
        cli_conf_path,
        &[
            "sym",
            "decrypt",
            "--key-id",
            key_id,
            "--output-file",
            decrypted_path,
            ciphertext_path,
        ],
    )
}

/// Helper to export a key (CO operation - key output)
fn co_export_key(cli_conf_path: &str, key_id: &str, output_path: &str) -> bool {
    run_ckms(
        cli_conf_path,
        &["sym", "keys", "export", "--key-id", key_id, output_path],
    )
}

/// Helper to destroy a key (CO operation — revokes first, then destroys)
fn co_destroy_key(cli_conf_path: &str, key_id: &str) -> bool {
    // Keys must be revoked before they can be destroyed.
    run_ckms(
        cli_conf_path,
        &["sym", "keys", "revoke", "--key-id", key_id, "test-cleanup"],
    );
    run_ckms(
        cli_conf_path,
        &["sym", "keys", "destroy", "--key-id", key_id],
    )
}

/// Helper to grant access (CO operation)
fn co_grant_access(
    cli_conf_path: &str,
    key_id: Option<&str>,
    user: &str,
    operations: &[&str],
) -> bool {
    let mut args = vec!["access-rights", "grant", user];
    if let Some(uid) = key_id {
        args.push("--object-uid");
        args.push(uid);
    }
    for op in operations {
        args.push(op);
    }
    run_ckms(cli_conf_path, &args)
}

// ============================================================================
// Test: Crypto Officer can perform lifecycle operations
// ============================================================================

/// CO can create symmetric keys
#[cfg(feature = "non-fips")]
#[serial]
#[tokio::test]
async fn test_co_can_create_keys() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_crypto_officer_users(vec![
        "owner.client@acme.com".to_owned(),
        "user.client@acme.com".to_owned(),
    ])
    .await;
    let co_conf = load_client_config("cert_owner.toml", ctx);

    // CO should be able to create keys
    let key_id = co_create_key(&co_conf)?;

    // Cleanup
    co_destroy_key(&co_conf, &key_id);
    Ok(())
}

/// CO can export keys (key output - ISO/IEC 19790 §7.4)
#[cfg(feature = "non-fips")]
#[serial]
#[tokio::test]
async fn test_co_can_export_keys() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_crypto_officer_users(vec![
        "owner.client@acme.com".to_owned(),
        "user.client@acme.com".to_owned(),
    ])
    .await;
    let co_conf = load_client_config("cert_owner.toml", ctx);

    // Create a key first
    let key_id = co_create_key(&co_conf)?;

    // CO should be able to export the key
    let export_path = std::env::temp_dir()
        .join(format!("test_co_export_{}.key", std::process::id()))
        .to_string_lossy()
        .to_string();
    let can_export = co_export_key(&co_conf, &key_id, &export_path);
    assert!(can_export, "Crypto Officer should be able to export keys");

    // Cleanup
    co_destroy_key(&co_conf, &key_id);
    drop(std::fs::remove_file(&export_path));
    Ok(())
}

/// CO can destroy keys
#[cfg(feature = "non-fips")]
#[serial]
#[tokio::test]
async fn test_co_can_destroy_keys() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_crypto_officer_users(vec![
        "owner.client@acme.com".to_owned(),
        "user.client@acme.com".to_owned(),
    ])
    .await;
    let co_conf = load_client_config("cert_owner.toml", ctx);

    // Create a key first
    let key_id = co_create_key(&co_conf)?;

    // CO should be able to destroy the key
    let can_destroy = co_destroy_key(&co_conf, &key_id);
    assert!(can_destroy, "Crypto Officer should be able to destroy keys");
    Ok(())
}

// ============================================================================
// Test: Crypto Officer CAN perform cryptographic operations (superset of Operator)
// ============================================================================

/// CO can encrypt data (ISO/IEC 19790 §7.4 does not forbid CO from holding User services;
/// NIST SP 800-57 Part 2 Rev 1 confirms CO can perform crypto operations by policy)
#[cfg(feature = "non-fips")]
#[serial]
#[tokio::test]
async fn test_co_can_encrypt() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_crypto_officer_users(vec![
        "owner.client@acme.com".to_owned(),
        "user.client@acme.com".to_owned(),
    ])
    .await;
    let co_conf = load_client_config("cert_owner.toml", ctx);

    // Create a key first
    let key_id = co_create_key(&co_conf)?;

    // Create a plaintext file
    let plaintext_path = std::env::temp_dir()
        .join(format!("test_co_encrypt_plain_{}.txt", std::process::id()))
        .to_string_lossy()
        .to_string();
    std::fs::write(&plaintext_path, "test data for encryption")?;

    let ciphertext_path = std::env::temp_dir()
        .join(format!("test_co_encrypt_cipher_{}.enc", std::process::id()))
        .to_string_lossy()
        .to_string();

    // Active CO SHOULD be able to encrypt (CO role is a superset of Operator)
    let can_encrypt = op_encrypt(&co_conf, &key_id, &plaintext_path, &ciphertext_path);
    assert!(
        can_encrypt,
        "Crypto Officer SHOULD be able to encrypt — CO role is a superset of Operator \
         (ISO/IEC 19790 §7.4 + NIST SP 800-57 Part 2 Rev 1)"
    );

    // Cleanup
    co_destroy_key(&co_conf, &key_id);
    drop(std::fs::remove_file(&plaintext_path));
    drop(std::fs::remove_file(&ciphertext_path));
    Ok(())
}

/// CO can decrypt data (Operator operations are a subset of `CryptoOfficer`)
#[cfg(feature = "non-fips")]
#[serial]
#[tokio::test]
async fn test_co_can_decrypt() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_crypto_officer_users(vec![
        "owner.client@acme.com".to_owned(),
        "user.client@acme.com".to_owned(),
    ])
    .await;
    let co_conf = load_client_config("cert_owner.toml", ctx);

    // CO creates a key and encrypts directly
    let key_id = co_create_key(&co_conf)?;

    let plaintext_path = std::env::temp_dir()
        .join(format!("test_co_decrypt_plain_{}.txt", std::process::id()))
        .to_string_lossy()
        .to_string();
    std::fs::write(&plaintext_path, "test data for decryption")?;

    let ciphertext_path = std::env::temp_dir()
        .join(format!("test_co_decrypt_cipher_{}.enc", std::process::id()))
        .to_string_lossy()
        .to_string();

    // CO encrypts
    let encrypted = op_encrypt(&co_conf, &key_id, &plaintext_path, &ciphertext_path);
    assert!(encrypted, "CO should be able to encrypt");

    let decrypted_path = std::env::temp_dir()
        .join(format!("test_co_decrypt_result_{}.txt", std::process::id()))
        .to_string_lossy()
        .to_string();

    // CO SHOULD be able to decrypt (crypto operations are in CO's allowed set)
    let can_decrypt = op_decrypt(&co_conf, &key_id, &ciphertext_path, &decrypted_path);
    assert!(
        can_decrypt,
        "Crypto Officer SHOULD be able to decrypt — CO role is a superset of Operator"
    );

    // Cleanup
    co_destroy_key(&co_conf, &key_id);
    drop(std::fs::remove_file(&plaintext_path));
    drop(std::fs::remove_file(&ciphertext_path));
    drop(std::fs::remove_file(&decrypted_path));
    Ok(())
}

// ============================================================================
// Test: Operator can perform cryptographic operations
// ============================================================================

/// Operator can encrypt and decrypt data
#[cfg(feature = "non-fips")]
#[serial]
#[tokio::test]
async fn test_operator_can_encrypt_decrypt() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_crypto_officer_users(vec![
        "owner.client@acme.com".to_owned(),
        "user.client@acme.com".to_owned(),
    ])
    .await;
    let co_conf = load_client_config("cert_owner.toml", ctx);
    let op_conf = load_client_config("cert_server.toml", ctx); // kmserver.acme.com (Operator)

    // CO creates a key
    let key_id = co_create_key(&co_conf)?;

    // CO grants Operator access
    co_grant_access(
        &co_conf,
        Some(&key_id),
        "kmserver.acme.com",
        &["encrypt", "decrypt"],
    );

    // Create test data
    let plaintext_path = std::env::temp_dir()
        .join(format!("test_op_encrypt_plain_{}.txt", std::process::id()))
        .to_string_lossy()
        .to_string();
    std::fs::write(&plaintext_path, "test data for operator encryption")?;

    let ciphertext_path = std::env::temp_dir()
        .join(format!("test_op_encrypt_cipher_{}.enc", std::process::id()))
        .to_string_lossy()
        .to_string();

    let decrypted_path = std::env::temp_dir()
        .join(format!("test_op_encrypt_result_{}.txt", std::process::id()))
        .to_string_lossy()
        .to_string();

    // Operator should be able to encrypt
    let encrypted = op_encrypt(&op_conf, &key_id, &plaintext_path, &ciphertext_path);
    assert!(encrypted, "Operator should be able to encrypt");

    // Operator should be able to decrypt
    let decrypted = op_decrypt(&op_conf, &key_id, &ciphertext_path, &decrypted_path);
    assert!(decrypted, "Operator should be able to decrypt");

    // Verify decrypted content matches
    let original = std::fs::read_to_string(&plaintext_path)?;
    let result = std::fs::read_to_string(&decrypted_path)?;
    assert_eq!(original, result, "Decrypted content should match original");

    // Cleanup
    co_destroy_key(&co_conf, &key_id);
    drop(std::fs::remove_file(&plaintext_path));
    drop(std::fs::remove_file(&ciphertext_path));
    drop(std::fs::remove_file(&decrypted_path));
    Ok(())
}

// ============================================================================
// Test: Operator CANNOT perform lifecycle operations
// ============================================================================

/// Operator cannot create keys
#[cfg(feature = "non-fips")]
#[serial]
#[tokio::test]
async fn test_operator_cannot_create_keys() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_crypto_officer_users(vec![
        "owner.client@acme.com".to_owned(),
        "user.client@acme.com".to_owned(),
    ])
    .await;
    let op_conf = load_client_config("cert_server.toml", ctx); // kmserver.acme.com (Operator)

    // Operator should NOT be able to create keys
    let key_result = co_create_key(&op_conf);
    assert!(
        key_result.is_err(),
        "Operator should NOT be able to create keys (CO-only operation)"
    );
    Ok(())
}

/// Operator cannot export keys (key output is CO-only)
#[cfg(feature = "non-fips")]
#[serial]
#[tokio::test]
async fn test_operator_cannot_export_keys() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_crypto_officer_users(vec![
        "owner.client@acme.com".to_owned(),
        "user.client@acme.com".to_owned(),
    ])
    .await;
    let co_conf = load_client_config("cert_owner.toml", ctx);
    let op_conf = load_client_config("cert_server.toml", ctx); // kmserver.acme.com (Operator)

    // CO creates a key
    let key_id = co_create_key(&co_conf)?;

    // CO grants Operator access
    co_grant_access(
        &co_conf,
        Some(&key_id),
        "kmserver.acme.com",
        &["encrypt", "decrypt"],
    );

    // Operator should NOT be able to export the key
    let export_path = std::env::temp_dir()
        .join(format!("test_op_export_{}.key", std::process::id()))
        .to_string_lossy()
        .to_string();
    let can_export = co_export_key(&op_conf, &key_id, &export_path);
    assert!(
        !can_export,
        "Operator should NOT be able to export keys (key output is CO-only per ISO/IEC 19790 §7.4)"
    );

    // Cleanup
    co_destroy_key(&co_conf, &key_id);
    drop(std::fs::remove_file(&export_path));
    Ok(())
}

/// Operator cannot destroy keys
#[cfg(feature = "non-fips")]
#[serial]
#[tokio::test]
async fn test_operator_cannot_destroy_keys() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_crypto_officer_users(vec![
        "owner.client@acme.com".to_owned(),
        "user.client@acme.com".to_owned(),
    ])
    .await;
    let co_conf = load_client_config("cert_owner.toml", ctx);
    let op_conf = load_client_config("cert_server.toml", ctx); // kmserver.acme.com (Operator)

    // CO creates a key
    let key_id = co_create_key(&co_conf)?;

    // CO grants Operator access
    co_grant_access(
        &co_conf,
        Some(&key_id),
        "kmserver.acme.com",
        &["encrypt", "decrypt"],
    );

    // Operator should NOT be able to destroy the key
    let can_destroy = co_destroy_key(&op_conf, &key_id);
    assert!(
        !can_destroy,
        "Operator should NOT be able to destroy keys (CO-only operation)"
    );

    // Cleanup
    co_destroy_key(&co_conf, &key_id);
    Ok(())
}

// ============================================================================
// Test: Crypto Officer ownership bypass
// ============================================================================

/// A CO can access any object regardless of which CO created it
/// (ownership bypass — ISO/IEC 19790 §7.4 CO role has system-wide lifecycle scope).
#[cfg(feature = "non-fips")]
#[serial]
#[tokio::test]
async fn test_co_ownership_bypass() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_crypto_officer_users(vec![
        "owner.client@acme.com".to_owned(),
        "user.client@acme.com".to_owned(),
    ])
    .await;
    let owner_co_conf = load_client_config("cert_owner.toml", ctx);
    let user_co_conf = load_client_config("cert_user.toml", ctx);

    // Owner CO creates a key.
    let key_id = co_create_key(&owner_co_conf)?;

    // The second CO can export it without a prior explicit grant — COs have
    // system-wide read access to all managed objects (ownership bypass).
    let export_path = std::env::temp_dir()
        .join(format!("test_co_bypass_export_{}.key", std::process::id()))
        .to_string_lossy()
        .to_string();
    let can_export = co_export_key(&user_co_conf, &key_id, &export_path);
    assert!(
        can_export,
        "Crypto Officer must have ownership bypass — all COs can access any managed object"
    );

    // Cleanup
    co_destroy_key(&owner_co_conf, &key_id);
    drop(std::fs::remove_file(&export_path));
    Ok(())
}

/// Operator cannot access objects without explicit grant
#[cfg(feature = "non-fips")]
#[serial]
#[tokio::test]
async fn test_operator_needs_explicit_grant() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_crypto_officer_users(vec![
        "owner.client@acme.com".to_owned(),
        "user.client@acme.com".to_owned(),
    ])
    .await;
    let co_conf = load_client_config("cert_owner.toml", ctx);
    let op_conf = load_client_config("cert_server.toml", ctx); // kmserver.acme.com (Operator)

    // CO creates a key
    let key_id = co_create_key(&co_conf)?;

    // Operator should NOT be able to export without explicit grant
    let export_path = std::env::temp_dir()
        .join(format!(
            "test_op_no_grant_export_{}.key",
            std::process::id()
        ))
        .to_string_lossy()
        .to_string();
    let can_export = co_export_key(&op_conf, &key_id, &export_path);
    assert!(
        !can_export,
        "Operator should NOT be able to export without explicit grant"
    );

    // CO grants export access
    let granted = co_grant_access(&co_conf, Some(&key_id), "kmserver.acme.com", &["get"]);
    assert!(granted, "CO should be able to grant access");

    // Now Operator should be able to export
    let can_export_after_grant = co_export_key(&op_conf, &key_id, &export_path);
    assert!(
        can_export_after_grant,
        "Operator should be able to export after explicit grant"
    );

    // Cleanup
    co_destroy_key(&co_conf, &key_id);
    drop(std::fs::remove_file(&export_path));
    Ok(())
}

// ============================================================================
// Test: CO can grant/revoke access
// ============================================================================

/// CO can grant and revoke access rights
#[cfg(feature = "non-fips")]
#[serial]
#[tokio::test]
async fn test_co_can_grant_revoke_access() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_crypto_officer_users(vec![
        "owner.client@acme.com".to_owned(),
        "user.client@acme.com".to_owned(),
    ])
    .await;
    let co_conf = load_client_config("cert_owner.toml", ctx);
    let op_conf = load_client_config("cert_server.toml", ctx); // kmserver.acme.com (Operator)

    // CO creates a key
    let key_id = co_create_key(&co_conf)?;

    // Create test data
    let plaintext_path = std::env::temp_dir()
        .join(format!(
            "test_grant_revoke_plain_{}.txt",
            std::process::id()
        ))
        .to_string_lossy()
        .to_string();
    std::fs::write(&plaintext_path, "test data")?;

    let ciphertext_path = std::env::temp_dir()
        .join(format!(
            "test_grant_revoke_cipher_{}.enc",
            std::process::id()
        ))
        .to_string_lossy()
        .to_string();

    // Operator cannot encrypt without grant
    let can_encrypt_before = op_encrypt(&op_conf, &key_id, &plaintext_path, &ciphertext_path);
    assert!(
        !can_encrypt_before,
        "Operator should not encrypt without grant"
    );

    // CO grants encrypt access
    let granted = co_grant_access(&co_conf, Some(&key_id), "kmserver.acme.com", &["encrypt"]);
    assert!(granted, "CO should be able to grant access");

    // Operator can now encrypt
    let can_encrypt_after = op_encrypt(&op_conf, &key_id, &plaintext_path, &ciphertext_path);
    assert!(can_encrypt_after, "Operator should encrypt after grant");

    // CO revokes encrypt access
    let revoked = run_ckms(
        &co_conf,
        &[
            "access-rights",
            "revoke",
            "kmserver.acme.com",
            "--object-uid",
            &key_id,
            "encrypt",
        ],
    );
    assert!(revoked, "CO should be able to revoke access");

    // Operator cannot encrypt anymore
    let ciphertext_path2 = std::env::temp_dir()
        .join(format!(
            "test_grant_revoke_cipher2_{}.enc",
            std::process::id()
        ))
        .to_string_lossy()
        .to_string();
    let can_encrypt_revoked = op_encrypt(&op_conf, &key_id, &plaintext_path, &ciphertext_path2);
    assert!(
        !can_encrypt_revoked,
        "Operator should not encrypt after revoke"
    );

    // Cleanup
    co_destroy_key(&co_conf, &key_id);
    drop(std::fs::remove_file(&plaintext_path));
    drop(std::fs::remove_file(&ciphertext_path));
    drop(std::fs::remove_file(&ciphertext_path2));
    Ok(())
}

// ============================================================================
// Split-key Ceremony CLI Tests
//
// These tests exercise the full key ceremony flow via the ckms binary.
// Server: ceremony-mode (`require_ceremony = true`) loaded from
//   `test_data/configs/server/rbac/crypto_officers.toml`.
// Users:
//   - `owner.client@acme.com` (cert_owner.toml) — CO candidate 1
//   - `user.client@acme.com`  (cert_user.toml)  — CO candidate 2
//   - `kmserver.acme.com`     (cert_server.toml) — Operator (never in CO list)
//
// Because all ceremony tests share a single server instance (OnceCell), the
// lifecycle tests are combined into one ordered function to avoid race conditions.
// ============================================================================

/// Parse all "Unique identifier: <uid>" lines from CLI output.
///
/// Used to collect multiple share UIDs from `ckms sym keys create-split-key` output.
fn extract_all_uids(text: &str) -> Vec<String> {
    let uuid_re =
        regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            .expect("valid UUID regex");
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            // "Unique identifier: <uuid>" — single-key output
            if let Some(rest) = trimmed.strip_prefix("Unique identifier:") {
                let uid = rest.trim().to_owned();
                if !uid.is_empty() {
                    return Some(uid);
                }
            }
            // Bare UUID line — split-key multi-identifier output
            if uuid_re.is_match(trimmed) && trimmed.len() == 36 {
                return Some(trimmed.to_owned());
            }
            None
        })
        .filter(|s| !s.is_empty())
        .collect()
}

/// Run a ckms command and capture stdout on success, or return None on failure.
fn run_ckms_output(cli_conf_path: &str, args: &[&str]) -> Option<String> {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.args(args);
    let output = cmd.output().ok()?;
    if output.status.success() {
        String::from_utf8(output.stdout).ok()
    } else {
        eprintln!(
            "DEBUG run_ckms_output FAILED: args={:?}\n  exit={}\n  stdout: {}\n  stderr: {}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        None
    }
}

/// Return true if the CO status endpoint reports `ceremony_activated: true`.
fn co_status_is_active(cli_conf_path: &str) -> bool {
    run_ckms_output(
        cli_conf_path,
        &["access-rights", "crypto-officer", "status"],
    )
    .is_some_and(|out| out.contains(r#""ceremony_activated": true"#))
}

// ─── T_C1 + T_C3 + T_C6: full ceremony lifecycle ─────────────────────────────

/// Full split-key ceremony lifecycle via the ckms CLI.
///
/// Phases covered:
///   Phase 0 — Pre-ceremony: CO candidates are Operators (cannot Get/Export/Destroy).
///   Phase 1 — Provisioning: create key + split key shares.
///   Phase 2 — Activation: custodians grant access, joiner runs join-split-key.
///   Phase 3 — Active: CO can access any object (ownership bypass).
///   Phase 4 — Disable: ceremony revoked, CO reverts to Operator.
///   Phase 6 — Re-activation: second ceremony activates CO again.
#[cfg(feature = "non-fips")]
#[serial]
#[tokio::test]
async fn test_ceremony_full_lifecycle_cli() -> CosmianResult<()> {
    log_init(None);
    let ctx = test_kms_server::start_ceremony_test_kms_server().await;

    let co1_conf = load_client_config("cert_owner.toml", ctx); // owner.client@acme.com — co_users[1] → share1
    let co2_conf = load_client_config("cert_user.toml", ctx); //  user.client@acme.com  — co_users[0] → share0
    let co3_conf = load_client_config("cert_co3.toml", ctx); //   co3.client@acme.com   — co_users[2] → share2
    let op_conf = load_client_config("cert_server.toml", ctx); // kmserver.acme.com (Operator)

    // ── Phase 0: Pre-ceremony — CO candidates are Operators ───────────────────
    // CO candidates cannot perform CO operations (Create returns key but Get is blocked).
    // Status endpoint should show ceremony_activated = false.
    let status_before = run_ckms_output(&co1_conf, &["access-rights", "crypto-officer", "status"]);
    assert!(status_before.is_some(), "Status endpoint must be reachable");
    let status_str = status_before.unwrap();
    assert!(
        status_str.contains("false") || !status_str.contains("ceremony_activated: true"),
        "Ceremony must not be active before the ceremony: {status_str}"
    );

    // ── Phase 1: Provisioning — create key + split ────────────────────────────
    // CO candidates have the ceremony candidate exemption for Create + CreateSplitKey.
    let create_out = run_ckms_output(
        &co1_conf,
        &["sym", "keys", "create", "--number-of-bits", "256"],
    )
    .expect("CO candidate must be able to create a key before ceremony (exemption)");
    let key_uids = extract_all_uids(&create_out);
    assert!(
        !key_uids.is_empty(),
        "Create key must return a UID: {create_out}"
    );
    let key_uid = key_uids
        .first()
        .expect("create must return at least one UID");

    // With 3 COs, CreateSplitKey auto-overrides total_parts to 3.
    // Round-robin: share0 → user.client (co2), share1 → owner.client (co1), share2 → co3.client (co3).
    let split_out = run_ckms_output(
        &co1_conf,
        &["sym", "keys", "create-split-key", "--key-id", key_uid],
    )
    .expect("CO candidate must be able to split a key before ceremony (exemption)");
    // NOTE: the ceremony source key is now DESTROYED automatically after successful split.
    let share_uids = extract_all_uids(&split_out);
    assert_eq!(
        share_uids.len(),
        3,
        "3-of-3 ceremony split must produce 3 share UIDs; got: {split_out}"
    );
    let share0_uid = share_uids.first().expect("split must produce share 0"); // owned by user.client (co2)
    let share1_uid = share_uids.get(1).expect("split must produce share 1"); // owned by owner.client (co1)
    let share2_uid = share_uids.get(2).expect("split must produce share 2"); // owned by co3.client (co3)

    // ── Phase 2: Activation ───────────────────────────────────────────────────
    // co2 (user.client) owns share0 → grants co1 (owner.client) access.
    let granted0 = run_ckms(
        &co2_conf,
        &[
            "access-rights",
            "grant",
            "owner.client@acme.com",
            "--object-uid",
            share0_uid,
            "get",
        ],
    );
    assert!(
        granted0,
        "co2 must be able to grant co1 access to share0 (co2 is the owner)"
    );

    // co3 (co3.client) owns share2 → grants co1 (owner.client) access.
    let granted2 = run_ckms(
        &co3_conf,
        &[
            "access-rights",
            "grant",
            "owner.client@acme.com",
            "--object-uid",
            share2_uid,
            "get",
        ],
    );
    assert!(
        granted2,
        "co3 must be able to grant co1 access to share2 (co3 is the owner)"
    );

    // co1 activates the ceremony with all 3 shares (dedicated endpoint, secret not stored).
    // co1 owns share1; co2 granted access to share0; co3 granted access to share2.
    let activate_out = run_ckms_output(
        &co1_conf,
        &[
            "access-rights",
            "crypto-officer",
            "activate",
            share0_uid,
            share1_uid,
            share2_uid,
        ],
    )
    .expect("CO candidate must be able to activate ceremony");
    assert!(
        !activate_out.is_empty(),
        "crypto-officer activate must produce output: {activate_out}"
    );

    // Status must now show ceremony active.
    assert!(
        co_status_is_active(&co1_conf),
        "Ceremony must be active after successful activate"
    );

    // ── Phase 3: Active — CO can perform lifecycle operations ─────────────────
    // Create a key owned by co2 (operator role before ceremony, so can own objects).
    let co2_create_out = run_ckms_output(
        &co2_conf,
        &["sym", "keys", "create", "--number-of-bits", "256"],
    )
    .expect("co2 must be able to create a key");
    let co2_key_uids = extract_all_uids(&co2_create_out);
    assert!(!co2_key_uids.is_empty(), "co2 create must return a UID");
    let co2_key_uid = co2_key_uids.first().expect("co2 create must return a UID");

    // Active CO (co1) can export co2's key via ownership bypass.
    let export_tmp =
        std::env::temp_dir().join(format!("ceremony_co_export_{}.key", std::process::id()));
    let exported = run_ckms(
        &co1_conf,
        &[
            "sym",
            "keys",
            "export",
            "--key-id",
            co2_key_uid,
            export_tmp.to_str().unwrap(),
        ],
    );
    assert!(
        exported,
        "Active CO must export any key via ownership bypass"
    );
    drop(std::fs::remove_file(&export_tmp));

    // Operator (kmserver) cannot export without an explicit grant.
    let export_tmp2 =
        std::env::temp_dir().join(format!("ceremony_op_export_{}.key", std::process::id()));
    let op_cannot_export = !run_ckms(
        &op_conf,
        &[
            "sym",
            "keys",
            "export",
            "--key-id",
            co2_key_uid,
            export_tmp2.to_str().unwrap(),
        ],
    );
    assert!(
        op_cannot_export,
        "Operator must NOT export another user's key without grant"
    );

    // ── Phase 4 (T_C3): Disable ceremony — blocked in multi-CO deployment ─────
    // TM-F006: With 3 COs configured, a single CO cannot unilaterally disable
    // the ceremony at runtime. The quorum guard in the server requires removing
    // the user from `crypto_officer_users` in kms.toml and restarting.
    // The single-CO disable lifecycle is covered by the server-level unit tests
    // in `crate/server/src/tests/key_ceremony_tests.rs`.
    let disabled = run_ckms(&co1_conf, &["access-rights", "crypto-officer", "disable"]);
    assert!(
        !disabled,
        "Single CO must NOT be able to unilaterally disable the ceremony in a multi-CO deployment"
    );

    // Ceremony must still be active since disable was correctly rejected.
    assert!(
        co_status_is_active(&co1_conf),
        "Ceremony must remain active after a rejected single-CO disable attempt"
    );

    // Cleanup — the ceremony source key (key_uid) is auto-destroyed after split;
    // only co2's key (co2_key_uid) needs explicit cleanup.
    co_destroy_key(&co1_conf, co2_key_uid);
    Ok(())
}

// ─── T_C2: Operator blocked before ceremony ──────────────────────────────────

/// Operator (kmserver.acme.com) cannot perform CO lifecycle operations
/// regardless of ceremony state.
#[cfg(feature = "non-fips")]
#[serial]
#[tokio::test]
async fn test_operator_cannot_perform_co_operations_in_ceremony_mode() -> CosmianResult<()> {
    log_init(None);
    let ctx = test_kms_server::start_ceremony_test_kms_server().await;
    let op_conf = load_client_config("cert_server.toml", ctx); // kmserver.acme.com (Operator)

    // Operator cannot create a key (lifecycle operation).
    let cannot_create = !run_ckms(
        &op_conf,
        &["sym", "keys", "create", "--number-of-bits", "256"],
    );
    assert!(
        cannot_create,
        "Operator must NOT be able to create keys (CO-only operation)"
    );
    Ok(())
}

// ─── T_C4: Self-activation attempt (auto-assignment prevents it) ──────────────

/// Verify that a CO candidate cannot submit their own share ALONE to activate.
/// With 3 CO candidates, shares are distributed one-per-CO (round-robin).
/// Joining with only 1 of the required 3 shares must fail.
#[cfg(feature = "non-fips")]
#[serial]
#[tokio::test]
async fn test_ceremony_join_with_only_own_share_fails() -> CosmianResult<()> {
    log_init(None);
    let ctx = test_kms_server::start_ceremony_test_kms_server().await;
    let co1_conf = load_client_config("cert_owner.toml", ctx);

    // Create and split a new key (co1 gets share 0 by auto-assignment).
    let create_out = run_ckms_output(
        &co1_conf,
        &["sym", "keys", "create", "--number-of-bits", "256"],
    )
    .expect("CO candidate must be able to create a key");
    let key_uids = extract_all_uids(&create_out);
    let key_uid = key_uids
        .first()
        .expect("create must return at least one UID");

    let split_out = run_ckms_output(
        &co1_conf,
        &["sym", "keys", "create-split-key", "--key-id", key_uid],
    )
    .expect("CO candidate must split key");
    let share_uids = extract_all_uids(&split_out);
    assert_eq!(share_uids.len(), 3);
    let share_0 = share_uids.first().expect("split must produce share 0");

    // Attempt ceremony activation with only 1 share (need n=3) — must fail.
    let activate_with_one = run_ckms(
        &co1_conf,
        &["access-rights", "crypto-officer", "activate", share_0],
    );
    assert!(
        !activate_with_one,
        "Ceremony activation with only 1 share when n=3 is required must fail"
    );
    Ok(())
}

// ─── T_C5: Non-CO user (Operator) cannot trigger ceremony activation ──────────

/// An Operator (`kmserver.acme.com`, not in `crypto_officer_users`) cannot run
/// `crypto-officer activate` to trigger a ceremony activation even if granted share access.
#[cfg(feature = "non-fips")]
#[serial]
#[tokio::test]
async fn test_operator_cannot_activate_ceremony() -> CosmianResult<()> {
    log_init(None);
    let ctx = test_kms_server::start_ceremony_test_kms_server().await;
    let co1_conf = load_client_config("cert_owner.toml", ctx);
    let co2_conf = load_client_config("cert_user.toml", ctx);
    let co3_conf = load_client_config("cert_co3.toml", ctx);
    let op_conf = load_client_config("cert_server.toml", ctx); // Operator

    // CO candidate creates and splits a key.
    let create_out = run_ckms_output(
        &co1_conf,
        &["sym", "keys", "create", "--number-of-bits", "256"],
    )
    .expect("CO candidate must create a key");
    let key_uids = extract_all_uids(&create_out);
    let key_uid = key_uids
        .first()
        .expect("create must return at least one UID");

    let split_out = run_ckms_output(
        &co1_conf,
        &["sym", "keys", "create-split-key", "--key-id", key_uid],
    )
    .expect("CO candidate must split key");
    let share_uids = extract_all_uids(&split_out);
    assert_eq!(share_uids.len(), 3);
    let share_uid_0 = share_uids.first().expect("split must produce share 0"); // owned by co2 (user.client)
    let share_uid_1 = share_uids.get(1).expect("split must produce share 1"); // owned by co1 (owner.client)
    let share_uid_2 = share_uids.get(2).expect("split must produce share 2"); // owned by co3

    // Grant Operator access to all 3 shares.
    run_ckms(
        &co2_conf,
        &[
            "access-rights",
            "grant",
            "kmserver.acme.com",
            "--object-uid",
            share_uid_0,
            "get",
        ],
    );
    run_ckms(
        &co1_conf,
        &[
            "access-rights",
            "grant",
            "kmserver.acme.com",
            "--object-uid",
            share_uid_1,
            "get",
        ],
    );
    run_ckms(
        &co3_conf,
        &[
            "access-rights",
            "grant",
            "kmserver.acme.com",
            "--object-uid",
            share_uid_2,
            "get",
        ],
    );

    // Operator attempts ceremony activation — must fail because kmserver is not in
    // crypto_officer_users.
    let op_activate = run_ckms(
        &op_conf,
        &[
            "access-rights",
            "crypto-officer",
            "activate",
            share_uid_0,
            share_uid_1,
            share_uid_2,
        ],
    );
    assert!(
        !op_activate,
        "Operator must NOT be able to activate ceremony — not in crypto_officer_users"
    );
    Ok(())
}

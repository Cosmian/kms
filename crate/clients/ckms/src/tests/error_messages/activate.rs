// KMIP 2.1 Activate Operation Compliance Tests (CLI-level)
// Verifies that the `ckms sym keys activate` command returns proper errors
// per KMIP 2.1 Table 166: Activate Errors

use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::utils::{extract_uids::extract_uid, owner_config, run_ckms, run_ckms_expect_error},
};

/// Test that newly-created symmetric keys are already in Active state.
/// The server auto-activates keys on creation, so `activate` on a fresh key
/// must return `Wrong_Key_Lifecycle_State`.
#[tokio::test]
async fn test_activate_success() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    // Create a key (auto-activated by the server)
    let stdout = run_ckms(&conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    // Key is already Active → activate must fail with lifecycle error
    let stderr = run_ckms_expect_error(&conf, &["sym", "keys", "activate", "-k", key_id])?;
    assert!(
        stderr.contains("Wrong_Key_Lifecycle_State") || stderr.contains("already in Active"),
        "Expected lifecycle error for already-active key, got: {stderr}"
    );

    Ok(())
}

/// Test KMIP 2.1 Error: Object Not Found
#[tokio::test]
async fn test_activate_object_not_found() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let stderr = run_ckms_expect_error(
        &conf,
        &["sym", "keys", "activate", "-k", "non-existent-key-id-12345"],
    )?;
    assert!(
        stderr.contains("Object_Not_Found") || stderr.contains("Item_Not_Found"),
        "Expected Object_Not_Found error, got: {stderr}"
    );

    Ok(())
}

/// Test KMIP 2.1 Error: Wrong Key Lifecycle State - Already Active
#[tokio::test]
async fn test_activate_already_active() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    // Create a key (auto-activated by server)
    let stdout = run_ckms(&conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    // Try to activate an already-active key → should fail
    let stderr = run_ckms_expect_error(&conf, &["sym", "keys", "activate", "-k", key_id])?;
    assert!(
        stderr.contains("Wrong_Key_Lifecycle_State"),
        "Expected Wrong_Key_Lifecycle_State error, got: {stderr}"
    );

    Ok(())
}

/// Test KMIP 2.1 Error: Wrong Key Lifecycle State - Deactivated (Revoked)
#[tokio::test]
async fn test_activate_deactivated_key() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    // Create a key (auto-activated)
    let stdout = run_ckms(&conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    // Revoke the key (deactivate)
    run_ckms(
        &conf,
        &["sym", "keys", "revoke", "test revocation", "-k", key_id],
    )?;

    // Try to activate a revoked key → should fail
    let stderr = run_ckms_expect_error(&conf, &["sym", "keys", "activate", "-k", key_id])?;
    assert!(
        stderr.contains("Wrong_Key_Lifecycle_State"),
        "Expected Wrong_Key_Lifecycle_State error for deactivated key, got: {stderr}"
    );

    Ok(())
}

/// Test KMIP 2.1 Error: Wrong Key Lifecycle State - Destroyed
#[tokio::test]
async fn test_activate_destroyed_key() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    // Create a key (auto-activated)
    let stdout = run_ckms(&conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    // Revoke then destroy
    run_ckms(
        &conf,
        &[
            "sym",
            "keys",
            "revoke",
            "revoke before destroy",
            "-k",
            key_id,
        ],
    )?;
    run_ckms(&conf, &["sym", "keys", "destroy", "-k", key_id])?;

    // Try to activate a destroyed key → should fail
    let stderr = run_ckms_expect_error(&conf, &["sym", "keys", "activate", "-k", key_id])?;
    assert!(
        stderr.contains("Wrong_Key_Lifecycle_State"),
        "Expected Wrong_Key_Lifecycle_State error for destroyed key, got: {stderr}"
    );

    Ok(())
}

/// Test KMIP 2.1 Error: Wrong Key Lifecycle State - Compromised
#[tokio::test]
async fn test_activate_compromised_key() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    // Create a key (auto-activated)
    let stdout = run_ckms(&conf, &["sym", "keys", "create"])?;
    let key_id =
        extract_uid(&stdout, "Unique identifier").expect("should extract key unique identifier");

    // Revoke with compromised reason
    run_ckms(
        &conf,
        &["sym", "keys", "revoke", "key compromise", "-k", key_id],
    )?;

    // Try to activate a compromised key → should fail
    let stderr = run_ckms_expect_error(&conf, &["sym", "keys", "activate", "-k", key_id])?;
    assert!(
        stderr.contains("Wrong_Key_Lifecycle_State"),
        "Expected Wrong_Key_Lifecycle_State error for compromised key, got: {stderr}"
    );

    Ok(())
}

/// Test that EC keys are also auto-activated on creation
#[tokio::test]
async fn test_activate_ec_key() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    // Create an EC key pair (auto-activated)
    let stdout = run_ckms(&conf, &["ec", "keys", "create"])?;
    let private_key_id = extract_uid(&stdout, "Private key unique identifier")
        .expect("should extract private key uid");

    // Key is already Active → activate must fail
    let stderr = run_ckms_expect_error(&conf, &["ec", "keys", "activate", "-k", private_key_id])?;
    assert!(
        stderr.contains("Wrong_Key_Lifecycle_State") || stderr.contains("already in Active"),
        "Expected lifecycle error for already-active EC key, got: {stderr}"
    );

    Ok(())
}

/// Test that RSA keys are also auto-activated on creation
#[tokio::test]
async fn test_activate_rsa_key() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    // Create an RSA key pair (auto-activated)
    let stdout = run_ckms(&conf, &["rsa", "keys", "create"])?;
    let private_key_id = extract_uid(&stdout, "Private key unique identifier")
        .expect("should extract private key uid");

    // Key is already Active → activate must fail
    let stderr = run_ckms_expect_error(&conf, &["rsa", "keys", "activate", "-k", private_key_id])?;
    assert!(
        stderr.contains("Wrong_Key_Lifecycle_State") || stderr.contains("already in Active"),
        "Expected lifecycle error for already-active RSA key, got: {stderr}"
    );

    Ok(())
}

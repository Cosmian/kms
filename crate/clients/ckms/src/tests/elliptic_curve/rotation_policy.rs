use test_kms_server::start_default_test_kms_server;

use super::create_key_pair::create_ec_key_pair;
use crate::{
    error::result::CosmianResult,
    tests::utils::{owner_config, run_ckms},
};

#[tokio::test]
pub(crate) async fn test_ec_set_and_get_rotation_policy() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create an EC key pair (P-256)
    let (private_key_id, _public_key_id) =
        create_ec_key_pair(&owner_client_conf_path, "nist-p256", &[], false)?;

    // Set rotation policy on the private key with interval and name
    let args = vec![
        "ec",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &private_key_id,
        "--interval",
        "172800",
        "--rotation-name",
        "ec-keyset",
    ];
    let output = run_ckms(&owner_client_conf_path, &args)?;
    assert!(
        output.contains("Rotation policy set successfully"),
        "expected success message in: {output}"
    );

    // Get rotation policy and verify
    let args = vec![
        "ec",
        "keys",
        "get-rotation-policy",
        "--key-id",
        &private_key_id,
    ];
    let output = run_ckms(&owner_client_conf_path, &args)?;
    assert!(
        output.contains("172800"),
        "expected interval=172800 in: {output}"
    );
    assert!(
        output.contains("ec-keyset"),
        "expected name=ec-keyset in: {output}"
    );

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_ec_rekey() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create an EC key pair (P-256)
    let (private_key_id, _public_key_id) =
        create_ec_key_pair(&owner_client_conf_path, "nist-p256", &[], false)?;

    // Re-Key the EC key pair
    let args = vec!["ec", "keys", "re-key", "--key-id", &private_key_id];
    let output = run_ckms(&owner_client_conf_path, &args)?;
    assert!(
        output.contains("rotated"),
        "expected 'rotated' in: {output}"
    );
    assert!(
        output.contains("Unique identifier"),
        "expected new UID in: {output}"
    );

    Ok(())
}

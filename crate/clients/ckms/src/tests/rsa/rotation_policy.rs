use test_kms_server::start_default_test_kms_server;

use super::create_key_pair::{RsaKeyPairOptions, create_rsa_key_pair};
use crate::{
    error::result::CosmianResult,
    tests::utils::{owner_config, run_ckms},
};

#[tokio::test]
pub(crate) async fn test_rsa_set_and_get_rotation_policy() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create an RSA key pair
    let (private_key_id, _public_key_id) = create_rsa_key_pair(
        &owner_client_conf_path,
        &RsaKeyPairOptions {
            number_of_bits: Some(2048),
            ..Default::default()
        },
    )?;

    // Set rotation policy on the private key with interval, offset, and name
    let args = vec![
        "rsa",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &private_key_id,
        "--interval",
        "86400",
        "--offset",
        "7200",
        "--rotation-name",
        "rsa-keyset",
    ];
    let output = run_ckms(&owner_client_conf_path, &args)?;
    assert!(
        output.contains("Rotation policy set successfully"),
        "expected success message in: {output}"
    );

    // Get rotation policy and verify
    let args = vec![
        "rsa",
        "keys",
        "get-rotation-policy",
        "--key-id",
        &private_key_id,
    ];
    let output = run_ckms(&owner_client_conf_path, &args)?;
    assert!(
        output.contains("86400"),
        "expected interval=86400 in: {output}"
    );
    assert!(output.contains("7200"), "expected offset=7200 in: {output}");
    assert!(
        output.contains("rsa-keyset"),
        "expected name=rsa-keyset in: {output}"
    );

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_rsa_rekey() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create an RSA key pair
    let (private_key_id, _public_key_id) = create_rsa_key_pair(
        &owner_client_conf_path,
        &RsaKeyPairOptions {
            number_of_bits: Some(2048),
            ..Default::default()
        },
    )?;

    // Re-Key the RSA key pair
    let args = vec!["rsa", "keys", "re-key", "--key-id", &private_key_id];
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

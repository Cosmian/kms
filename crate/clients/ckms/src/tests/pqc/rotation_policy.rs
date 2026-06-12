use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::utils::{owner_config, run_ckms},
};

/// Create a ML-KEM key pair using `run_ckms` and return (`private_key_id`, `public_key_id`)
fn create_ml_kem_key_pair(cli_conf_path: &str) -> CosmianResult<(String, String)> {
    let args = vec!["pqc", "keys", "create", "--algorithm", "ml-kem-768"];
    let output = run_ckms(cli_conf_path, &args)?;
    // Parse "Private key unique identifier: xxx"
    let sk_id = output
        .lines()
        .find(|l| l.contains("Private key unique identifier"))
        .and_then(|l| l.split(':').next_back())
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();
    let pk_id = output
        .lines()
        .find(|l| l.contains("Public key unique identifier"))
        .and_then(|l| l.split(':').next_back())
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();
    Ok((sk_id, pk_id))
}

#[tokio::test]
pub(crate) async fn test_pqc_set_and_get_rotation_policy() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create a ML-KEM key pair
    let (private_key_id, _public_key_id) = create_ml_kem_key_pair(&owner_client_conf_path)?;

    // Set rotation policy
    let args = vec![
        "pqc",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &private_key_id,
        "--interval",
        "259200",
        "--rotation-name",
        "pqc-keyset",
    ];
    let output = run_ckms(&owner_client_conf_path, &args)?;
    assert!(
        output.contains("Rotation policy set successfully"),
        "expected success message in: {output}"
    );

    // Get rotation policy and verify
    let args = vec![
        "pqc",
        "keys",
        "get-rotation-policy",
        "--key-id",
        &private_key_id,
    ];
    let output = run_ckms(&owner_client_conf_path, &args)?;
    assert!(
        output.contains("259200"),
        "expected interval=259200 in: {output}"
    );
    assert!(
        output.contains("pqc-keyset"),
        "expected name=pqc-keyset in: {output}"
    );

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_pqc_rekey() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    // Create a ML-KEM key pair
    let (private_key_id, _public_key_id) = create_ml_kem_key_pair(&owner_client_conf_path)?;

    // Re-Key the PQC key pair
    let args = vec!["pqc", "keys", "re-key", "--key-id", &private_key_id];
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

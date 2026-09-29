use base64::{Engine as _, engine::general_purpose};
use cosmian_kms_cli_actions::reexport::cosmian_kms_crypto::reexport::cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{RngCore, SeedableRng},
};
use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::utils::{extract_uids::extract_uid, owner_config, run_ckms},
};

/// Create a symmetric key via the CLI.
///
/// `extra_args` are appended after `["sym", "keys", "create"]`.
/// Pass `&[]` for defaults (AES-256).
pub(crate) fn create_symmetric_key(
    cli_conf_path: &str,
    extra_args: &[&str],
) -> CosmianResult<String> {
    let mut args = vec!["sym", "keys", "create"];
    args.extend_from_slice(extra_args);
    let stdout = run_ckms(cli_conf_path, &args)?;
    let uid = extract_uid(&stdout, "Unique identifier").ok_or_else(|| {
        crate::error::CosmianError::Default("failed extracting the unique identifier".to_owned())
    })?;
    Ok(uid.to_string())
}

#[tokio::test]
async fn test_create_symmetric_key() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let mut rng = CsRng::from_entropy();
    let mut key = vec![0_u8; 32];

    // AES
    {
        // AES 256 bit key (default)
        create_symmetric_key(&owner_client_conf_path, &[])?;
        // AES 128 bit key
        create_symmetric_key(&owner_client_conf_path, &["--number-of-bits", "128"])?;
        //  AES 256 bit key from a base64 encoded key
        rng.fill_bytes(&mut key);
        let key_b64 = general_purpose::STANDARD.encode(&key);
        create_symmetric_key(&owner_client_conf_path, &["--bytes-b64", &key_b64])?;
    }

    #[cfg(feature = "non-fips")]
    {
        // ChaCha20 256 bit key
        create_symmetric_key(&owner_client_conf_path, &["--algorithm", "chacha20"])?;
        // ChaCha20 128 bit key
        create_symmetric_key(
            &owner_client_conf_path,
            &["--algorithm", "chacha20", "--number-of-bits", "128"],
        )?;
        //  ChaCha20 256 bit key from a base64 encoded key
        let mut rng = CsRng::from_entropy();
        let mut key = vec![0_u8; 32];
        rng.fill_bytes(&mut key);
        let key_b64 = general_purpose::STANDARD.encode(&key);
        create_symmetric_key(
            &owner_client_conf_path,
            &["--algorithm", "chacha20", "--bytes-b64", &key_b64],
        )?;
    }

    // Sha3
    {
        // Sha3 256 bit salt
        create_symmetric_key(&owner_client_conf_path, &["--algorithm", "sha3"])?;
        // Sha3 salts
        create_symmetric_key(
            &owner_client_conf_path,
            &["--algorithm", "sha3", "--number-of-bits", "224"],
        )?;
        create_symmetric_key(
            &owner_client_conf_path,
            &["--algorithm", "sha3", "--number-of-bits", "256"],
        )?;
        create_symmetric_key(
            &owner_client_conf_path,
            &["--algorithm", "sha3", "--number-of-bits", "384"],
        )?;
        create_symmetric_key(
            &owner_client_conf_path,
            &["--algorithm", "sha3", "--number-of-bits", "512"],
        )?;
        //  Sha3 256 bit salt from a base64 encoded salt
        let mut rng = CsRng::from_entropy();
        let mut salt = vec![0_u8; 32];
        rng.fill_bytes(&mut salt);
        let key_b64 = general_purpose::STANDARD.encode(&salt);
        create_symmetric_key(
            &owner_client_conf_path,
            &["--algorithm", "sha3", "--bytes-b64", &key_b64],
        )?;
    }
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_create_wrapped_symmetric_key() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    let wrapping_key_id = create_symmetric_key(&owner_client_conf_path, &[])?;
    // AES 128 bit key
    let _wrapped_symmetric_key = create_symmetric_key(
        &owner_client_conf_path,
        &[
            "--number-of-bits",
            "128",
            "--wrapping-key-id",
            &wrapping_key_id,
        ],
    )?;
    Ok(())
}

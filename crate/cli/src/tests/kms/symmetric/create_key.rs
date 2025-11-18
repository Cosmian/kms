use base64::{Engine as _, engine::general_purpose};
use cosmian_kms_client::reexport::cosmian_kms_client_utils::create_utils::SymmetricAlgorithm;
use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{RngCore, SeedableRng},
};
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::symmetric::keys::create_key::CreateKeyAction, error::result::KmsCliResult,
};

#[allow(clippy::large_stack_frames)]
#[tokio::test]
pub(crate) async fn test_create_symmetric_key() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let mut rng = CsRng::from_entropy();
    let mut key = vec![0_u8; 32];

    // AES
    {
        // AES 256 bit key
        CreateKeyAction::default()
            .run(ctx.get_owner_client())
            .await?;
        // AES 128 bit key
        let _uid = CreateKeyAction {
            number_of_bits: Some(128),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        //  AES 256 bit key from a base64 encoded key
        rng.fill_bytes(&mut key);
        let key_b64 = general_purpose::STANDARD.encode(&key);
        let _uid = CreateKeyAction {
            wrap_key_b64: Some(key_b64),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;
    }

    #[cfg(feature = "non-fips")]
    {
        // ChaCha20 256 bit key
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Chacha20,
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        // ChaCha20 128 bit key
        CreateKeyAction {
            number_of_bits: Some(128),
            algorithm: SymmetricAlgorithm::Chacha20,
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        //  ChaCha20 256 bit key from a base64 encoded key
        let mut rng = CsRng::from_entropy();
        let mut key = vec![0_u8; 32];
        rng.fill_bytes(&mut key);
        let key_b64 = general_purpose::STANDARD.encode(&key);
        CreateKeyAction {
            wrap_key_b64: Some(key_b64),
            algorithm: SymmetricAlgorithm::Chacha20,
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;
    }

    // Sha3
    {
        // SHA3 256 bit salt (default)
        CreateKeyAction {
            algorithm: SymmetricAlgorithm::Sha3,
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        // SHA3 salts with different sizes
        CreateKeyAction {
            number_of_bits: Some(224),
            algorithm: SymmetricAlgorithm::Sha3,
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        CreateKeyAction {
            number_of_bits: Some(256),
            algorithm: SymmetricAlgorithm::Sha3,
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        CreateKeyAction {
            number_of_bits: Some(384),
            algorithm: SymmetricAlgorithm::Sha3,
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        CreateKeyAction {
            number_of_bits: Some(512),
            algorithm: SymmetricAlgorithm::Sha3,
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        // SHA3 256 bit salt from a base64 encoded salt
        let mut rng = CsRng::from_entropy();
        let mut salt = vec![0_u8; 32];
        rng.fill_bytes(&mut salt);
        let key_b64 = general_purpose::STANDARD.encode(&salt);
        CreateKeyAction {
            wrap_key_b64: Some(key_b64),
            algorithm: SymmetricAlgorithm::Sha3,
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;
    }
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_create_wrapped_symmetric_key() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;

    let wrapping_key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;
    // AES 128 bit key
    let _wrapped_symmetric_key = CreateKeyAction {
        number_of_bits: Some(128),
        wrapping_key_id: Some(wrapping_key_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    Ok(())
}

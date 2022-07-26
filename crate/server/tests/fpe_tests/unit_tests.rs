use std::sync::Arc;

use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::Create,
    kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType},
};
use cosmian_kms_server::{
    config::{auth::AuthConfig, init_config, Config},
    core::crud::KmipServer,
    result::{KResult, KResultHelper},
    KMSServer,
};
use cosmian_kms_utils::{
    cosmian_crypto_base::entropy::CsRng,
    crypto::fpe::{
        kmip_requests::{fpe_build_decryption_request, fpe_build_encryption_request},
        operation::AlphabetCharacters,
    },
};
use tracing::debug;

#[actix_rt::test]
async fn fpe_encryption() -> KResult<()> {
    let config = Config {
        auth: AuthConfig {
            delegated_authority_domain: "dev-1mbsbmin.us.auth0.com".to_string(),
        },
        ..Default::default()
    };
    init_config(&config).await?;

    let kms = Arc::new(KMSServer::instantiate().await?);
    let owner = "eyJhbGciOiJSUzI1Ni";
    let nonexistent_owner = "invalid_owner";

    // Generate FPE Tweak (client responsibility)
    let tweak = {
        let mut cs_rng = CsRng::new();
        cs_rng.generate_random_bytes(64)
    };

    // Create symmetric key
    let create_request = Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::FPEFF1),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            ..Attributes::new(ObjectType::SymmetricKey)
        },
        protection_storage_masks: None,
    };
    let cr = kms.create(create_request, owner, None).await?;
    let aes_uid = &cr.unique_identifier;
    debug!("Create response: {:?}", cr);

    // FPE encryption with this AES key
    let alphabet = AlphabetCharacters::AlphaNumeric;
    let data = "data to encrypt";
    let er = kms
        .encrypt(
            fpe_build_encryption_request(aes_uid, tweak.clone(), alphabet, data)?,
            owner,
            None,
        )
        .await?;
    assert_eq!(aes_uid, &er.unique_identifier);
    let encrypted_data = er.data.context("There should be data")?;
    debug!("encrypted data: {:?}", encrypted_data);

    // assert encryption fails with an invalid owner
    let er = kms
        .encrypt(
            fpe_build_encryption_request(
                aes_uid,
                tweak.clone(),
                AlphabetCharacters::AlphaNumeric,
                data,
            )?,
            nonexistent_owner,
            None,
        )
        .await;
    assert!(er.is_err());

    // FPE decryption
    let dr = kms
        .decrypt(
            fpe_build_decryption_request(aes_uid, tweak.clone(), encrypted_data.clone()),
            owner,
            None,
        )
        .await?;
    let cleartext = &dr.data.context("There should be decrypted data")?;
    assert_eq!(data.as_bytes(), cleartext);

    // assert decryption fails with an invalid owner

    let er = kms
        .decrypt(
            fpe_build_decryption_request(aes_uid, tweak, encrypted_data),
            nonexistent_owner,
            None,
        )
        .await;
    assert!(er.is_err());

    Ok(())
}

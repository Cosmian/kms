use std::sync::Arc;

use cosmian_crypto_base::entropy::gen_bytes;
use cosmian_kms_common::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::Create,
    kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType},
};
use cosmian_rust_lib::crypto::fpe::AlphabetCharacters;
use tracing::debug;

use super::kmip_requests::{fpe_build_decryption_request, fpe_build_encryption_request};
use crate::{
    config::init_config,
    kmip::kmip_server::{server::kmip_server::KmipServer, KMSServer},
    result::{KResult, KResultHelper},
};

#[actix_rt::test]
async fn fpe_encryption() -> KResult<()> {
    let config = crate::config::Config {
        delegated_authority_domain: Some("dev-1mbsbmin.us.auth0.com".to_string()),
        ..Default::default()
    };
    init_config(&config).await?;

    let kms = Arc::new(KMSServer::instantiate().await?);
    let owner = "eyJhbGciOiJSUzI1Ni";
    let nonexistent_owner = "invalid_owner";

    // Generate FPE Tweak (client responsibility)
    let mut tweak = vec![0_u8; 64];
    gen_bytes(&mut tweak[..])?;

    // Create symmetric key
    let create_request = Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            ..Attributes::new(ObjectType::SymmetricKey)
        },
        protection_storage_masks: None,
    };
    let cr = kms.create(create_request, owner).await?;
    let aes_uid = &cr.unique_identifier;
    debug!("Create response: {:?}", cr);

    // FPE encryption with this AES key
    let alphabet = AlphabetCharacters::AlphaNumeric;
    let data = "data to encrypt";
    let er = kms
        .encrypt(
            fpe_build_encryption_request(aes_uid, tweak.clone(), alphabet, data)?,
            owner,
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
        )
        .await;
    assert!(er.is_err());

    // FPE decryption
    let dr = kms
        .decrypt(
            fpe_build_decryption_request(aes_uid, tweak.clone(), encrypted_data.clone()),
            owner,
        )
        .await?;
    let cleartext = &dr.data.context("There should be decrypted data")?;
    assert_eq!(data.as_bytes(), cleartext);

    // assert decryption fails with an invalid owner

    let er = kms
        .decrypt(
            fpe_build_decryption_request(aes_uid, tweak, encrypted_data),
            nonexistent_owner,
        )
        .await;
    assert!(er.is_err());

    Ok(())
}

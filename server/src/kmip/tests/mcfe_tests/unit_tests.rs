use std::{convert::TryFrom, sync::Arc};

use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Get, GetAttributes},
};
use cosmian_kms_utils::crypto::mcfe::{
    mcfe_secret_key_from_key_block, mcfe_setup_from_attributes, secret_key_from_lwe_secret_key,
};
use cosmian_mcfe::lwe;
use num_bigint::BigUint;
use uuid::Uuid;

use crate::{
    config::init_config,
    error::KmsError,
    kmip::{
        kmip_server::{server::kmip_server::KmipServer, KMSServer},
        tests::mcfe_tests::kmip_requests::{
            lwe_secret_key_create_request, lwe_setup_attribute_reference,
        },
    },
    kms_bail,
    result::KResult,
};

#[actix_rt::test]
async fn test_secret_key_crud() -> KResult<()> {
    let config = crate::config::Config {
        delegated_authority_domain: Some("dev-1mbsbmin.us.auth0.com".to_string()),
        ..Default::default()
    };
    init_config(&config).await?;

    let kms = Arc::new(KMSServer::instantiate().await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    let lwe_setup = lwe::Setup {
        clients: 10,
        message_length: 31,
        message_bound: BigUint::from(std::u32::MAX),
        vectors_bound: BigUint::from(std::u32::MAX),
        n0: 1024,
    };
    let lwe_sk = lwe::SecretKey::try_from(&lwe_setup)?;
    let kms_sk = secret_key_from_lwe_secret_key(&lwe_setup, &lwe_sk)?;
    let kms_sk_key_block = match kms_sk {
        Object::SymmetricKey { key_block } => key_block,
        _other => {
            return Err(KmsError::ServerError(
                "The object is not an MCFE LWE Secret Key".to_owned(),
            ))
        }
    };
    let cr = kms
        .create(lwe_secret_key_create_request(&lwe_setup)?, owner)
        .await?;
    assert_eq!(ObjectType::SymmetricKey, cr.object_type);

    let uid = cr.unique_identifier;
    // check the generated id is an UUID
    let uid_ = Uuid::parse_str(&uid).map_err(|e| KmsError::InvalidRequest(e.to_string()))?;
    assert_eq!(&uid, &uid_.to_string());

    // get object
    let gr = kms.get(Get::from(uid.as_str()), owner).await?;
    assert_eq!(uid, gr.unique_identifier);
    assert_eq!(ObjectType::SymmetricKey, gr.object_type);
    // recover sk
    let object = gr.object;
    let recovered_kms_key_block = match object {
        Object::SymmetricKey { key_block } => key_block,
        _other => {
            kms_bail!("The objet at uid: {uid} is not an MCFE LWE Secret Key")
        }
    };
    assert_eq!(
        kms_sk_key_block.cryptographic_algorithm,
        recovered_kms_key_block.cryptographic_algorithm
    );
    assert_eq!(
        kms_sk_key_block.cryptographic_length,
        recovered_kms_key_block.cryptographic_length
    );
    assert_eq!(
        kms_sk_key_block.key_format_type,
        recovered_kms_key_block.key_format_type
    );
    let recovered_lwe_sk = mcfe_secret_key_from_key_block(&recovered_kms_key_block)?;
    assert_eq!(lwe_sk.0.len(), recovered_lwe_sk.0.len());
    // get all attributes
    let gar = kms
        .get_attributes(
            GetAttributes {
                unique_identifier: Some(uid.clone()),
                attribute_references: None,
            },
            owner,
        )
        .await?;
    let kms_sk_attr = kms_sk_key_block.key_value.attributes()?;
    assert_eq!(&gar.attributes, kms_sk_attr);
    // get LWE Setup from attributes

    let gar = kms
        .get_attributes(
            GetAttributes {
                unique_identifier: Some(uid),
                attribute_references: Some(vec![lwe_setup_attribute_reference()]),
            },
            owner,
        )
        .await?;
    let recovered_setup = mcfe_setup_from_attributes(&gar.attributes)?;
    assert_eq!(lwe_setup, recovered_setup);
    Ok(())
}

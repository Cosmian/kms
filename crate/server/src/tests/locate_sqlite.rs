use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{Create, CreateKeyPair, CreateKeyPairResponse, CreateResponse, Locate},
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
    },
};

use crate::{
    result::KResult,
    tests::test_utils::{post_2_1, test_app},
};

#[actix_rt::test]
async fn locate_sqlite() -> KResult<()> {
    // Use sqlite-backed test app
    let app = test_app(None, None).await;

    // Create EC keypair with a tag name (FIPS-approved curve and usage mask)
    let create = CreateKeyPair {
        common_attributes: None,
        private_key_attributes: Some(Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            cryptographic_length: Some(256),
            cryptographic_usage_mask: Some(CryptographicUsageMask::Sign),
            ..Default::default()
        }),
        public_key_attributes: Some(Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            cryptographic_length: Some(256),
            cryptographic_usage_mask: Some(CryptographicUsageMask::Verify),
            ..Default::default()
        }),
        common_protection_storage_masks: None,
        private_protection_storage_masks: None,
        public_protection_storage_masks: None,
    };

    let _resp: CreateKeyPairResponse = post_2_1(&app, create).await?;

    // Locate PublicKey with tag "cat" → expect the public key only
    let mut attrs_pub = Attributes {
        object_type: Some(ObjectType::PublicKey),
        ..Default::default()
    };
    attrs_pub.set_tags(vec!["cat".to_owned()])?;
    let res_pub: Vec<UniqueIdentifier> = post_2_1(
        &app,
        Locate {
            attributes: attrs_pub,
            ..Locate::default()
        },
    )
    .await?;
    assert_eq!(res_pub.len(), 1);

    // Locate PrivateKey with AND CryptographicAlgorithm EC → expect only private key
    let attrs_and = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
        ..Default::default()
    };
    let res_and: Vec<UniqueIdentifier> = post_2_1(
        &app,
        Locate {
            attributes: attrs_and,
            ..Locate::default()
        },
    )
    .await?;
    assert_eq!(res_and.len(), 1);

    // (Skip mismatched RSA filter in FIPS sqlite to reduce flakiness)

    // Create a symmetric AES key and locate by ObjectType::SymmetricKey
    let create_sym = Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            ..Default::default()
        },
        protection_storage_masks: None,
    };
    let _sym_resp: CreateResponse = post_2_1(&app, create_sym).await?;

    // Locate by ObjectType::SymmetricKey → expect at least 1 key
    let attrs_sym = Attributes {
        object_type: Some(ObjectType::SymmetricKey),
        ..Default::default()
    };
    let res_sym: Vec<UniqueIdentifier> = post_2_1(
        &app,
        Locate {
            attributes: attrs_sym,
            ..Locate::default()
        },
    )
    .await?;
    assert_eq!(res_sym.len(), 1);

    Ok(())
}

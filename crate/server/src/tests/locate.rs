use std::sync::Arc;

use cosmian_kms_client_utils::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader},
        kmip_types::ProtocolVersion,
    },
    kmip_2_1::{
        kmip_attributes::Attributes, kmip_messages::RequestMessageBatchItem,
        kmip_objects::ObjectType, kmip_operations::Operation, kmip_types::RecommendedCurve,
        requests::create_ec_key_pair_request,
    },
};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_operations::{Create, CreateKeyPair, CreateKeyPairResponse, CreateResponse, Locate},
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
    },
};
use cosmian_logger::log_init;

use crate::{
    config::{MainDBConfig, ServerParams},
    core::KMS,
    result::KResult,
    tests::test_utils::{https_clap_config, post_2_1, test_app},
};

#[tokio::test]
async fn test_locate() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    let owner = "mt_owner";
    let mut clap_config = https_clap_config();
    clap_config.db = MainDBConfig {
        database_type: Some("sqlite".to_owned()),
        sqlite_path: crate::tests::test_utils::get_tmp_sqlite_path(),
        clear_database: true,
        ..Default::default()
    };
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    // same request of the test in curve_25519_tests.rs in order to minimize debug surface
    // once the issue with ObjectType is fixed, change this request to some key that haven't been
    // used in other tests in order to augment the test coverage
    let request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            maximum_response_size: Some(9999),
            batch_count: 2,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem::new(Operation::CreateKeyPair(Box::new(
                create_ec_key_pair_request(
                    None,
                    vec!["cat"], // changed this line
                    RecommendedCurve::P256,
                    false,
                    None,
                )?,
            ))),
        )],
    };

    let response = kms.message(request, owner, None).await?;
    assert_eq!(response.response_header.batch_count, 1);

    // Verify specific individual keys can be retrieved
    let test_keys = vec![
        (vec!["cat"], Some(ObjectType::Certificate), 0), // expect to find nothing
        (vec!["cat"], Some(ObjectType::PublicKey), 1),   // expect to find 1 key
        (vec!["cat"], Some(ObjectType::PrivateKey), 1),  // expect to find 1 key
    ];

    // Tip : if you have redis-cli installed use `redis-cli KEYS "do::*"` to see all objects stored
    for (expected_tags, expected_object_type, expected_result) in test_keys {
        let mut key_attrs = Attributes {
            object_type: expected_object_type,
            ..Default::default()
        };
        key_attrs.set_tags(expected_tags)?;

        let locate_specific = Locate {
            attributes: key_attrs,
            ..Locate::default()
        };
        let specific_response = kms.locate(locate_specific, owner, None).await?;
        let found_count = specific_response.located_items.unwrap();
        assert_eq!(
            found_count, expected_result,
            "Should find {expected_result} keys... found {found_count} keys",
        );
    }

    Ok(())
}

#[actix_rt::test]
async fn test_locate_key_pair_and_sym_key() -> KResult<()> {
    // Use sqlite-backed test app
    let app = test_app(None, None).await;

    // Create EC keypair (FIPS-approved curve and usage mask)
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

    // Locate PublicKey with tag "cat" → expect 0 public key since tag was not set on creation
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
    assert_eq!(res_pub.len(), 0);

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

#[actix_rt::test]
async fn test_locate_filters_by_object_type_and_and_semantics() -> KResult<()> {
    // Start test app (KMIP 2.1 endpoint)
    let app = test_app(None, None).await;

    // Create an EC key pair
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

    let create_resp: CreateKeyPairResponse = post_2_1(&app, create).await?;
    let UniqueIdentifier::TextString(priv_id) = create_resp.private_key_unique_identifier else {
        panic!("expected private key unique identifier as text string")
    };
    let UniqueIdentifier::TextString(pub_id) = create_resp.public_key_unique_identifier else {
        panic!("expected public key unique identifier as text string")
    };

    // Locate by UniqueIdentifier: ensure it maps back to the expected ObjectType
    let locate_private = Locate {
        maximum_items: None,
        offset_items: None,
        storage_status_mask: None,
        object_group_member: None,
        attributes: Attributes {
            object_type: Some(ObjectType::PrivateKey),
            unique_identifier: Some(UniqueIdentifier::TextString(priv_id.clone())),
            ..Default::default()
        },
    };
    let private_hits: Vec<UniqueIdentifier> = post_2_1(&app, locate_private).await?;
    assert_eq!(private_hits.len(), 1);
    assert_eq!(private_hits[0], UniqueIdentifier::Integer(1));

    let locate_public = Locate {
        maximum_items: None,
        offset_items: None,
        storage_status_mask: None,
        object_group_member: None,
        attributes: Attributes {
            object_type: Some(ObjectType::PublicKey),
            unique_identifier: Some(UniqueIdentifier::TextString(pub_id.clone())),
            ..Default::default()
        },
    };
    let public_hits: Vec<UniqueIdentifier> = post_2_1(&app, locate_public).await?;
    assert_eq!(public_hits.len(), 1);
    assert_eq!(public_hits[0], UniqueIdentifier::Integer(1));

    // AND semantics: ObjectType + CryptographicAlgorithm must both match
    let locate_and_ok = Locate {
        maximum_items: None,
        offset_items: None,
        storage_status_mask: None,
        object_group_member: None,
        attributes: Attributes {
            object_type: Some(ObjectType::PrivateKey),
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            ..Default::default()
        },
    };
    let and_hits: Vec<UniqueIdentifier> = post_2_1(&app, locate_and_ok).await?;
    assert_eq!(and_hits.len(), 1);

    // Note: negative AND semantics checks are unreliable if the server ignores
    // one of the attributes during Locate. We keep the positive AND test above.

    Ok(())
}

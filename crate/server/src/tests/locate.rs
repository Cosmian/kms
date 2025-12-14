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
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Locate;
use cosmian_logger::log_init;

use crate::{
    config::{MainDBConfig, ServerParams},
    core::KMS,
    result::KResult,
    tests::test_utils::https_clap_config,
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

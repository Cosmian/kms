use std::sync::Arc;

use cosmian_kms_client_utils::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader},
        kmip_types::ProtocolVersion,
    },
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_messages::RequestMessageBatchItem,
        kmip_objects::ObjectType,
        kmip_operations::Operation,
        kmip_types::RecommendedCurve,
        requests::create_ec_key_pair_request, //kmip_types::CryptographicAlgorithm,
    },
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Locate;
use cosmian_logger::log_init;

#[allow(clippy::all, unused, unused_imports, clippy::print_stdout)]
use crate::{
    config::{MainDBConfig, ServerParams},
    core::KMS,
    error::KmsError,
    result::KResult,
    tests::test_utils::https_clap_config,
};

fn get_redis_url() -> String {
    option_env!("KMS_REDIS_URL")
        .unwrap_or(&std::env::var("REDIS_HOST").map_or_else(
            |_| "redis://localhost:6379".to_owned(),
            |var_env| format!("redis://{var_env}:6379"),
        ))
        .to_owned()
}

#[tokio::test]
#[allow(deprecated, clippy::all, unused, print_stdout)]
async fn test_locate() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    let owner = "mt_owner";
    let user = "mt_normal_user";
    let redis_url = get_redis_url();
    // we start a fresh KMS, it finds the data in redis, and migrates it
    let mut clap_config = https_clap_config();
    clap_config.db = MainDBConfig {
        database_type: Some("redis-findex".to_owned()),
        database_url: Some(redis_url),
        redis_master_password: Some("password".to_owned()),
        redis_findex_label: Some("label".to_owned()),
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
                    RecommendedCurve::CURVE25519,
                    false,
                    None,
                )?,
            ))),
        )],
    };

    let response = kms.message(request, &owner, None).await?;
    assert_eq!(response.response_header.batch_count, 1);

    // Verify specific individual keys can be retrieved
    let test_keys = vec![
        (vec!["cat"], Some(ObjectType::Certificate), 0), // expect to find nothing, we didn't create any cert. For some reason, finds two keys
        (
            vec!["cat"],
            Some(ObjectType::PublicKey),
            1, // expect to find 1 key, for some reason, it finds the private key as well
        ),
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

        println!("found response: {specific_response:?}");

        let found_count = specific_response.located_items.unwrap();

        println!(
            "Found {found_count} keys with  object type \
             {expected_object_type:?}"
        );

        assert_eq!(
            found_count, expected_result,
            "Should find {expected_result} keys... found {found_count} keys",
        );
    }

    Ok(())
}

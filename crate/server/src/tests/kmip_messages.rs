use std::sync::Arc;

use cloudproof::reexport::crypto_core::X25519_PUBLIC_KEY_LENGTH;
use cosmian_kmip::kmip::{
    kmip_messages::{RequestBatchItem, RequestHeader, RequestMessage},
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Import, Operation},
    kmip_types::{
        Attributes, CryptographicAlgorithm, KeyFormatType, LinkType, LinkedObjectIdentifier,
        OperationEnumeration, ProtocolVersion, RecommendedCurve,
    },
};
use cosmian_kms_utils::crypto::curve_25519::{
    kmip_requests::{ec_create_key_pair_request, get_private_key_request, get_public_key_request},
    operation::{self, to_curve_25519_256_public_key},
};
use cosmian_logger::log_utils::log_init;
use uuid::Uuid;

use crate::{
    config::ServerParams, error::KmsError, result::KResult, tests::test_utils::https_clap_config,
    KMSServer,
};

#[actix_rt::test]
async fn test_kmip_messages() -> KResult<()> {
    log_init("trace,hyper=info,reqwest=info");

    let clap_config = https_clap_config();

    let kms = Arc::new(KMSServer::instantiate(ServerParams::try_from(&clap_config).await?).await?);
    let owner = "eyJhbGciOiJSUzI1Ni";

    // request key pair creation
    let ec_create_request =
        ec_create_key_pair_request(&[] as &[&str], RecommendedCurve::CURVE25519)?;
    let message_request = RequestMessage {
        header: RequestHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            maximum_response_size: Some(9999),
            batch_count: 1,
            client_correlation_value: None,
            server_correlation_value: None,
            asynchronous_indicator: None,
            attestation_capable_indicator: None,
            attestation_type: None,
            authentication: None,
            batch_error_continuation_option: None,
            batch_order_option: None,
            timestamp: None,
        },
        items: vec![RequestBatchItem {
            operation: OperationEnumeration::CreateKeyPair,
            ephemeral: None,
            unique_batch_item_id: None,
            request_payload: Operation::CreateKeyPair(ec_create_request),
            message_extension: None,
        }],
    };
    let response = kms.message(message_request, owner, None).await?;
    // request import
    // let import_pk = vec![1_u8, 2, 3];
    // let import_pk = to_curve_25519_256_public_key(&, sk_uid);
    // let import_uid = Uuid::new_v4().to_string();
    // let import_request = Import {
    //     unique_identifier: import_uid.clone(),
    //     object_type: ObjectType::PublicKey,
    //     replace_existing: Some(true),
    //     key_wrap_type: None,
    //     attributes: Attributes {
    //         object_type: Some(ObjectType::PublicKey),
    //         ..Attributes::default()
    //     },
    //     object: import_pk.clone(),
    // };
    // let update_response = kms.import(request, owner, None).await?;
    // assert_eq!(new_uid, update_response.unique_identifier);

    Ok(())
}

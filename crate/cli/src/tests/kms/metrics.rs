use cosmian_kmip::time_normalize;
use cosmian_kms_client::cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{Create, CreateResponse, Destroy, Locate},
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
        requests::build_revoke_key_request,
    },
};
// KmsClient imported via test_kms_server helpers
use test_kms_server::start_default_test_kms_server;

// Verify active keys count via Locate after create/revoke/destroy sequence
#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn test_active_keys_metric_matches_locate() {
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Create 10 symmetric AES keys with immediate activation
    for _ in 0..10 {
        let attrs = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            object_type: Some(ObjectType::SymmetricKey),
            activation_date: Some(time_normalize().unwrap()),
            ..Default::default()
        };
        let req = Create {
            object_type: ObjectType::SymmetricKey,
            attributes: attrs,
            protection_storage_masks: None,
        };
        let _resp: CreateResponse = client.create(req).await.unwrap();
    }

    // Locate symmetric keys and pick the first UID
    let locate_req = Locate {
        attributes: Attributes {
            object_type: Some(ObjectType::SymmetricKey),
            ..Default::default()
        },
        ..Default::default()
    };
    let ids = client
        .locate(locate_req)
        .await
        .unwrap()
        .unique_identifier
        .unwrap();
    let first_uid = ids.first().cloned().unwrap();
    let first_uid_str = first_uid.to_string();

    // Revoke then destroy the selected key
    let revoke_req = build_revoke_key_request(
        &first_uid_str,
        cosmian_kms_client::cosmian_kmip::kmip_0::kmip_types::RevocationReason {
            revocation_reason_code: cosmian_kms_client::cosmian_kmip::kmip_0::kmip_types::RevocationReasonCode::Unspecified,
            revocation_message: Some("test revoke".to_string()),
        },
    )
    .unwrap();
    client.revoke(revoke_req).await.unwrap();

    let destroy_req = Destroy {
        unique_identifier: Some(UniqueIdentifier::TextString(first_uid_str)),
        remove: false,
        cascade: false,
    };
    client.destroy(destroy_req).await.unwrap();

    // Locate remaining symmetric keys and assert count is 9
    let locate_req2 = Locate {
        attributes: Attributes {
            object_type: Some(ObjectType::SymmetricKey),
            ..Default::default()
        },
        ..Default::default()
    };
    let remaining = client
        .locate(locate_req2)
        .await
        .unwrap()
        .unique_identifier
        .unwrap_or_default();
    assert_eq!(remaining.len(), 9);
}

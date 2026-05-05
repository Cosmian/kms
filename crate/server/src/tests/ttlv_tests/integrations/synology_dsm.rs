//! Integration test that replays the exact Synology DSM 7.x operation sequence
//! observed in production KMS TRACE logs (`kms.2026-03-19`).
//!
//! ## Source
//!
//! The protocol sequence was reconstructed verbatim from the production log
//! captured on 2026-03-19 during an actual DSM encrypted-volume creation.
//!
//! ## DSM KMIP profile
//!
//! | Property           | Value                        |
//! |--------------------|------------------------------|
//! | Protocol version   | KMIP 1.2 (major=1, minor=2)  |
//! | Object type        | `SecretData` / Password        |
//! | Key format         | Opaque                       |
//! | Usage mask         | `Verify` (0x0002)            |
//! | Template attribute | `OperationPolicyName="default"` |
//!
//! ## Exact operation sequence from the log (9 operations, 9 TCP connections)
//!
//! 1. `Query` (`ThreadId` 61, 09:00:17) – capability discovery, functions 1-6
//! 2. `Query` (`ThreadId` 62, 09:02:20) – identical to #1
//! 3. `Query` (`ThreadId` 63, 09:02:20) – identical to #1
//! 4. `Locate` (`ThreadId` 64, 09:02:20) – by volume UUID; expects 0 results
//! 5. `Query` (`ThreadId` 65, 09:02:20) – identical to #1
//! 6. `Register` (`ThreadId` 66, 09:02:21) – stores the volume passphrase as
//!    `SecretData(Password)` with `OperationPolicyName("default")` and an
//!    initial SHA-512 hex name
//! 7. `ModifyAttribute` (`ThreadId` 67, 09:02:21) – atomically replaces
//!    `Name[0]` (the SHA-512 hex) with the canonical volume UUID
//! 8. `Locate` – by volume UUID; must find exactly the registered key
//! 9. `Activate` – transitions the key from `PreActive` → Active
//!
//! DSM opens a fresh TCP connection for every operation. The first three Queries
//! are a rapid burst of parallel capability-discovery connections at startup.
//! The fourth Query fires just before Register as part of the create flow.
//! Steps 8 and 9 only proceed if `ModifyAttributeResponse` correctly echoes
//! the modified `Name` attribute (KMIP 1.2 spec §4.14, issue #820).

use std::sync::Arc;

use cosmian_kms_interfaces::as_hsm_uid;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{
            CryptographicUsageMask, ProtocolVersion, ResultStatusEnumeration, SecretDataType,
        },
    },
    kmip_1_4::{
        kmip_attributes::{Attribute, Name, ObjectType},
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, TemplateAttribute},
        kmip_messages::RequestMessageBatchItem,
        kmip_objects::{Object, SecretData},
        kmip_operations::{Activate, Locate, ModifyAttribute, Operation, Query, Register},
        kmip_types::{KeyFormatType, NameType, OperationEnumeration, QueryFunction},
    },
    kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN,
        kmip_attributes::Attribute as Attribute21,
        kmip_operations::{ModifyAttribute as ModifyAttribute21, Operation as Operation21},
        kmip_types::{
            CryptographicAlgorithm, Name as Name21, NameType as NameType21, UniqueIdentifier,
        },
        requests::symmetric_key_create_request,
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::log_init;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    config::ServerParams,
    core::KMS,
    result::KResult,
    tests::{
        hsm::test_helpers::{get_hsm_password, get_hsm_slot_id},
        test_utils::get_tmp_sqlite_path,
        ttlv_tests::{get_client, socket_client::SocketClient},
    },
};

const EMPTY_TAGS: [&str; 0] = [];

/// Volume UUID as used by DSM for Name-based Locate and `ModifyAttribute`.
const VOLUME_UUID: &str = "2e043205-f1e7-48bb-a615-d331f2f84751";

/// Initial key name: SHA-512 hex string that DSM registers first.
/// It is later replaced by the volume UUID via `ModifyAttribute`.
const SHA512_NAME: &str = "2847051dc248189fb64543b646860f6b92a6ab65a95927\
                           988f6b4dc77ecf5096d6ebe2b5ffb63925679bc3648ba7\
                           38c70a8966acf3ab2c2b85e30ed273a158c6";

/// Volume passphrase bytes captured from the production log.
const KEY_MATERIAL: &[u8] = &[
    0xeb, 0x70, 0xfe, 0x2c, 0x80, 0x34, 0x27, 0x9b, 0xa6, 0x32, 0x2b, 0x35, 0xc2, 0x83, 0x5d, 0x1c,
    0x45, 0x60, 0xf4, 0xdc, 0x30, 0xd6, 0xb2, 0x4e, 0x6c, 0x9c, 0x2e, 0x31, 0x9e, 0x29, 0x57, 0xa9,
    0xdf, 0x6e, 0xd9, 0x7b, 0x73, 0xce, 0x06, 0xce, 0x94, 0x84, 0x7e, 0xc0, 0x00, 0xb7, 0xb8, 0xdf,
    0x5b, 0x2f, 0x6b, 0x8b, 0x12, 0xe7, 0xd9, 0xa1, 0x95, 0x14, 0x08, 0xda, 0x04, 0x53, 0xb9, 0x69,
    0x94, 0x46, 0x0b, 0x9f, 0x49, 0x6a, 0xb4, 0xa7,
];

fn kmip12() -> ProtocolVersion {
    ProtocolVersion {
        protocol_version_major: 1,
        protocol_version_minor: 2,
    }
}

// ─── Test entry point ────────────────────────────────────────────────────────

/// Replay the exact 9-operation Synology DSM 7.x sequence observed in the
/// `kms.2026-03-19` production log.
#[test]
fn test_synology_dsm_volume_lifecycle() {
    log_init(None);

    let client = get_client();

    // Operations 1-3: three parallel capability-discovery Queries from DSM
    // (observed at 09:00:17 in the log, likely one per DSM worker thread).
    query(&client);
    query(&client);
    query(&client);

    // Operation 4: Locate by volume UUID — must find nothing (new volume).
    let located = locate_by_name(&client, VOLUME_UUID);
    assert_eq!(
        located.len(),
        0,
        "volume UUID should not exist before Register"
    );

    // Operation 5: another Query right before Register (separate TCP connection).
    query(&client);

    // Operation 6: Register the passphrase with OperationPolicyName("default").
    let uid = register_volume_key(&client);
    assert!(!uid.is_empty(), "Register must return a non-empty UID");

    // Operation 7: ModifyAttribute — rename the initial SHA-512 name to the volume UUID.
    modify_name_to_uuid(&client, &uid, VOLUME_UUID);

    // Operation 8: Locate by volume UUID — must now find exactly the renamed key.
    let located = locate_by_name(&client, VOLUME_UUID);
    assert_eq!(
        located.len(),
        1,
        "Locate must find exactly one object after ModifyAttribute"
    );
    assert_eq!(located[0], uid, "Located UID must match the registered key");

    // Operation 9: Activate — transitions the key from PreActive → Active.
    activate_volume_key(&client, &uid);
}

// ─── Step implementations ─────────────────────────────────────────────────────

/// KMIP 1.2 Query with all six query functions DSM uses.
fn query(client: &SocketClient) {
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: kmip12(),
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Query,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Query(Query {
                    query_function: Some(vec![
                        QueryFunction::QueryOperations,
                        QueryFunction::QueryObjects,
                        QueryFunction::QueryServerInformation,
                        QueryFunction::QueryApplicationNamespaces,
                        QueryFunction::QueryExtensionList,
                        QueryFunction::QueryExtensionMap,
                    ]),
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Query: request failed");

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("Query: expected V14 response");
    };
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::Success,
        "Query failed: {:?}",
        batch_item.result_reason
    );
}

/// KMIP 1.2 Locate by Name. Returns the list of matching UIDs.
fn locate_by_name(client: &SocketClient, name_value: &str) -> Vec<String> {
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: kmip12(),
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Locate,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Locate(Locate {
                    maximum_items: None,
                    storage_status_mask: None,
                    object_group_member: None,
                    attribute: Some(vec![Attribute::Name(Name {
                        name_value: name_value.to_owned(),
                        name_type: NameType::UninterpretedTextString,
                    })]),
                    template_attribute: None,
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Locate: request failed");

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("Locate: expected V14 response");
    };
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::Success,
        "Locate failed: {:?}",
        batch_item.result_reason
    );

    let Some(Operation::LocateResponse(locate_resp)) = &batch_item.response_payload else {
        panic!("Locate: expected LocateResponse payload");
    };
    locate_resp.unique_identifier.clone().unwrap_or_default()
}

/// KMIP 1.2 Register – stores the volume passphrase as DSM sends it.
///
/// Attributes (in the exact order DSM uses):
/// 1. `CryptographicUsageMask = Verify`
/// 2. `OperationPolicyName = "default"`
/// 3. `Name = <SHA-512 hex>` (initial name, later renamed)
///
/// Object: `SecretData { type=Password, key_format=Opaque, material=<bytes> }`
fn register_volume_key(client: &SocketClient) -> String {
    let object = Object::SecretData(SecretData {
        secret_data_type: SecretDataType::Password,
        key_block: KeyBlock {
            key_format_type: KeyFormatType::Opaque,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::new(KEY_MATERIAL.to_vec())),
                attribute: None,
            }),
            key_compression_type: None,
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    });

    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: kmip12(),
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Register,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Register(Register {
                    object_type: ObjectType::SecretData,
                    object,
                    template_attribute: TemplateAttribute {
                        attribute: Some(vec![
                            Attribute::CryptographicUsageMask(CryptographicUsageMask::Verify),
                            Attribute::OperationPolicyName("default".to_owned()),
                            Attribute::Name(Name {
                                name_value: SHA512_NAME.to_owned(),
                                name_type: NameType::UninterpretedTextString,
                            }),
                        ]),
                    },
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Register: request failed");

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("Register: expected V14 response");
    };
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::Success,
        "Register failed: {:?}",
        batch_item.result_reason
    );

    let Some(Operation::RegisterResponse(register_resp)) = &batch_item.response_payload else {
        panic!("Register: expected RegisterResponse payload");
    };
    assert!(
        !register_resp.unique_identifier.is_empty(),
        "Register must return a non-empty UID"
    );
    register_resp.unique_identifier.clone()
}

/// KMIP 1.2 `Activate` – transitions the registered key from `PreActive` to Active.
///
/// DSM sends this after the Locate confirms the renamed key is findable,
/// completing the volume creation workflow (issue #820).
fn activate_volume_key(client: &SocketClient, uid: &str) {
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: kmip12(),
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Activate,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Activate(Activate {
                    unique_identifier: uid.to_owned(),
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Activate: request failed");

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("Activate: expected V14 response");
    };
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::Success,
        "Activate failed: {:?}",
        batch_item.result_reason
    );
    let Some(Operation::ActivateResponse(activate_resp)) = &batch_item.response_payload else {
        panic!("Activate: expected ActivateResponse payload");
    };
    assert_eq!(
        activate_resp.unique_identifier, uid,
        "ActivateResponse UID must match the registered key"
    );
}

/// KMIP 1.2 `ModifyAttribute` – replaces `Name[0]` with the volume UUID.
///
/// DSM sends this immediately after Register to rename the initial SHA-512
/// name to the canonical volume UUID that it uses for future Locate calls.
fn modify_name_to_uuid(client: &SocketClient, uid: &str, new_name: &str) {
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: kmip12(),
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::ModifyAttribute,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::ModifyAttribute(ModifyAttribute {
                    unique_identifier: Some(uid.to_owned()),
                    attribute: Attribute::Name(Name {
                        name_value: new_name.to_owned(),
                        name_type: NameType::UninterpretedTextString,
                    }),
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("ModifyAttribute: request failed");

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("ModifyAttribute: expected V14 response");
    };
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::Success,
        "ModifyAttribute failed: {:?}",
        batch_item.result_reason
    );

    // KMIP 1.2 spec §4.14: the server MUST echo the modified attribute in
    // the response.  This is the invariant fixed by issue #820 — before that
    // fix the server returned a `Comment` placeholder instead of the actual
    // `Name` value, which caused the DSM client to fail Locate after Register.
    let Some(Operation::ModifyAttributeResponse(modify_resp)) = &batch_item.response_payload else {
        panic!("ModifyAttribute: expected ModifyAttributeResponse payload");
    };
    assert_eq!(
        modify_resp.unique_identifier, uid,
        "ModifyAttributeResponse.unique_identifier must echo the request UID"
    );
    assert_eq!(
        modify_resp.attribute,
        Attribute::Name(Name {
            name_value: new_name.to_owned(),
            name_type: NameType::UninterpretedTextString,
        }),
        "ModifyAttributeResponse.attribute must echo the exact Name attribute that was set"
    );
}

// ─── Non-regression test: issue #933 ─────────────────────────────────────────

/// Non-regression test for issue #933: `ModifyAttribute` must succeed for a
/// non-extractable (sensitive) HSM-backed AES key.
///
/// ## Motivation
///
/// Synology DSM calls `ModifyAttribute(Name)` immediately after `Register` to
/// replace the initial SHA-512 name with the volume UUID.  When the KMS is
/// configured with an HSM and the wrapping key is marked sensitive (non-extractable),
/// the original `HsmStore::retrieve` attempted to export the key material, which
/// caused a "This key is sensitive and cannot be exported" error, making the entire
/// DSM volume creation flow fail.
///
/// ## Fix
///
/// `HsmStore::retrieve` now falls back to `get_key_metadata` (no material export)
/// when PKCS#11 returns `CKR_ATTRIBUTE_SENSITIVE`, building a metadata-only stub
/// that satisfies attribute-only KMIP operations.  `HsmStore::update_object` was
/// also changed to return `Ok(())` instead of `Err(...)` for attribute updates.
///
/// ## Requirements
///
/// Set `HSM_MODEL=softhsm2`, `HSM_USER_PASSWORD=<pin>`, and `HSM_SLOT_ID=<slot>`
/// before running (see `crate/server/src/tests/hsm/test_helpers.rs`).
/// On macOS the default softhsm2 library lives at
/// `/opt/homebrew/lib/softhsm/libsofthsm2.so` and slot 0x01 is initialised by
/// `softhsm2-util --init-token --free --label test --pin 1234 --so-pin 1234`.
#[tokio::test]
#[ignore = "Requires softhsm2: HSM_MODEL=softhsm2, HSM_USER_PASSWORD, HSM_SLOT_ID"]
async fn test_issue_933_modify_attribute_hsm_sensitive_key() -> KResult<()> {
    log_init(None);

    let owner = Uuid::new_v4().to_string();
    let kek_uuid = Uuid::new_v4();

    // Build a softhsm2-backed KMS config.
    let user_password = get_hsm_password()?;
    let slot = get_hsm_slot_id()?;
    let kek_uid = as_hsm_uid!(slot, kek_uuid);
    let sqlite_path = get_tmp_sqlite_path();

    let mut clap_config = crate::tests::test_utils::https_clap_config();
    clap_config.hsm.hsm_model = "softhsm2".to_owned();
    clap_config.hsm.hsm_admin = vec![owner.clone()];
    clap_config.hsm.hsm_slot = vec![slot];
    clap_config.hsm.hsm_password = vec![user_password];
    clap_config.db.sqlite_path = sqlite_path;

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    // Step 1: Create a sensitive AES-256 key in the HSM (non-extractable).
    let create_request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        Some(UniqueIdentifier::TextString(kek_uid.clone())),
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        true, // sensitive / non-extractable
        None,
    )?;

    let request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            maximum_response_size: Some(9999),
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_messages::RequestMessageBatchItem::new(
                Operation21::Create(create_request),
            ),
        )],
    };
    let create_resp = kms.message(request, &owner).await?;
    let ResponseMessageBatchItemVersioned::V21(bi) = &create_resp.batch_item[0] else {
        panic!("Expected KMIP 2.1 response");
    };
    assert_eq!(
        bi.result_status,
        ResultStatusEnumeration::Success,
        "Create HSM key failed: {:?}",
        bi.result_reason
    );

    // Step 2: Call ModifyAttribute(Name) — this must succeed for sensitive HSM keys.
    let new_name = "volume-2e043205-f1e7-48bb-a615-d331f2f84751";
    let modify_request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            maximum_response_size: Some(9999),
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_messages::RequestMessageBatchItem::new(
                Operation21::ModifyAttribute(ModifyAttribute21 {
                    unique_identifier: Some(UniqueIdentifier::TextString(kek_uid.clone())),
                    new_attribute: Attribute21::Name(Name21 {
                        name_value: new_name.to_owned(),
                        name_type: NameType21::UninterpretedTextString,
                    }),
                }),
            ),
        )],
    };
    let modify_resp = kms.message(modify_request, &owner).await?;
    let ResponseMessageBatchItemVersioned::V21(bi) = &modify_resp.batch_item[0] else {
        panic!("Expected KMIP 2.1 response");
    };
    assert_eq!(
        bi.result_status,
        ResultStatusEnumeration::Success,
        "ModifyAttribute failed for sensitive HSM key (issue #933): {:?} - {:?}",
        bi.result_reason,
        bi.result_message,
    );

    // Cleanup: destroy the key.
    let destroy_request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            maximum_response_size: Some(9999),
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_messages::RequestMessageBatchItem::new(
                Operation21::Destroy(
                    cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Destroy {
                        unique_identifier: Some(UniqueIdentifier::TextString(kek_uid.clone())),
                        remove: true,
                        cascade: true,
                        expected_object_type: None,
                    },
                ),
            ),
        )],
    };
    drop(kms.message(destroy_request, &owner).await);

    Ok(())
}

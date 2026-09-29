//! Version-gating tests for attributes introduced after KMIP 1.0.
//!
//! A KMIP server SHALL NOT return an attribute that the client's protocol version does
//! not define. Per the OASIS KMIP Specification, Section 3 "Attributes":
//! - KMIP 1.1 introduces `Fresh` (§3.34).
//! - KMIP 1.2 introduces `Alternative Name` (§3.40) and `Original Creation Date` (§3.43).
//! - KMIP 1.3 introduces `Random Number Generator` (§3.44).
//! - KMIP 1.4 introduces `Description` (§3.46), `Comment` (§3.47), `Sensitive` (§3.48),
//!   `Always Sensitive` (§3.49), `Extractable` (§3.50) and `Never Extractable` (§3.51).
//!
//! Version gating applies to *every* response, including attributes the client asked for
//! by name: a pre-1.4 client cannot decode a KMIP 1.4 attribute it does not know.
//!
//! Note that KMIP 1.4 §4.12 ("if no attribute name is specified in the request, all
//! attributes SHALL be deemed to match") is refined by the OASIS mandatory test vector
//! `kmip/v1.4/XML/mandatory/TL-M-3-14.xml`: the default `GetAttributes` response set (the
//! TL profile) excludes `Sensitive`, `Always Sensitive`, `Extractable` and
//! `Never Extractable`, even though `GetAttributeList` advertises them. The vector is the
//! authoritative interop criterion and is exercised by `kmip_xml_tl`.

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_1_4::{
        kmip_attributes::Attribute,
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Get, GetAttributes, Operation},
        kmip_types::OperationEnumeration,
    },
    ttlv::{KmipEnumerationVariant, KmipFlavor, TTLV, TTLValue, from_ttlv, to_ttlv},
};
use cosmian_logger::{info, log_init};

use super::{create_1_4::create_symmetric_key, get_client};
use crate::tests::ttlv_tests::socket_client::SocketClient;

// ---------------------------------------------------------------------------
// Helper: send KMIP 1.x Get and return the serialized response bytes.
// ---------------------------------------------------------------------------
fn kmip1_get_response_bytes(
    client: &SocketClient,
    key_id: &str,
    minor: i32,
) -> (ResponseMessage, Vec<u8>) {
    let request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: minor,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Get,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Get(Get {
                    unique_identifier: Some(key_id.to_owned()),
                    key_format_type: None,
                    key_compression_type: None,
                    key_wrapping_specification: None,
                }),
                message_extension: None,
            },
        )],
    };

    let response: ResponseMessage = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request)
        .expect("Failed to send KMIP 1.x Get request");

    let ttlv = to_ttlv(&response).expect("Failed to convert response to TTLV");
    let bytes = ttlv
        .to_bytes(KmipFlavor::Kmip1)
        .expect("Failed to serialize response TTLV");

    (response, bytes)
}

// ---------------------------------------------------------------------------
// Helper: send a KMIP 1.x `GetAttributeList` and return the advertised names.
// ---------------------------------------------------------------------------
fn kmip1_get_attribute_list_names(client: &SocketClient, key_id: &str, minor: i32) -> Vec<String> {
    let request_ttlv = TTLV {
        tag: "RequestMessage".to_owned(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "RequestHeader".to_owned(),
                value: TTLValue::Structure(vec![
                    TTLV {
                        tag: "ProtocolVersion".to_owned(),
                        value: TTLValue::Structure(vec![
                            TTLV {
                                tag: "ProtocolVersionMajor".to_owned(),
                                value: TTLValue::Integer(1),
                            },
                            TTLV {
                                tag: "ProtocolVersionMinor".to_owned(),
                                value: TTLValue::Integer(minor),
                            },
                        ]),
                    },
                    TTLV {
                        tag: "MaximumResponseSize".to_owned(),
                        value: TTLValue::Integer(8192),
                    },
                    TTLV {
                        tag: "BatchCount".to_owned(),
                        value: TTLValue::Integer(1),
                    },
                ]),
            },
            TTLV {
                tag: "BatchItem".to_owned(),
                value: TTLValue::Structure(vec![
                    TTLV {
                        tag: "Operation".to_owned(),
                        value: TTLValue::Enumeration(KmipEnumerationVariant {
                            value: 0x0000_000C, // GetAttributeList
                            name: String::new(),
                        }),
                    },
                    TTLV {
                        tag: "RequestPayload".to_owned(),
                        value: TTLValue::Structure(vec![TTLV {
                            tag: "UniqueIdentifier".to_owned(),
                            value: TTLValue::TextString(key_id.to_owned()),
                        }]),
                    },
                ]),
            },
        ]),
    };

    let request_bytes = request_ttlv
        .to_bytes(KmipFlavor::Kmip1)
        .expect("Failed to serialize GetAttributeList request");

    let response_bytes = client
        .send_raw_request(&request_bytes)
        .expect("Failed to send GetAttributeList request");

    let response_ttlv =
        TTLV::from_bytes(&response_bytes, KmipFlavor::Kmip1).expect("Invalid response TTLV");
    let response: ResponseMessage = from_ttlv(response_ttlv).expect("Invalid response message");

    let ResponseMessageBatchItemVersioned::V14(batch_item) = &response.batch_item[0] else {
        panic!("Unexpected V21 response for a KMIP 1.x GetAttributeList");
    };
    let Some(Operation::GetAttributeListResponse(payload)) = &batch_item.response_payload else {
        panic!("Expected GetAttributeListResponse payload");
    };

    info!(
        "KMIP 1.{minor} GetAttributeList attribute names: {:?}",
        payload.attribute_names
    );
    payload.attribute_names.clone()
}

// ---------------------------------------------------------------------------
// KMIP 1.2 Get — AlwaysSensitive MUST NOT appear
// ---------------------------------------------------------------------------
#[test]
fn test_get_kmip12_does_not_return_always_sensitive() {
    log_init(option_env!("RUST_LOG"));

    let client = get_client();
    let key_id = create_symmetric_key(&client, "test_get_kmip12_always_sensitive");
    info!("Key ID: {key_id}");

    let (response, bytes) = kmip1_get_response_bytes(&client, &key_id, 2);

    // Verify the operation succeeded
    let batch_item = response.batch_item.first().expect("Expected batch item");
    let ResponseMessageBatchItemVersioned::V14(item) = batch_item else {
        panic!("Expected V14 response batch item");
    };
    assert_eq!(item.result_status, ResultStatusEnumeration::Success);

    assert!(
        !bytes
            .windows(b"Always Sensitive".len())
            .any(|w| w == b"Always Sensitive"),
        "KMIP 1.2 Get response MUST NOT contain 'Always Sensitive' (KMIP 1.4+ attribute)"
    );
    assert!(
        !bytes
            .windows(b"Never Extractable".len())
            .any(|w| w == b"Never Extractable"),
        "KMIP 1.2 Get response MUST NOT contain 'Never Extractable' (KMIP 1.4+ attribute)"
    );
}

// ---------------------------------------------------------------------------
// KMIP 1.3 Get — AlwaysSensitive MUST NOT appear
// ---------------------------------------------------------------------------
#[test]
fn test_get_kmip13_does_not_return_always_sensitive() {
    log_init(option_env!("RUST_LOG"));

    let client = get_client();
    let key_id = create_symmetric_key(&client, "test_get_kmip13_always_sensitive");
    info!("Key ID: {key_id}");

    let (response, bytes) = kmip1_get_response_bytes(&client, &key_id, 3);

    let batch_item = response.batch_item.first().expect("Expected batch item");
    let ResponseMessageBatchItemVersioned::V14(item) = batch_item else {
        panic!("Expected V14 response batch item");
    };
    assert_eq!(item.result_status, ResultStatusEnumeration::Success);

    assert!(
        !bytes
            .windows(b"Always Sensitive".len())
            .any(|w| w == b"Always Sensitive"),
        "KMIP 1.3 Get response MUST NOT contain 'Always Sensitive' (KMIP 1.4+ attribute)"
    );
}

// ---------------------------------------------------------------------------
// KMIP 1.4 GetAttributeList — AlwaysSensitive MUST be advertised (KMIP 1.4
// §3.49: "SHALL always have a value").
// ---------------------------------------------------------------------------
#[test]
fn test_get_attribute_list_kmip14_advertises_always_sensitive() {
    log_init(option_env!("RUST_LOG"));

    let client = get_client();
    let key_id = create_symmetric_key(&client, "test_get_14_always_sensitive");

    let attribute_names = kmip1_get_attribute_list_names(&client, &key_id, 4);

    assert!(
        attribute_names.iter().any(|n| n == "Always Sensitive"),
        "KMIP 1.4 GetAttributeList MUST advertise 'Always Sensitive': got {attribute_names:?}"
    );
}

// ---------------------------------------------------------------------------
// KMIP 1.2 GetAttributeList — the KMIP 1.4 attributes MUST NOT be advertised.
// ---------------------------------------------------------------------------
#[test]
fn test_get_attribute_list_kmip12_does_not_advertise_always_sensitive() {
    log_init(option_env!("RUST_LOG"));

    let client = get_client();
    let key_id = create_symmetric_key(&client, "test_get_attr_list_12_always_sensitive");

    let attribute_names = kmip1_get_attribute_list_names(&client, &key_id, 2);

    for forbidden in &[
        "Always Sensitive",
        "Never Extractable",
        "Extractable",
        "Sensitive",
    ] {
        assert!(
            !attribute_names.iter().any(|n| n == forbidden),
            "KMIP 1.2 GetAttributeList MUST NOT advertise '{forbidden}' (KMIP 1.4+ attribute): \
             got {attribute_names:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Helper: send a KMIP 1.x `GetAttributes` with no attribute name (default all)
// and return the attribute names carried by the response.
// ---------------------------------------------------------------------------
fn kmip1_default_get_attributes_names(
    client: &SocketClient,
    key_id: &str,
    minor: i32,
) -> Vec<String> {
    kmip1_get_attributes_names(client, key_id, minor, None)
}

/// Send a KMIP 1.x `GetAttributes` for `attribute_name` (or all attributes when `None`)
/// and return the attribute names carried by the response.
fn kmip1_get_attributes_names(
    client: &SocketClient,
    key_id: &str,
    minor: i32,
    attribute_name: Option<Vec<String>>,
) -> Vec<String> {
    let request = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: minor,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::GetAttributes,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::GetAttributes(GetAttributes {
                    unique_identifier: Some(key_id.to_owned()),
                    attribute_name,
                }),
                message_extension: None,
            },
        )],
    };

    let response: ResponseMessage = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request)
        .expect("Failed to send KMIP 1.x GetAttributes request");

    let ResponseMessageBatchItemVersioned::V14(item) =
        response.batch_item.first().expect("Expected batch item")
    else {
        panic!("Expected V14 response batch item");
    };
    assert_eq!(item.result_status, ResultStatusEnumeration::Success);

    let Some(Operation::GetAttributesResponse(payload)) = &item.response_payload else {
        panic!("Expected GetAttributesResponse payload");
    };

    let names = payload
        .attribute
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(kmip1_attribute_spec_name)
        .collect::<Vec<_>>();
    info!("KMIP 1.{minor} GetAttributes names: {names:?}");
    names
}

/// Map a KMIP 1.4 `Attribute` to its canonical specification name for the subset of
/// attributes exercised by these tests.
fn kmip1_attribute_spec_name(attribute: &Attribute) -> String {
    match attribute {
        Attribute::AlwaysSensitive(_) => "Always Sensitive",
        Attribute::Comment(_) => "Comment",
        Attribute::Description(_) => "Description",
        Attribute::Extractable(_) => "Extractable",
        Attribute::Fresh(_) => "Fresh",
        Attribute::NeverExtractable(_) => "Never Extractable",
        Attribute::OriginalCreationDate(_) => "Original Creation Date",
        Attribute::RandomNumberGenerator(_) => "Random Number Generator",
        Attribute::Sensitive(_) => "Sensitive",
        other => return format!("{other:?}").split('(').take(1).collect(),
    }
    .to_owned()
}

// ---------------------------------------------------------------------------
// KMIP 1.4 GetAttributes without attribute names — the four sensitivity
// attributes are NOT part of the default (TL profile) response set, per the
// OASIS mandatory vector `kmip/v1.4/XML/mandatory/TL-M-3-14.xml`. They remain
// advertised by GetAttributeList and are returned when explicitly requested.
// ---------------------------------------------------------------------------
#[test]
fn test_default_get_attributes_kmip14_omits_tl_profile_excluded_attributes() {
    log_init(option_env!("RUST_LOG"));

    let client = get_client();
    let key_id = create_symmetric_key(&client, "test_default_get_attrs_14");

    let names = kmip1_default_get_attributes_names(&client, &key_id, 4);

    for excluded in [
        "Sensitive",
        "Always Sensitive",
        "Extractable",
        "Never Extractable",
    ] {
        assert!(
            !names.iter().any(|n| n == excluded),
            "KMIP 1.4 default GetAttributes MUST NOT return '{excluded}' (TL-M-3-14): got {names:?}"
        );
    }
    // Post-1.0 attributes that ARE part of the default set must still be present.
    for required in ["Original Creation Date", "Random Number Generator"] {
        assert!(
            names.iter().any(|n| n == required),
            "KMIP 1.4 default GetAttributes MUST return '{required}' (TL-M-3-14): got {names:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// KMIP 1.2 GetAttributes without attribute names — KMIP 1.4 attributes MUST NOT
// be returned, but the KMIP 1.2/1.3 ones MAY be.
// ---------------------------------------------------------------------------
#[test]
fn test_default_get_attributes_kmip12_omits_kmip14_attributes() {
    log_init(option_env!("RUST_LOG"));

    let client = get_client();
    let key_id = create_symmetric_key(&client, "test_default_get_attrs_12");

    let names = kmip1_default_get_attributes_names(&client, &key_id, 2);

    for forbidden in [
        "Sensitive",
        "Always Sensitive",
        "Extractable",
        "Never Extractable",
        "Description",
        "Comment",
        "Random Number Generator",
    ] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "KMIP 1.2 GetAttributes MUST NOT return '{forbidden}' (introduced after KMIP 1.2): \
             got {names:?}"
        );
    }
    assert!(
        names.iter().any(|n| n == "Original Creation Date"),
        "KMIP 1.2 defines 'Original Creation Date' (§3.43) and MUST still return it: got {names:?}"
    );
}

// ---------------------------------------------------------------------------
// KMIP 1.0 GetAttributes without attribute names — nothing introduced after
// KMIP 1.0 may be returned.
// ---------------------------------------------------------------------------
#[test]
fn test_default_get_attributes_kmip10_omits_post_10_attributes() {
    log_init(option_env!("RUST_LOG"));

    let client = get_client();
    let key_id = create_symmetric_key(&client, "test_default_get_attrs_10");

    let names = kmip1_default_get_attributes_names(&client, &key_id, 0);

    for forbidden in [
        "Fresh",
        "Alternative Name",
        "Original Creation Date",
        "Random Number Generator",
        "Sensitive",
        "Always Sensitive",
        "Extractable",
        "Never Extractable",
    ] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "KMIP 1.0 GetAttributes MUST NOT return '{forbidden}' (introduced after KMIP 1.0): \
             got {names:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// KMIP 1.0 GetAttributeList — nothing introduced after KMIP 1.0 may be
// advertised.
// ---------------------------------------------------------------------------
#[test]
fn test_get_attribute_list_kmip10_omits_post_10_attributes() {
    log_init(option_env!("RUST_LOG"));

    let client = get_client();
    let key_id = create_symmetric_key(&client, "test_get_attr_list_10_versions");

    let attribute_names = kmip1_get_attribute_list_names(&client, &key_id, 0);

    for forbidden in [
        "Fresh",
        "Alternative Name",
        "Original Creation Date",
        "Random Number Generator",
    ] {
        assert!(
            !attribute_names.iter().any(|n| n == forbidden),
            "KMIP 1.0 GetAttributeList MUST NOT advertise '{forbidden}' (introduced after KMIP \
             1.0): got {attribute_names:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// KMIP 1.2 GetAttributeList — `Random Number Generator` is KMIP 1.3 (§3.44) and
// MUST NOT be advertised, while `Alternative Name` and `Original Creation Date`
// are KMIP 1.2 (§3.40, §3.43) and MUST be.
// ---------------------------------------------------------------------------
#[test]
fn test_get_attribute_list_kmip12_version_boundaries() {
    log_init(option_env!("RUST_LOG"));

    let client = get_client();
    let key_id = create_symmetric_key(&client, "test_get_attr_list_12_versions");

    let attribute_names = kmip1_get_attribute_list_names(&client, &key_id, 2);

    assert!(
        !attribute_names
            .iter()
            .any(|n| n == "Random Number Generator"),
        "KMIP 1.2 GetAttributeList MUST NOT advertise 'Random Number Generator' (KMIP 1.3 \
         §3.44): got {attribute_names:?}"
    );
    for required in ["Fresh", "Alternative Name", "Original Creation Date"] {
        assert!(
            attribute_names.iter().any(|n| n == required),
            "KMIP 1.2 GetAttributeList MUST advertise '{required}': got {attribute_names:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Explicitly requesting a KMIP 1.4 attribute from a pre-1.4 client MUST still
// not return it: the attribute does not exist in the client's protocol version.
// ---------------------------------------------------------------------------
#[test]
fn test_explicit_get_attributes_kmip12_still_omits_kmip14_attributes() {
    log_init(option_env!("RUST_LOG"));

    let client = get_client();
    let key_id = create_symmetric_key(&client, "test_explicit_get_attrs_12");

    let requested = vec![
        "Always Sensitive".to_owned(),
        "Sensitive".to_owned(),
        "Extractable".to_owned(),
        "Never Extractable".to_owned(),
        "State".to_owned(),
    ];
    let names = kmip1_get_attributes_names(&client, &key_id, 2, Some(requested));

    for forbidden in [
        "Always Sensitive",
        "Sensitive",
        "Extractable",
        "Never Extractable",
    ] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "KMIP 1.2 GetAttributes MUST NOT return '{forbidden}' even when explicitly \
             requested (KMIP 1.4 §3.48–§3.51): got {names:?}"
        );
    }
    assert!(
        names.iter().any(|n| n == "State"),
        "The KMIP 1.0 'State' attribute must still be returned: got {names:?}"
    );
}

// ---------------------------------------------------------------------------
// Explicitly requesting the KMIP 1.4 attributes from a KMIP 1.4 client MUST
// return them (they are excluded only from the *default* TL profile set).
// ---------------------------------------------------------------------------
#[test]
fn test_explicit_get_attributes_kmip14_returns_sensitivity_attributes() {
    log_init(option_env!("RUST_LOG"));

    let client = get_client();
    let key_id = create_symmetric_key(&client, "test_explicit_get_attrs_14");

    let requested = vec![
        "Always Sensitive".to_owned(),
        "Sensitive".to_owned(),
        "Extractable".to_owned(),
        "Never Extractable".to_owned(),
    ];
    let names = kmip1_get_attributes_names(&client, &key_id, 4, Some(requested));

    for required in [
        "Always Sensitive",
        "Sensitive",
        "Extractable",
        "Never Extractable",
    ] {
        assert!(
            names.iter().any(|n| n == required),
            "KMIP 1.4 GetAttributes MUST return explicitly requested '{required}': got {names:?}"
        );
    }
}

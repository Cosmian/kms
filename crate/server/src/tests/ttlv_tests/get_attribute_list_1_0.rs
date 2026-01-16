use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_messages::{ResponseMessage, ResponseMessageBatchItemVersioned},
    kmip_1_4,
    ttlv::{KmipEnumerationVariant, KmipFlavor, TTLV, TTLValue, from_ttlv, to_ttlv},
};
use cosmian_logger::{info, log_init};

use crate::tests::ttlv_tests::{create_1_4::create_symmetric_key, get_client};

/// KMIP 1.0 `GetAttributeList` behavior check.
///
/// Requirement: a KMIP 1.0 server response MUST NOT advertise post-1.0
/// attributes such as `Fresh`.
#[test]
fn test_get_attribute_list_1_0_does_not_advertise_fresh_attribute() {
    log_init(None);

    let client = get_client();

    // Create a symmetric key so we have a valid UniqueIdentifier.
    let key_id = create_symmetric_key(&client, "get_attribute_list_no_fresh");

    // Now ask for attribute list using a KMIP 1.0 RequestMessage TTLV matching
    // the server logs (ProtocolVersion 1.0, MaximumResponseSize, TimeStamp,
    // Operation enumeration with empty name).
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
                                value: TTLValue::Integer(0),
                            },
                        ]),
                    },
                    TTLV {
                        tag: "MaximumResponseSize".to_owned(),
                        value: TTLValue::Integer(8192),
                    },
                    TTLV {
                        tag: "TimeStamp".to_owned(),
                        value: TTLValue::DateTime(
                            time::OffsetDateTime::from_unix_timestamp(1_736_927_444).unwrap(),
                        ),
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
                            // GetAttributeList
                            value: 0x0000_000C,
                            name: String::new(),
                        }),
                    },
                    TTLV {
                        tag: "RequestPayload".to_owned(),
                        value: TTLValue::Structure(vec![
                            TTLV {
                                tag: "UniqueIdentifier".to_owned(),
                                value: TTLValue::TextString(key_id),
                            },
                            // Per KMIP spec, GetAttributeList request payload includes
                            // AttributeName(s). The log snippet we are mirroring has a
                            // response that complains about a missing AttributeName.
                            // Provide a minimal attribute name to keep the request valid.
                            TTLV {
                                tag: "AttributeName".to_owned(),
                                value: TTLValue::TextString("ObjectType".to_owned()),
                            },
                        ]),
                    },
                ]),
            },
        ]),
    };

    let request_bytes = request_ttlv
        .to_bytes(KmipFlavor::Kmip1)
        .expect("Failed to serialize request TTLV");

    // Send raw TTLV bytes and decode the response.
    let response_bytes = client
        .send_raw_request(&request_bytes)
        .expect("Failed to send GetAttributeList request bytes");
    let response_ttlv =
        TTLV::from_bytes(&response_bytes, KmipFlavor::Kmip1).expect("Invalid response TTLV");
    let response: ResponseMessage = from_ttlv(response_ttlv).expect("Invalid response message");

    info!("GetAttributeList ResponseMessage: {response}");

    // Helpful debugging if the server returns an unexpected payload.
    // eprintln!("Decoded ResponseMessage: {response:#?}");

    let attribute_names: Vec<String> = match &response.batch_item[0] {
        ResponseMessageBatchItemVersioned::V14(batch_item) => {
            let Some(kmip_1_4::kmip_operations::Operation::GetAttributeListResponse(payload)) =
                &batch_item.response_payload
            else {
                panic!("Expected GetAttributeListResponse payload");
            };
            payload.attribute_names.clone()
        }
        other @ ResponseMessageBatchItemVersioned::V21(_) => {
            panic!("Unexpected response variant: {other:?}")
        }
    };

    info!("GetAttributeList attribute names: {:?}", attribute_names);
    assert!(
        !attribute_names.iter().any(|n| n == "Fresh"),
        "KMIP 1.0 GetAttributeList must NOT advertise the Fresh attribute"
    );

    // Mandatory KMIP 1.0 compatibility check: validate the encoded TTLV response
    // does not contain the string "Fresh".
    let response_ttlv: TTLV = to_ttlv(&response).expect("Failed to convert response to TTLV");
    let response_bytes = response_ttlv
        .to_bytes(KmipFlavor::Kmip1)
        .expect("Failed to serialize response TTLV");
    assert!(
        !response_bytes
            .windows(b"Fresh".len())
            .any(|w| w == b"Fresh"),
        "KMIP 1.0 GetAttributeList response must NOT include Fresh (TTLV contains \"Fresh\")"
    );
}

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_messages::{ResponseMessage, ResponseMessageBatchItemVersioned},
    kmip_1_4,
    ttlv::{KmipEnumerationVariant, KmipFlavor, TTLV, TTLValue, from_ttlv},
};
use cosmian_logger::{info, log_init};

use crate::tests::ttlv_tests::{create_1_4::create_symmetric_key, get_client};

/// KMIP 1.4 `GetAttributeList` should advertise `Fresh`.
#[test]
fn test_get_attribute_list_1_4_advertises_fresh_attribute() {
    log_init(None);

    let client = get_client();

    // Create a symmetric key so we have a valid UniqueIdentifier.
    let key_id = create_symmetric_key(&client, "get_attribute_list_with_fresh");

    // Build a KMIP 1.4 RequestMessage.
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
                                value: TTLValue::Integer(4),
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
                        value: TTLValue::Structure(vec![
                            TTLV {
                                tag: "UniqueIdentifier".to_owned(),
                                value: TTLValue::TextString(key_id),
                            },
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

    let response_bytes = client
        .send_raw_request(&request_bytes)
        .expect("Failed to send GetAttributeList request bytes");
    let response_ttlv =
        TTLV::from_bytes(&response_bytes, KmipFlavor::Kmip1).expect("Invalid response TTLV");
    let response: ResponseMessage = from_ttlv(response_ttlv).expect("Invalid response message");

    info!("GetAttributeList ResponseMessage: {response}");

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
        attribute_names.iter().any(|n| n == "Fresh"),
        "KMIP 1.4 GetAttributeList must advertise the Fresh attribute"
    );
}

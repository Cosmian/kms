//! Property-based tests for TTLV serialization roundtrips.
//!
//! Uses `proptest` to generate random KMIP request messages and verify that:
//!   struct → TTLV → bytes → TTLV → struct
//! preserves the original data (modulo field ordering).

use proptest::prelude::*;

use crate::{
    kmip_0::{
        kmip_messages::{RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader},
        kmip_types::{CryptographicUsageMask, ProtocolVersion},
    },
    kmip_1_4::{
        kmip_attributes::{Attribute, CryptographicAlgorithm, ObjectType},
        kmip_data_structures::TemplateAttribute,
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Create, CreateKeyPair, Operation, Query},
        kmip_types::{OperationEnumeration, QueryFunction},
    },
    ttlv::{KmipFlavor, TTLV, from_ttlv, to_ttlv},
};

// ── Strategies ───────────────────────────────────────────────────────────────

fn arb_protocol_version() -> impl Strategy<Value = ProtocolVersion> {
    prop_oneof![
        Just(ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 0
        }),
        Just(ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 1
        }),
        Just(ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 2
        }),
        Just(ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 4
        }),
    ]
}

fn arb_symmetric_algorithm() -> impl Strategy<Value = CryptographicAlgorithm> {
    prop_oneof![
        Just(CryptographicAlgorithm::AES),
        Just(CryptographicAlgorithm::DES),
    ]
}

fn arb_asymmetric_algorithm() -> impl Strategy<Value = CryptographicAlgorithm> {
    prop_oneof![
        Just(CryptographicAlgorithm::RSA),
        Just(CryptographicAlgorithm::EC),
    ]
}

fn arb_crypto_length() -> impl Strategy<Value = i32> {
    prop_oneof![
        Just(128),
        Just(192),
        Just(256),
        Just(2048),
        Just(3072),
        Just(4096),
    ]
}

fn arb_usage_mask() -> impl Strategy<Value = CryptographicUsageMask> {
    prop_oneof![
        Just(CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt),
        Just(CryptographicUsageMask::Sign),
        Just(CryptographicUsageMask::Verify),
        Just(CryptographicUsageMask::Sign | CryptographicUsageMask::Verify),
        Just(CryptographicUsageMask::MACGenerate | CryptographicUsageMask::MACVerify),
    ]
}

fn arb_query_functions() -> impl Strategy<Value = Vec<QueryFunction>> {
    prop::collection::vec(
        prop_oneof![
            Just(QueryFunction::QueryOperations),
            Just(QueryFunction::QueryObjects),
            Just(QueryFunction::QueryServerInformation),
            Just(QueryFunction::QueryApplicationNamespaces),
            Just(QueryFunction::QueryExtensionList),
            Just(QueryFunction::QueryExtensionMap),
        ],
        1..=6,
    )
}

/// Generate a Query operation request.
fn arb_query_request() -> impl Strategy<Value = RequestMessage> {
    (arb_protocol_version(), arb_query_functions()).prop_map(|(version, functions)| {
        RequestMessage {
            request_header: RequestMessageHeader {
                protocol_version: version,
                batch_count: 1,
                ..Default::default()
            },
            batch_item: vec![RequestMessageBatchItemVersioned::V14(Box::new(
                RequestMessageBatchItem {
                    operation: OperationEnumeration::Query,
                    ephemeral: None,
                    unique_batch_item_id: None,
                    request_payload: Operation::Query(Query {
                        query_function: Some(functions),
                    }),
                    message_extension: None,
                },
            ))],
        }
    })
}

/// Generate a Create (symmetric key) request.
fn arb_create_request() -> impl Strategy<Value = RequestMessage> {
    (
        arb_protocol_version(),
        arb_symmetric_algorithm(),
        arb_crypto_length(),
        arb_usage_mask(),
    )
        .prop_map(|(version, algo, length, mask)| RequestMessage {
            request_header: RequestMessageHeader {
                protocol_version: version,
                batch_count: 1,
                ..Default::default()
            },
            batch_item: vec![RequestMessageBatchItemVersioned::V14(Box::new(
                RequestMessageBatchItem {
                    operation: OperationEnumeration::Create,
                    ephemeral: None,
                    unique_batch_item_id: None,
                    request_payload: Operation::Create(Create {
                        object_type: ObjectType::SymmetricKey,
                        template_attribute: TemplateAttribute {
                            attribute: Some(vec![
                                Attribute::CryptographicAlgorithm(algo),
                                Attribute::CryptographicLength(length),
                                Attribute::CryptographicUsageMask(mask),
                            ]),
                        },
                    }),
                    message_extension: None,
                },
            ))],
        })
}

/// Generate a `CreateKeyPair` request.
fn arb_create_key_pair_request() -> impl Strategy<Value = RequestMessage> {
    (
        arb_protocol_version(),
        arb_asymmetric_algorithm(),
        arb_crypto_length(),
    )
        .prop_map(|(version, algo, length)| RequestMessage {
            request_header: RequestMessageHeader {
                protocol_version: version,
                batch_count: 1,
                ..Default::default()
            },
            batch_item: vec![RequestMessageBatchItemVersioned::V14(Box::new(
                RequestMessageBatchItem {
                    operation: OperationEnumeration::CreateKeyPair,
                    ephemeral: None,
                    unique_batch_item_id: None,
                    request_payload: Operation::CreateKeyPair(CreateKeyPair {
                        common_template_attribute: Some(TemplateAttribute {
                            attribute: Some(vec![
                                Attribute::CryptographicAlgorithm(algo),
                                Attribute::CryptographicLength(length),
                            ]),
                        }),
                        private_key_template_attribute: Some(TemplateAttribute {
                            attribute: Some(vec![Attribute::CryptographicUsageMask(
                                CryptographicUsageMask::Sign,
                            )]),
                        }),
                        public_key_template_attribute: Some(TemplateAttribute {
                            attribute: Some(vec![Attribute::CryptographicUsageMask(
                                CryptographicUsageMask::Verify,
                            )]),
                        }),
                    }),
                    message_extension: None,
                },
            ))],
        })
}

/// Any KMIP request message.
fn arb_request_message() -> impl Strategy<Value = RequestMessage> {
    prop_oneof![
        arb_query_request(),
        arb_create_request(),
        arb_create_key_pair_request(),
    ]
}

// ── Roundtrip tests ──────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn ttlv_bytes_roundtrip_kmip1(msg in arb_request_message()) {
        let ttlv = to_ttlv(&msg).unwrap();
        let bytes = ttlv.to_bytes(KmipFlavor::Kmip1).unwrap();
        let ttlv2 = crate::ttlv::TTLV::from_bytes(&bytes, KmipFlavor::Kmip1).unwrap();
        let msg2: RequestMessage = from_ttlv(&ttlv2).unwrap();
        prop_assert_eq!(msg, msg2);
    }
}

// ── Robustness: corrupted untrusted input must never panic the decoders ─────

proptest! {
    #[test]
    fn corrupted_ttlv_bytes_never_panic(
        msg in arb_request_message(),
        flip in any::<prop::sample::Index>(),
        mask in 1_u8..,
        cut in any::<prop::sample::Index>(),
    ) {
        let mut bytes = to_ttlv(&msg).unwrap().to_bytes(KmipFlavor::Kmip1).unwrap();
        let i = flip.index(bytes.len());
        if let Some(b) = bytes.get_mut(i) {
            *b ^= mask;
        }
        bytes.truncate(cut.index(bytes.len()).saturating_add(1));
        drop(TTLV::find_version(&bytes));
        for flavor in [KmipFlavor::Kmip1, KmipFlavor::Kmip2] {
            if let Ok(ttlv) = TTLV::from_bytes(&bytes, flavor) {
                drop(from_ttlv::<RequestMessage>(&ttlv));
            }
        }
    }

    #[test]
    fn corrupted_json_ttlv_never_panics(
        msg in arb_request_message(),
        flip in any::<prop::sample::Index>(),
        mask in 1_u8..,
    ) {
        let mut json = serde_json::to_vec(&to_ttlv(&msg).unwrap()).unwrap();
        let i = flip.index(json.len());
        if let Some(b) = json.get_mut(i) {
            *b ^= mask;
        }
        if let Ok(s) = std::str::from_utf8(&json)
            && let Ok(ttlv) = serde_json::from_str::<TTLV>(s)
        {
            drop(from_ttlv::<RequestMessage>(&ttlv));
        }
    }
}

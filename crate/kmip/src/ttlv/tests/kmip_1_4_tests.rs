use cosmian_logger::{info, log_init};
use num_bigint_dig::BigInt;
use zeroize::Zeroizing;

use crate::{
    SafeBigInt,
    kmip_0::{
        kmip_messages::{RequestMessage, RequestMessageBatchItemVersioned},
        kmip_types::{CredentialType, CredentialValue, CryptographicUsageMask},
    },
    kmip_1_4::{
        kmip_attributes::Attribute,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, TemplateAttribute},
        kmip_objects::{Object, PrivateKey, SymmetricKey},
        kmip_types::{
            CryptographicAlgorithm, CryptographicDomainParameters, KeyFormatType, Name, NameType,
            RecommendedCurve,
        },
    },
    ttlv::{from_ttlv, to_ttlv},
};

#[test]
fn test_template_attributes() {
    log_init(option_env!("RUST_LOG"));

    let template_attribute = TemplateAttribute {
        attribute: Some(vec![
            Attribute::Name(Name {
                name_value: "TestName".to_owned(),
                name_type: NameType::UninterpretedTextString,
            }),
            Attribute::Name(Name {
                name_value: "http://localhost".to_owned(),
                name_type: NameType::URI,
            }),
            Attribute::CryptographicAlgorithm(CryptographicAlgorithm::ECDH),
            Attribute::CryptographicLength(128),
            Attribute::CryptographicDomainParameters(CryptographicDomainParameters {
                qlength: Some(256),
                recommended_curve: Some(RecommendedCurve::P256),
            }),
            Attribute::CryptographicUsageMask(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
        ]),
    };

    let ttlv = to_ttlv(&template_attribute).expect("Failed to convert TemplateAttribute to TTLV");
    info!("TTLV: {:#?}", ttlv);

    // Deserialize the TTLV back to TemplateAttribute
    let deserialized_template_attribute: TemplateAttribute =
        from_ttlv(ttlv).expect("Failed to deserialize TTLV");

    info!(
        "Deserialized TemplateAttribute: {:#?}",
        deserialized_template_attribute
    );
    assert_eq!(
        template_attribute, deserialized_template_attribute,
        "Deserialized TemplateAttribute does not match the original"
    );
}

#[test]
fn test_object_raw() {
    log_init(option_env!("RUST_LOG"));

    let object = Object::SymmetricKey(SymmetricKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::Raw,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::new(vec![0x01, 0x02, 0x03])),
                attribute: None,
            }),
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    });

    let ttlv = to_ttlv(&object).expect("Failed to convert Object to TTLV");
    info!("TTLV: {:#?}", ttlv);

    // Deserialize the TTLV back to Object
    let deserialized_object: Object = from_ttlv(ttlv).expect("Failed to deserialize TTLV");

    info!("Deserialized Object: {:#?}", deserialized_object);
    assert_eq!(
        object, deserialized_object,
        "Deserialized Object does not match the original"
    );

    // JSON Serde
    let json = serde_json::to_string_pretty(&object).expect("Failed to serialize to JSON");
    info!("JSON: {}", json);
    let deserialized_object_json: Object =
        serde_json::from_str(&json).expect("Failed to deserialize from JSON");
    assert_eq!(
        object, deserialized_object_json,
        "Deserialized Object from JSON does not match the original"
    );
}

#[test]
fn test_object_structured_sym() {
    log_init(option_env!("RUST_LOG"));
    let object = Object::SymmetricKey(SymmetricKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentSymmetricKey {
                    key: Zeroizing::new(vec![0x01, 0x02, 0x03]),
                },
                attribute: None,
            }),
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    });

    let ttlv = to_ttlv(&object).expect("Failed to convert Object to TTLV");
    info!("TTLV: {:#?}", ttlv);

    // Deserialize the TTLV back to Object
    let deserialized_object: Object = from_ttlv(ttlv).expect("Failed to deserialize TTLV");

    info!("Deserialized Object: {:#?}", deserialized_object);
    assert_eq!(
        object, deserialized_object,
        "Deserialized Object does not match the original"
    );

    // JSON Serde
    let json = serde_json::to_string_pretty(&object).expect("Failed to serialize to JSON");
    info!("JSON: {}", json);
    let deserialized_object_json: Object =
        serde_json::from_str(&json).expect("Failed to deserialize from JSON");
    assert_eq!(
        object, deserialized_object_json,
        "Deserialized Object from JSON does not match the original"
    );
}

/// Regression test for GitHub issue #824 (`FortiOS` 7.6.0 / `FortiGate` 40F support).
///
/// `FortiGate` sends KMIP 1.0 binary requests where credentials are nested correctly per spec:
///   `RequestHeader { ... Authentication { Credential { CredentialType, CredentialValue } } ... }`
///
/// The old code modelled `authentication: Option<Vec<Credential>>` which caused the TTLV
/// deserializer to look for `CredentialType` as a direct child of `Authentication`, skipping
/// the `Credential` wrapper and failing with `missing field 'CredentialType'`.
///
/// The fix adds an `Authentication` wrapper struct so the deserialization matches the wire
/// format: `Authentication { credential: Vec<Credential> }`.
#[test]
fn test_kmip_1_0_authentication_fortigate() {
    use crate::ttlv::{KmipEnumerationVariant, TTLV, TTLValue, from_ttlv};

    log_init(option_env!("RUST_LOG"));

    // Build a minimal TTLV structure that mirrors what FortiGate 40F sends over the KMIP
    // socket (port 5696):
    // RequestMessage {
    //   RequestHeader {
    //     ProtocolVersion { Major=1, Minor=0 }
    //     Authentication {
    //       Credential {
    //         CredentialType = UsernameAndPassword (0x1)
    //         CredentialValue { Username="fg-client", Password="password" }
    //       }
    //     }
    //     BatchCount = 1
    //   }
    //   BatchItem {
    //     Operation = Locate (0x8)
    //     RequestPayload { }
    //   }
    // }
    let ttlv = TTLV {
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
                        tag: "Authentication".to_owned(),
                        value: TTLValue::Structure(vec![TTLV {
                            tag: "Credential".to_owned(),
                            value: TTLValue::Structure(vec![
                                TTLV {
                                    tag: "CredentialType".to_owned(),
                                    value: TTLValue::Enumeration(KmipEnumerationVariant {
                                        value: 0x0000_0001, // UsernameAndPassword
                                        name: String::new(),
                                    }),
                                },
                                TTLV {
                                    tag: "CredentialValue".to_owned(),
                                    value: TTLValue::Structure(vec![
                                        TTLV {
                                            tag: "Username".to_owned(),
                                            value: TTLValue::TextString("fg-client".to_owned()),
                                        },
                                        TTLV {
                                            tag: "Password".to_owned(),
                                            value: TTLValue::TextString("password".to_owned()),
                                        },
                                    ]),
                                },
                            ]),
                        }]),
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
                            value: 0x0000_0008, // Locate
                            name: "Locate".to_owned(),
                        }),
                    },
                    TTLV {
                        tag: "RequestPayload".to_owned(),
                        value: TTLValue::Structure(vec![]),
                    },
                ]),
            },
        ]),
    };

    let req: RequestMessage = from_ttlv(ttlv).expect(
        "Failed to parse KMIP 1.0 RequestMessage with Authentication — FortiGate regression",
    );

    let auth = req
        .request_header
        .authentication
        .expect("Authentication should be present");
    assert_eq!(auth.credential.len(), 1, "Expected exactly one Credential");
    let cred = &auth.credential[0];
    assert_eq!(
        cred.credential_type,
        CredentialType::UsernameAndPassword,
        "CredentialType should be UsernameAndPassword"
    );
    assert!(
        matches!(
            &cred.credential_value,
            CredentialValue::UsernameAndPassword { username, password }
            if username == "fg-client" && password.as_deref() == Some("password")
        ),
        "CredentialValue mismatch: {:?}",
        cred.credential_value
    );
    assert_eq!(
        req.request_header.protocol_version.protocol_version_major,
        1
    );
    assert_eq!(
        req.request_header.protocol_version.protocol_version_minor,
        0
    );
    assert_eq!(req.request_header.batch_count, 1);
    assert_eq!(req.batch_item.len(), 1);
    let RequestMessageBatchItemVersioned::V14(item) = &req.batch_item[0] else {
        panic!("Expected a KMIP 1.4 batch item for protocol version 1.x");
    };
    assert_eq!(
        item.operation,
        crate::kmip_1_4::kmip_types::OperationEnumeration::Locate
    );
}

#[test]
fn test_object_structured_rsa() {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("trace"));
    let object = Object::PrivateKey(PrivateKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentRSAPrivateKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentRSAPrivateKey {
                    modulus: Box::new(BigInt::from(1)),
                    private_exponent: Some(Box::new(SafeBigInt::from(BigInt::from(1)))),
                    public_exponent: Some(Box::new(BigInt::from(u128::MAX))),
                    p: Some(Box::new(SafeBigInt::from(BigInt::from(2)))),
                    q: Some(Box::new(SafeBigInt::from(BigInt::from(3)))),
                    prime_exponent_p: Some(Box::new(SafeBigInt::from(BigInt::from(4)))),
                    prime_exponent_q: Some(Box::new(SafeBigInt::from(BigInt::from(5)))),
                    crt_coefficient: Some(Box::new(SafeBigInt::from(BigInt::from(6)))),
                },
                attribute: None,
            }),
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    });

    let ttlv = to_ttlv(&object).expect("Failed to convert Object to TTLV");
    info!("TTLV: {:#?}", ttlv);

    // Deserialize the TTLV back to Object
    let deserialized_object: Object = from_ttlv(ttlv).expect("Failed to deserialize TTLV");

    info!("Deserialized Object: {:#?}", deserialized_object);
    assert_eq!(
        object, deserialized_object,
        "Deserialized Object does not match the original"
    );

    // JSON Serde
    let json = serde_json::to_string_pretty(&object).expect("Failed to serialize to JSON");
    info!("JSON: {}", json);
    let deserialized_object_json: Object =
        serde_json::from_str(&json).expect("Failed to deserialize from JSON");
    assert_eq!(
        object, deserialized_object_json,
        "Deserialized Object from JSON does not match the original"
    );
}

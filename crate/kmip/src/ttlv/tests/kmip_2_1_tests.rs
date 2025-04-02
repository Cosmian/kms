use cosmian_logger::log_init;
use num_bigint_dig::BigInt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::{info, trace};
use zeroize::Zeroizing;

use crate::{
    error::{result::KmipResult, KmipError},
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned, ResponseMessageHeader,
        },
        kmip_types::{
            AsynchronousIndicator, AttestationType, BatchErrorContinuationOption, Credential,
            ErrorReason, MessageExtension, Nonce, ProtocolVersion, ResultStatusEnumeration,
        },
    },
    kmip_2_1::{
        kmip_attributes::{Attribute, Attributes},
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_messages::{RequestMessageBatchItem, ResponseMessageBatchItem},
        kmip_objects::{Object, ObjectType, PublicKey, SymmetricKey},
        kmip_operations::{
            Create, DecryptResponse, Encrypt, Import, ImportResponse, Locate, LocateResponse,
            Operation, Query, SetAttribute,
        },
        kmip_types::{
            CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, Link, LinkType,
            LinkedObjectIdentifier, OperationEnumeration, QueryFunction, UniqueIdentifier,
        },
    },
    ttlv::{from_ttlv, to_ttlv, KmipEnumerationVariant, TTLValue, TTLV},
    SafeBigInt,
};

fn aes_key_material(key_value: &[u8]) -> KeyMaterial {
    KeyMaterial::TransparentSymmetricKey {
        key: Zeroizing::from(key_value.to_vec()),
    }
}

fn aes_key_value(key_value: &[u8]) -> KeyValue {
    KeyValue {
        key_material: aes_key_material(key_value),
        attributes: Some(Attributes {
            object_type: Some(ObjectType::SymmetricKey),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(key_value.len() as i32 * 8),
            cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            ..Attributes::default()
        }),
    }
}

fn aes_key_block(key_value: &[u8]) -> KeyBlock {
    KeyBlock {
        key_format_type: KeyFormatType::TransparentSymmetricKey,
        key_compression_type: None,
        key_value: Some(aes_key_value(key_value)),
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(key_value.len() as i32 * 8),
        key_wrapping_data: None,
    }
}

fn aes_key(key_value: &[u8]) -> Object {
    Object::SymmetricKey(SymmetricKey {
        key_block: aes_key_block(key_value),
    })
}

fn aes_key_material_ttlv(key_value: &[u8]) -> TTLV {
    TTLV {
        tag: "KeyMaterial".to_owned(),
        value: TTLValue::Structure(vec![TTLV {
            tag: "Key".to_owned(),
            value: TTLValue::ByteString(key_value.to_vec()),
        }]),
    }
}

fn aes_key_value_ttlv(key_value: &[u8]) -> TTLV {
    TTLV {
        tag: "KeyValue".to_owned(),
        value: TTLValue::Structure(vec![
            aes_key_material_ttlv(key_value),
            TTLV {
                tag: "Attributes".to_owned(),
                value: TTLValue::Structure(vec![
                    TTLV {
                        tag: "CryptographicAlgorithm".to_owned(),
                        value: TTLValue::Enumeration(KmipEnumerationVariant {
                            name: "AES".to_owned(),
                            value: 0,
                        }),
                    },
                    TTLV {
                        tag: "CryptographicLength".to_owned(),
                        value: TTLValue::Integer(key_value.len() as i32 * 8),
                    },
                    TTLV {
                        tag: "CryptographicUsageMask".to_owned(),
                        value: TTLValue::Integer(4),
                    },
                    TTLV {
                        tag: "KeyFormatType".to_owned(),
                        value: TTLValue::Enumeration(KmipEnumerationVariant {
                            name: "TransparentSymmetricKey".to_owned(),
                            value: 0,
                        }),
                    },
                    TTLV {
                        tag: "ObjectType".to_owned(),
                        value: TTLValue::Enumeration(KmipEnumerationVariant {
                            name: "SymmetricKey".to_owned(),
                            value: 0,
                        }),
                    },
                ]),
            },
        ]),
    }
}

fn aes_key_block_ttlv(key_value: &[u8]) -> TTLV {
    TTLV {
        tag: "KeyBlock".to_owned(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "KeyFormatType".to_owned(),
                value: TTLValue::Enumeration(KmipEnumerationVariant {
                    name: "TransparentSymmetricKey".to_owned(),
                    value: 0,
                }),
            },
            aes_key_value_ttlv(key_value),
            TTLV {
                tag: "CryptographicAlgorithm".to_owned(),
                value: TTLValue::Enumeration(KmipEnumerationVariant {
                    name: "AES".to_owned(),
                    value: 0,
                }),
            },
            TTLV {
                tag: "CryptographicLength".to_owned(),
                value: TTLValue::Integer(key_value.len() as i32 * 8),
            },
        ]),
    }
}

fn aes_key_ttlv(key_value: &[u8]) -> TTLV {
    TTLV {
        tag: "SymmetricKey".to_owned(),
        value: TTLValue::Structure(vec![aes_key_block_ttlv(key_value)]),
    }
}

#[test]
fn test_ser_aes_key() {
    log_init(option_env!("RUST_LOG"));
    let key_bytes: &[u8] = b"this_is_a_test";
    let aes_key = aes_key(key_bytes);

    // Serializer
    let ttlv = to_ttlv(&aes_key).unwrap();

    // Serialize
    let json = serde_json::to_string_pretty(&ttlv).unwrap();
    info!("{}", json);

    // Deserialize
    let ttlv_from_json = serde_json::from_str::<TTLV>(&json).unwrap();
    assert_eq!(ttlv, ttlv_from_json);

    // Deserializer
    let rec: Object = from_ttlv(ttlv.clone()).unwrap();
    assert_eq!(aes_key, rec);

    assert_eq!(aes_key_ttlv(key_bytes), ttlv);
}

#[test]
fn test_des_int() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        an_int: i32,
        another_int: i32,
    }
    log_init(option_env!("RUST_LOG"));

    let ttlv = TTLV {
        tag: "Test".to_owned(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "AnInt".to_owned(),
                value: TTLValue::Integer(2),
            },
            TTLV {
                tag: "AnotherInt".to_owned(),
                value: TTLValue::Integer(-44),
            },
        ]),
    };

    let rec: Test = from_ttlv(ttlv).unwrap();
    assert_eq!(
        &Test {
            an_int: 2,
            another_int: -44
        },
        &rec
    );
}

#[test]
fn test_des_array() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        ints: Vec<i32>,
    }

    log_init(option_env!("RUST_LOG"));
    let ttlv = TTLV {
        tag: "Test".to_owned(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "Ints".to_owned(),
                value: TTLValue::Integer(2),
            },
            TTLV {
                tag: "Ints".to_owned(),
                value: TTLValue::Integer(4),
            },
        ]),
    };

    let rec: Test = from_ttlv(ttlv).unwrap();
    assert_eq!(&Test { ints: vec![2, 4] }, &rec);
}

#[test]
fn test_des_enum() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        crypto_algo: CryptographicAlgorithm,
    }
    log_init(option_env!("RUST_LOG"));

    let ttlv = TTLV {
        tag: "Test".to_owned(),
        value: TTLValue::Structure(vec![TTLV {
            tag: "CryptoAlgo".to_owned(),
            value: TTLValue::Enumeration(KmipEnumerationVariant {
                name: "AES".to_owned(),
                value: 0,
            }),
        }]),
    };

    let rec: Test = from_ttlv(ttlv).unwrap();
    assert_eq!(
        &Test {
            crypto_algo: CryptographicAlgorithm::AES
        },
        &rec
    );
}

#[test]
fn test_key_material_vec_deserialization() {
    log_init(option_env!("RUST_LOG"));
    let bytes = Zeroizing::from(vec![
        116, 104, 105, 115, 95, 105, 115, 95, 97, 95, 116, 101, 115, 116,
    ]);
    let ttlv = TTLV {
        tag: "KeyMaterial".to_owned(),
        value: TTLValue::Structure(vec![TTLV {
            tag: "Key".to_owned(),
            value: TTLValue::ByteString(bytes.to_vec()),
        }]),
    };
    let km_: KeyMaterial = from_ttlv(ttlv).unwrap();
    info!("{:?}", km_);
    let km = KeyMaterial::TransparentSymmetricKey { key: bytes };
    assert_eq!(km, km_);
}

#[test]
fn test_key_material_big_int_deserialization() {
    log_init(option_env!("RUST_LOG"));
    let ttlv = TTLV {
        tag: "KeyMaterial".to_owned(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "KeyTypeSer".to_owned(),
                value: TTLValue::Enumeration(KmipEnumerationVariant {
                    name: "DH".to_owned(),
                    value: 0,
                }),
            },
            TTLV {
                tag: "P".to_owned(),
                value: TTLValue::BigInteger(BigInt::from(u32::MAX).into()),
            },
            TTLV {
                tag: "Q".to_owned(),
                value: TTLValue::BigInteger(BigInt::from(1_u32).into()),
            },
            TTLV {
                tag: "G".to_owned(),
                value: TTLValue::BigInteger(BigInt::from(2_u32).into()),
            },
            TTLV {
                tag: "X".to_owned(),
                value: TTLValue::BigInteger(BigInt::from(u128::MAX).into()),
            },
        ]),
    };
    let km = KeyMaterial::TransparentDHPrivateKey {
        p: BigInt::from(u32::MAX).into(),
        q: Some(BigInt::from(1_u64).into()),
        g: BigInt::from(2_u32).into(),
        j: None,
        x: SafeBigInt::from(BigInt::from(u128::MAX)).into(),
    };
    let ttlv_ = to_ttlv(&km).unwrap();
    assert_eq!(ttlv, ttlv_);
    let km_: KeyMaterial = from_ttlv(ttlv_).unwrap();
    assert_eq!(km, km_);
}

#[test]
fn test_big_int_deserialization() {
    log_init(option_env!("RUST_LOG"));
    let km = KeyMaterial::TransparentDHPrivateKey {
        p: BigInt::from(u32::MAX).into(),
        q: Some(BigInt::from(1_u64).into()),
        g: BigInt::from(2_u32).into(),
        j: None,
        x: SafeBigInt::from(BigInt::from(u128::MAX - 1)).into(),
    };
    let j = serde_json::to_value(&km).unwrap();
    let km_: KeyMaterial = serde_json::from_value(j).unwrap();
    assert_eq!(km, km_);
}

#[test]
fn test_aes_key_material() {
    log_init(option_env!("RUST_LOG"));
    let key_bytes: &[u8] = b"this_is_a_test";

    // Serializer
    let ttlv = to_ttlv(&aes_key_material(key_bytes)).unwrap();
    info!("{:?}", ttlv);
    assert_eq!(aes_key_material_ttlv(key_bytes), ttlv);

    // Serialize
    let json = serde_json::to_string_pretty(&ttlv).unwrap();
    // Deserialize
    let ttlv_from_json = serde_json::from_str::<TTLV>(&json).unwrap();
    assert_eq!(ttlv, ttlv_from_json);

    // Deserializer
    let rec: KeyMaterial = from_ttlv(ttlv).unwrap();
    assert_eq!(aes_key_material(key_bytes), rec);
}

#[test]
fn test_aes_key_value() {
    log_init(option_env!("RUST_LOG"));
    let key_bytes: &[u8] = b"this_is_a_test";
    //
    let json = serde_json::to_value(aes_key_value(key_bytes)).unwrap();
    let kv: KeyValue = serde_json::from_value(json).unwrap();
    assert_eq!(aes_key_value(key_bytes), kv);

    let ttlv = aes_key_value_ttlv(key_bytes);
    let rec: KeyValue = from_ttlv(ttlv).unwrap();
    assert_eq!(aes_key_value(key_bytes), rec);
}

#[test]
fn test_aes_key_block() {
    log_init(option_env!("RUST_LOG"));
    let key_bytes: &[u8] = b"this_is_a_test";
    //
    let json = serde_json::to_value(aes_key_block(key_bytes)).unwrap();
    let kb: KeyBlock = serde_json::from_value(json).unwrap();
    assert_eq!(aes_key_block(key_bytes), kb);
    //
    let ttlv = aes_key_block_ttlv(key_bytes);
    let rec: KeyBlock = from_ttlv(ttlv).unwrap();
    assert_eq!(aes_key_block(key_bytes), rec);
}

#[test]
fn test_des_aes_key() {
    log_init(option_env!("RUST_LOG"));
    let key_bytes: &[u8] = b"this_is_a_test";

    let key = aes_key(key_bytes);

    // Serializer
    let ttlv = to_ttlv(&key).unwrap();
    info!("{:?}", ttlv);
    assert_eq!(aes_key_ttlv(key_bytes), ttlv);

    // Serialize
    let json = serde_json::to_string_pretty(&ttlv).unwrap();
    // Deserialize
    let ttlv_from_json = serde_json::from_str::<TTLV>(&json).unwrap();
    assert_eq!(ttlv, ttlv_from_json);

    // Deserializer
    let rec: Object = from_ttlv(ttlv).unwrap();
    assert_eq!(aes_key(key_bytes), rec);
}

#[test]
fn test_object_ibn_struct() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Wrapper {
        object: Object,
    }
    log_init(option_env!("RUST_LOG"));

    let wrapper = Wrapper {
        object: aes_key(b"this_is_a_test"),
    };

    // Serializer
    let ttlv = to_ttlv(&wrapper).unwrap();
    info!("{:#?}", ttlv);
    // Serialize
    let json = serde_json::to_string_pretty(&ttlv).unwrap();
    info!("{}", json);
    // Deserialize
    let ttlv_from_json = serde_json::from_str::<TTLV>(&json).unwrap();
    assert_eq!(ttlv, ttlv_from_json);
    // Deserializer
    let rec: Wrapper = from_ttlv(ttlv).unwrap();
    assert_eq!(wrapper, rec);
}

#[test]
fn test_import_symmetric_key() {
    log_init(option_env!("RUST_LOG"));

    let key_bytes: &[u8] = b"this_is_a_test";
    let key = aes_key(key_bytes);
    let import = Import {
        unique_identifier: UniqueIdentifier::TextString("unique_identifier".to_owned()),
        object_type: ObjectType::Certificate,
        replace_existing: None,
        key_wrap_type: None,
        attributes: key.attributes().unwrap().to_owned(),
        object: key,
    };
    // Serializer
    let ttlv = to_ttlv(&import).unwrap();
    info!("{:?}", ttlv);
    // Serialize
    let json = serde_json::to_string_pretty(&ttlv).unwrap();
    info!("{}", json);
    // Deserialize
    let ttlv_from_json = serde_json::from_str::<TTLV>(&json).unwrap();
    assert_eq!(ttlv, ttlv_from_json);
    // Deserializer
    let rec: Import = from_ttlv(ttlv).unwrap();
    assert_eq!(import, rec);
}

#[test]
fn test_import_private_key() {
    log_init(option_env!("RUST_LOG"));
    let key_bytes: &[u8] = b"this_is_a_test";
    let key = Object::PublicKey(PublicKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: Some(KeyValue {
                key_material: KeyMaterial::ByteString(Zeroizing::from(key_bytes.to_vec())),
                attributes: Some(Attributes {
                    object_type: Some(ObjectType::PublicKey),
                    cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
                    cryptographic_length: Some(256),
                    cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
                    key_format_type: Some(KeyFormatType::TransparentECPublicKey),
                    ..Attributes::default()
                }),
            }),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            key_wrapping_data: None,
        },
    });
    let import = Import {
        unique_identifier: UniqueIdentifier::TextString("unique_identifier".to_owned()),
        object_type: ObjectType::PrivateKey,
        replace_existing: None,
        key_wrap_type: None,
        attributes: key.attributes().unwrap().to_owned(),
        object: key,
    };
    // Serializer
    let ttlv = to_ttlv(&import).unwrap();
    info!("{:?}", ttlv);
    // Serialize
    let json = serde_json::to_string_pretty(&ttlv).unwrap();
    info!("{}", json);
    // Deserialize
    let ttlv_from_json = serde_json::from_str::<TTLV>(&json).unwrap();
    assert_eq!(ttlv, ttlv_from_json);
    // Deserializer
    let rec: Import = from_ttlv(ttlv).unwrap();
    assert_eq!(import, rec);
}

#[test]
fn test_attributes() {
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    struct Wrapper {
        attrs: Attributes,
    }
    log_init(option_env!("RUST_LOG"));

    let wrapper = Wrapper {
        attrs: Attributes {
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
    };
    let ttlv = to_ttlv(&wrapper).unwrap();
    let json = serde_json::to_value(&ttlv).unwrap();
    let ttlv_: TTLV = serde_json::from_value(json).unwrap();
    assert_eq!(ttlv, ttlv_);
    let rec: Wrapper = from_ttlv(ttlv_).unwrap();
    assert_eq!(wrapper, rec);
}

#[test]
fn test_some_attributes() {
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    #[serde(untagged)]
    #[allow(clippy::large_enum_variant)]
    enum Wrapper {
        #[serde(rename_all = "PascalCase")]
        Attr {
            // #[serde(skip_serializing_if = "Option::is_none")]
            attrs: Attributes,
        },
        #[serde(rename_all = "PascalCase")]
        NoAttr { whatever: i32 },
    }

    log_init(option_env!("RUST_LOG"));

    let value = Wrapper::Attr {
        attrs: Attributes {
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
    };
    let ttlv = to_ttlv(&value).unwrap();
    let json = serde_json::to_value(&ttlv).unwrap();
    let ttlv_: TTLV = serde_json::from_value(json).unwrap();
    assert_eq!(ttlv, ttlv_);
    let rec: Wrapper = from_ttlv(ttlv_).unwrap();
    assert_eq!(value, rec);
}

#[test]
fn test_untagged_enum() {
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    #[serde(untagged)]
    enum Untagged {
        #[serde(rename_all = "PascalCase")]
        AnInt { the_int: i32 },
        #[serde(rename_all = "PascalCase")]
        ALong { the_long: i64 },
    }

    log_init(option_env!("RUST_LOG"));

    let value = Untagged::AnInt { the_int: 12 };

    // Serializer
    let ttlv = to_ttlv(&value).unwrap();
    assert_eq!(
        ttlv,
        TTLV {
            tag: "Untagged".to_owned(),
            value: TTLValue::Structure(vec![TTLV {
                tag: "TheInt".to_owned(),
                value: TTLValue::Integer(12)
            }])
        }
    );

    // Serialize
    let json = serde_json::to_string_pretty(&ttlv).unwrap();
    info!("{}", json);

    // Deserialize
    let ttlv_from_json = serde_json::from_str::<TTLV>(&json).unwrap();
    assert_eq!(ttlv, ttlv_from_json);

    // Deserializer
    let rec: Untagged = from_ttlv(ttlv).unwrap();
    assert_eq!(value, rec);
}

#[test]
fn test_java_import_response() {
    log_init(option_env!("RUST_LOG"));
    let ir = ImportResponse {
        unique_identifier: UniqueIdentifier::TextString("blah".to_owned()),
    };
    let json = serde_json::to_string(&to_ttlv(&ir).unwrap()).unwrap();
    let ir_ = from_ttlv(serde_json::from_str::<TTLV>(&json).unwrap()).unwrap();
    assert_eq!(ir, ir_);
}

#[test]
fn test_byte_string_key_material() {
    log_init(option_env!("RUST_LOG"));
    let key_bytes: &[u8] = b"this_is_a_test";
    let key_value = KeyValue {
        key_material: KeyMaterial::ByteString(Zeroizing::from(key_bytes.to_vec())),
        attributes: Some(Attributes {
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        }),
    };
    let ttlv = to_ttlv(&key_value).unwrap();
    let key_value_: KeyValue = from_ttlv(ttlv).unwrap();
    assert_eq!(key_value, key_value_);
}

#[test]
fn test_aes_key_full() {
    log_init(option_env!("RUST_LOG"));
    let key_bytes: &[u8] = b"this_is_a_test";
    let aes_key = aes_key(key_bytes);
    let ttlv = to_ttlv(&aes_key).unwrap();
    let aes_key_: Object = from_ttlv(ttlv).unwrap();
    assert_eq!(aes_key, aes_key_);
}

#[test]
fn test_attributes_with_links() {
    log_init(option_env!("RUST_LOG"));
    let attributes = Attributes {
        object_type: Some(ObjectType::SymmetricKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        link: Some(vec![
            Link {
                link_type: LinkType::ParentLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString("SK".to_owned()),
            },
            Link {
                link_type: LinkType::CertificateLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString("CERT".to_owned()),
            },
        ]),
        ..Attributes::default()
    };

    // Serializer
    let ttlv = to_ttlv(&attributes).unwrap();
    let json = serde_json::to_string_pretty(&ttlv).unwrap();
    info!("{}", json);
    // Deserialize
    let ttlv_from_json = serde_json::from_str::<TTLV>(&json).unwrap();
    assert_eq!(ttlv, ttlv_from_json);
    // Deserializer
    let rec: Attributes = from_ttlv(ttlv).unwrap();
    assert_eq!(attributes, rec);
}

#[test]
pub(crate) fn test_create() {
    log_init(option_env!("RUST_LOG"));
    let attributes = Attributes {
        object_type: Some(ObjectType::SymmetricKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        link: Some(vec![Link {
            link_type: LinkType::ParentLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString("SK".to_owned()),
        }]),
        ..Attributes::default()
    };
    let create = Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    };
    let ttlv = to_ttlv(&create).unwrap();
    let create_: Create = from_ttlv(ttlv).unwrap();
    assert_eq!(ObjectType::SymmetricKey, create_.object_type);
    assert_eq!(
        CryptographicAlgorithm::AES,
        create_.attributes.cryptographic_algorithm.unwrap()
    );
    assert_eq!(
        LinkedObjectIdentifier::TextString("SK".to_owned()),
        create_.attributes.link.as_ref().unwrap()[0].linked_object_identifier
    );
}

//Verify that issue https://github.com/Cosmian/kms/issues/92
// is actually fixed
#[test]
fn test_issue_deserialize_object_with_empty_attributes() {
    log_init(option_env!("RUST_LOG"));

    // this works
    serialize_deserialize(&get_key_block()).unwrap();
    trace!("KeyBlock serialize/deserialize OK");

    // this should work too but does not deserialize
    // because of the empty Attributes in the KeyValue
    let object = Object::SymmetricKey(SymmetricKey {
        key_block: get_key_block(),
    });
    let object_: Object = serialize_deserialize(&object).unwrap();
    match object_ {
        Object::SymmetricKey(SymmetricKey { key_block }) => {
            assert_eq!(
                get_key_block().key_value.map(|kv| kv.key_material),
                key_block.key_value.map(|kv| kv.key_material)
            );
        }
        _ => panic!("wrong object type"),
    }
}

fn serialize_deserialize<T: DeserializeOwned + Serialize>(object: &T) -> Result<T, KmipError> {
    // serialize
    let object_ttlv = to_ttlv(object)?;
    let json = serde_json::to_string_pretty(&object_ttlv)?;
    // deserialize
    let ttlv: TTLV = serde_json::from_str(&json)?;
    let t: T = from_ttlv(ttlv)?;
    Ok(t)
}

fn get_key_block() -> KeyBlock {
    KeyBlock {
        key_format_type: KeyFormatType::TransparentSymmetricKey,
        key_compression_type: None,
        key_value: Some(KeyValue {
            key_material: KeyMaterial::TransparentSymmetricKey {
                key: Zeroizing::from(
                    hex::decode(
                        b"EC189A82797F0AED1E5AEF9EB0D232E6079A1D3E5C00526DDEE59BCA16242604",
                    )
                    .unwrap(),
                ),
            },
            //TODO:: Empty attributes used to cause a deserialization issue for `Object`; `None` works
            attributes: Some(Attributes::default()),
        }),
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        key_wrapping_data: None,
    }
}

#[test]
pub(crate) fn test_message_enforce_enum() {
    log_init(option_env!("RUST_LOG"));

    // check Message request serializer reinforcement
    let req = RequestMessage {
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
            RequestMessageBatchItem {
                operation: OperationEnumeration::Create,
                ephemeral: None,
                unique_batch_item_id: None,
                // mismatch operation regarding the enum
                request_payload: Operation::Locate(Locate::default()),
                message_extension: None,
            },
        )],
    };
    assert_eq!(
        to_ttlv(&req).unwrap_err().to_string(),
        "operation enum (`Create`) doesn't correspond to request payload (`Locate`)".to_owned()
    );

    let req = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            maximum_response_size: Some(9999),
            // mismatch number of batch items
            batch_count: 15,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem::new(Operation::Locate(Locate::default())),
        )],
    };
    assert_eq!(
        to_ttlv(&req).unwrap_err().to_string(),
        "mismatch count of batch items between header (`15`) and actual items count (`1`)"
            .to_owned()
    );

    let req = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Decrypt,
                ephemeral: None,
                unique_batch_item_id: None,
                // mismatch operation regarding the enum
                request_payload: Operation::DecryptResponse(DecryptResponse {
                    unique_identifier: UniqueIdentifier::TextString("id_12345".to_owned()),
                    data: Some(Zeroizing::from(b"decrypted_data".to_vec())),
                    correlation_value: None,
                }),
                message_extension: None,
            },
        )],
    };
    assert_eq!(
        to_ttlv(&req).unwrap_err().to_string(),
        "request payload operation is not a request type operation (`Response`)".to_owned()
    );

    // check Message response serializer reinforcement
    let res = ResponseMessage {
        response_header: ResponseMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            time_stamp: 1_697_201_574,
            ..Default::default()
        },
        batch_item: vec![ResponseMessageBatchItemVersioned::V21(
            ResponseMessageBatchItem {
                operation: Some(OperationEnumeration::Decrypt),
                unique_batch_item_id: None,
                // mismatch operation regarding the enum
                response_payload: Some(Operation::Locate(Locate::default())),
                message_extension: None,
                result_status: ResultStatusEnumeration::OperationPending,
                result_reason: None,
                result_message: None,
                asynchronous_correlation_value: None,
            },
        )],
    };
    assert_eq!(
        to_ttlv(&res).unwrap_err().to_string(),
        "missing `AsynchronousCorrelationValue` with pending status (`ResultStatus` is set to \
         `OperationPending`)"
            .to_owned()
    );

    let res = ResponseMessage {
        response_header: ResponseMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            time_stamp: 1_697_201_574,
            ..Default::default()
        },
        batch_item: vec![ResponseMessageBatchItemVersioned::V21(
            ResponseMessageBatchItem {
                operation: Some(OperationEnumeration::Decrypt),
                unique_batch_item_id: None,
                // mismatch operation regarding the enum
                response_payload: Some(Operation::Locate(Locate::default())),
                message_extension: None,
                result_status: ResultStatusEnumeration::OperationPending,
                result_reason: None,
                result_message: None,
                asynchronous_correlation_value: Some("0, 0, 1".to_owned()),
            },
        )],
    };
    assert_eq!(
        to_ttlv(&res).unwrap_err().to_string(),
        "operation enum (`Decrypt`) doesn't correspond to response payload (`Locate`)".to_owned()
    );

    let res = ResponseMessage {
        response_header: ResponseMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            time_stamp: 1_697_201_574,
            ..Default::default()
        },
        batch_item: vec![ResponseMessageBatchItemVersioned::V21(
            ResponseMessageBatchItem::new(ResultStatusEnumeration::OperationPending),
        )],
    };
    assert_eq!(
        to_ttlv(&res).unwrap_err().to_string(),
        "missing `AsynchronousCorrelationValue` with pending status (`ResultStatus` is set to \
         `OperationPending`)"
            .to_owned()
    );

    let res = ResponseMessage {
        response_header: ResponseMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            client_correlation_value: Some("client_123".to_owned()),
            server_correlation_value: Some("server_234".to_owned()),
            attestation_type: Some(vec![AttestationType::TPM_Quote]),
            time_stamp: 1_697_201_574,
            nonce: Some(Nonce {
                nonce_id: vec![5, 6, 7],
                nonce_value: vec![8, 9, 0],
            }),
            server_hashed_password: Some(b"5e8953ab".to_vec()),
        },
        batch_item: vec![ResponseMessageBatchItemVersioned::V21(
            ResponseMessageBatchItem {
                operation: Some(OperationEnumeration::Locate),
                unique_batch_item_id: Some(b"1234".to_vec()),
                // in a message response, we can't have `Operation::Locate`,
                // we could only have an `Operation::LocateResponse`
                response_payload: Some(Operation::Locate(Locate::default())),
                message_extension: Some(MessageExtension {
                    vendor_identification: "CosmianVendor".to_owned(),
                    criticality_indicator: false,
                    vendor_extension: vec![42_u8],
                }),
                result_status: ResultStatusEnumeration::OperationPending,
                result_reason: None,
                result_message: None,
                asynchronous_correlation_value: Some("42_u8, 5".to_owned()),
            },
        )],
    };
    assert_eq!(
        to_ttlv(&res).unwrap_err().to_string(),
        "response payload operation is not a response type operation (`Request`)".to_owned()
    );
}

#[test]
fn test_deserialization_set_attribute() -> KmipResult<()> {
    log_init(option_env!("RUST_LOG"));
    let set_attribute_request = r#"
    {
      "tag": "SetAttribute",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "173cb39b-c95a-4e98-ae0d-3e8079e145e6"
        },
        {
          "tag": "NewAttribute",
          "type": "Structure",
          "value": [
            {
              "tag": "Link",
              "type": "Structure",
              "value": [
                {
                  "tag": "LinkType",
                  "type": "Enumeration",
                  "value": "PublicKeyLink"
                },
                {
                  "tag": "LinkedObjectIdentifier",
                  "type": "TextString",
                  "value": "public_key_id"
                }
              ]
            }
          ]
        }
      ]
    }
    "#;
    let ttlv: TTLV = serde_json::from_str(set_attribute_request)?;
    trace!("ttlv: {:?}", &ttlv);
    let _set_attribute_request: SetAttribute = from_ttlv(ttlv)?;

    Ok(())
}

#[test]
fn test_deserialization_attribute() -> KmipResult<()> {
    log_init(option_env!("RUST_LOG"));
    let attribute_str = r#"
    {
          "tag": "NewAttribute",
          "type": "Structure",
          "value": [
            {
              "tag": "Link",
              "type": "Structure",
              "value": [
                {
                  "tag": "LinkType",
                  "type": "Enumeration",
                  "value": "PublicKeyLink"
                },
                {
                  "tag": "LinkedObjectIdentifier",
                  "type": "TextString",
                  "value": "public_key_id"
                }
              ]
            }
          ]
    }
    "#;
    let ttlv: TTLV = serde_json::from_str(attribute_str)?;
    trace!("ttlv: {:?}", ttlv);

    let _unused: Attribute = from_ttlv(ttlv)?;

    Ok(())
}

#[test]
fn test_deserialization_link() -> KmipResult<()> {
    log_init(option_env!("RUST_LOG"));
    let link_str = r#"
    {
              "tag": "Link",
              "type": "Structure",
              "value": [
                {
                  "tag": "LinkType",
                  "type": "Enumeration",
                  "value": "PublicKeyLink"
                },
                {
                  "tag": "LinkedObjectIdentifier",
                  "type": "TextString",
                  "value": "public_key_id"
                }
              ]
    }
    "#;
    let ttlv: TTLV = serde_json::from_str(link_str)?;
    trace!("ttlv: {:?}", ttlv);

    let _unused: Link = from_ttlv(ttlv)?;

    Ok(())
}

#[test]
fn test_serialization_set_attribute() -> KmipResult<()> {
    log_init(option_env!("RUST_LOG"));
    let set_attribute_request = SetAttribute {
        unique_identifier: Some(UniqueIdentifier::TextString(
            "173cb39b-c95a-4e98-ae0d-3e8079e145e6".to_owned(),
        )),
        new_attribute: Attribute::Links(vec![
            Link {
                link_type: LinkType::PublicKeyLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(
                    "public_key_id".to_owned(),
                ),
            },
            Link {
                link_type: LinkType::PrivateKeyLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(
                    "private_key_id".to_owned(),
                ),
            },
        ]),
    };

    let set_attribute = to_ttlv(&set_attribute_request)?;
    trace!("set_attribute: {:#?}", set_attribute);

    let set_attribute_deserialized: SetAttribute = from_ttlv(set_attribute)?;
    trace!("set_attribute_deserialized: {}", set_attribute_deserialized);

    Ok(())
}

#[test]
fn test_serialization_link() -> KmipResult<()> {
    log_init(option_env!("RUST_LOG"));
    let link_request = vec![Link {
        link_type: LinkType::PublicKeyLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString("public_key_id".to_owned()),
    }];

    let link = to_ttlv(&link_request)?;
    trace!("link: {:#?}", link);

    let link_deserialized: Vec<Link> = from_ttlv(link)?;
    trace!("set_attribute_deserialized: {:?}", link_deserialized);

    Ok(())
}

#[test]
fn integer_deserialization_test() -> KmipResult<()> {
    log_init(option_env!("RUST_LOG"));
    let integer_str = r#"
    {
        "tag": "IntegerNumber",
        "type": "Integer",
        "value": 123456789
    }
    "#;
    let ttlv: TTLV = serde_json::from_str(integer_str)?;
    if ttlv.value != TTLValue::Integer(123_456_789) {
        return Err(KmipError::Default("Expected Integer(123456789)".to_owned()));
    }

    let integer_str = r#"
    {
        "tag": "IntegerHex",
        "type": "Integer",
        "value": "0x075bcd15"
    }
    "#;
    let ttlv: TTLV = serde_json::from_str(integer_str)?;
    if ttlv.value != TTLValue::Integer(123_456_789) {
        return Err(KmipError::Default("Expected Integer(123456789)".to_owned()));
    }
    Ok(())
}

#[test]
fn long_integer_deserialization_test() -> KmipResult<()> {
    log_init(option_env!("RUST_LOG"));
    let integer_str = r#"
    {
        "tag": "IntegerNumber",
        "type": "LongInteger",
        "value": 123456789
    }
    "#;
    let ttlv: TTLV = serde_json::from_str(integer_str)?;
    if ttlv.value != TTLValue::LongInteger(123_456_789) {
        return Err(KmipError::Default(
            "Expected LongInteger(123456789)".to_owned(),
        ));
    }

    let integer_str = r#"
    {
        "tag": "IntegerHex",
        "type": "LongInteger",
        "value": "0x00000000075bcd15"
    }
    "#;
    let ttlv: TTLV = serde_json::from_str(integer_str)?;
    if ttlv.value != TTLValue::LongInteger(123_456_789) {
        return Err(KmipError::Default(
            "Expected LongInteger(123456789)".to_owned(),
        ));
    }
    Ok(())
}

#[test]
fn normative_request_message_test() {
    log_init(option_env!("RUST_LOG"));
    let ttlv_string = r#"
{"tag":"RequestMessage", "value":[
  {"tag":"RequestHeader", "value":[
    {"tag":"ProtocolVersion", "value":[
      {"tag":"ProtocolVersionMajor", "type":"Integer", "value":"0x00000002"},
      {"tag":"ProtocolVersionMinor", "type":"Integer", "value":"0x00000001"}
    ]},
    {"tag":"MaximumResponseSize", "type":"Integer", "value":"0x00000100"},
    {"tag":"BatchCount", "type":"Integer", "value":"0x00000001"}
  ]},
  {"tag":"BatchItem", "value":[
    {"tag":"Operation", "type":"Enumeration", "value":"Query"},
    {"tag":"RequestPayload", "value":[
      {"tag":"QueryFunction", "type":"Enumeration","value":"QueryOperations"},
      {"tag":"QueryFunction", "type":"Enumeration", "value":"QueryObjects"}
    ]}
  ]}
]}    
    "#;
    // Deserialize
    let ttlv: TTLV = serde_json::from_str(ttlv_string).unwrap();

    // Serialize
    let re_json = serde_json::to_string_pretty(&ttlv).unwrap();

    // Deserialize again
    let ttlv_: TTLV = serde_json::from_str(&re_json).unwrap();
    assert_eq!(ttlv, ttlv_);

    // Deserializer
    let norm_req: RequestMessage = from_ttlv(ttlv.clone()).unwrap();

    // KMIP Request Message in Rust
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            maximum_response_size: Some(256),
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Query,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Query(Query {
                    query_function: Some(vec![
                        QueryFunction::QueryOperations,
                        QueryFunction::QueryObjects,
                    ]),
                }),
                message_extension: None,
            },
        )],
    };
    assert_eq!(request_message, norm_req);

    // Serializer
    let ttlv__ = to_ttlv(&request_message).unwrap();
    assert_eq!(ttlv__, ttlv);
}

#[test]
fn test_locate_with_empty_attributes() {
    log_init(option_env!("RUST_LOG"));
    let locate = Locate::default();

    // Serializer
    let ttlv = to_ttlv(&locate).unwrap();
    info!("{:#?}", ttlv);

    // Serialize
    let json = serde_json::to_string_pretty(&ttlv).unwrap();
    info!("{}", json);

    // Deserialize
    let ttlv_from_json = serde_json::from_str::<TTLV>(&json).unwrap();
    assert_eq!(ttlv, ttlv_from_json);

    // Deserializer
    let locate_: Locate = from_ttlv(ttlv).unwrap();
    assert_eq!(locate, locate_);
}

//TODO: implement the Query operation in 2.1 first
// #[test]
// fn test_query_response() {
//     log_init(option_env!("RUST_LOG"));
//
//     let response_batch_item = ResponseMessageBatchItem {
//         operation: Some(OperationEnumeration::Query),
//         unique_batch_item_id: None,
//         response_payload: Some(Operation::QueryResponse(QueryResponse {
//             operation: Some(vec![
//                 OperationEnumeration::Activate,
//                 OperationEnumeration::Create,
//                 OperationEnumeration::Get,
//             ]),
//             object_type: None,
//             vendor_identification: None,
//             application_namespaces: None,
//             server_information: None,
//             extension_information: None,
//             attestation_types: None,
//             rng_mode: None,
//             profiles_supported: None,
//             validation_information: None,
//             capability_information: None,
//             client_registration_methods: None,
//             defaults_information: None,
//             protection_storage_masks: None,
//         })),
//         result_status: ResultStatusEnumeration::Success,
//         result_reason: None,
//         result_message: None,
//         asynchronous_correlation_value: None,
//         message_extension: None,
//     };
//
//     let ttlv = to_ttlv(&response_batch_item).unwrap();
//     trace!("batch item: {:#?}", ttlv);
//
//     let response_batch_item_: ResponseMessageBatchItem = from_ttlv(ttlv).unwrap();
//     trace!("query_response_deserialized: {:#?}", response_batch_item_);
//
//     assert_eq!(response_batch_item, response_batch_item_);
// }

#[test]
pub(crate) fn test_simple_message_request() {
    log_init(option_env!("RUST_LOG"));

    let req = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Query,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Query(Query {
                    query_function: Some(vec![QueryFunction::QueryOperations]),
                }),
                message_extension: None,
            },
        )],
    };
    let ttlv = to_ttlv(&req).unwrap();
    info!("TTLV: {:#?}", ttlv);
    let req_: RequestMessage = from_ttlv(ttlv).unwrap();
    info!("{:#?}", req_);
    let RequestMessageBatchItemVersioned::V21(batch_item) = &req_.batch_item[0] else {
        panic!("not a v2.1 batch item");
    };
    assert_eq!(batch_item.operation, OperationEnumeration::Query);
    let Operation::Query(query) = &batch_item.request_payload else {
        panic!("not an encrypt operation's request payload: {batch_item}");
    };
    assert_eq!(
        query.query_function,
        Some(vec![QueryFunction::QueryOperations])
    );
    assert_eq!(req, req_);
}

#[test]
pub(crate) fn test_message_request() {
    log_init(option_env!("RUST_LOG"));

    let req = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            maximum_response_size: Some(9999),
            batch_count: 1,
            client_correlation_value: Some("client_123".to_owned()),
            server_correlation_value: Some("server_234".to_owned()),
            asynchronous_indicator: Some(AsynchronousIndicator::Optional),
            attestation_capable_indicator: Some(true),
            attestation_type: Some(vec![AttestationType::TPM_Quote]),
            authentication: Some(vec![Credential::Attestation {
                nonce: Nonce {
                    nonce_id: vec![9, 8, 7],
                    nonce_value: vec![10, 11, 12],
                },
                attestation_type: AttestationType::TCG_Integrity_Report,
                attestation_measurement: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
                attestation_assertion: Some(vec![11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
            }]),
            batch_error_continuation_option: Some(BatchErrorContinuationOption::Undo),
            batch_order_option: Some(true),
            time_stamp: Some(1_950_940_403),
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Encrypt,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Encrypt(Encrypt {
                    data: Some(Zeroizing::from(b"to be enc".to_vec())),
                    ..Default::default()
                }),
                message_extension: Some(vec![MessageExtension {
                    vendor_identification: "CosmianVendor".to_owned(),
                    criticality_indicator: false,
                    vendor_extension: vec![42_u8],
                }]),
            },
        )],
    };
    let ttlv = to_ttlv(&req).unwrap();
    let req_: RequestMessage = from_ttlv(ttlv).unwrap();
    let RequestMessageBatchItemVersioned::V21(batch_item) = &req_.batch_item[0] else {
        panic!("not a v2.1 batch item");
    };
    assert_eq!(batch_item.operation, OperationEnumeration::Encrypt);
    let Operation::Encrypt(encrypt) = &batch_item.request_payload else {
        panic!("not an encrypt operation's request payload: {batch_item}");
    };
    assert_eq!(encrypt.data, Some(Zeroizing::from(b"to be enc".to_vec())));
    assert_eq!(req, req_);
}

#[test]
pub(crate) fn test_message_response() {
    log_init(option_env!("RUST_LOG"));

    let res = ResponseMessage {
        response_header: ResponseMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 2,
            client_correlation_value: Some("client_123".to_owned()),
            server_correlation_value: Some("server_234".to_owned()),
            attestation_type: Some(vec![AttestationType::TPM_Quote]),
            time_stamp: 1_697_201_574,
            nonce: Some(Nonce {
                nonce_id: vec![5, 6, 7],
                nonce_value: vec![8, 9, 0],
            }),
            server_hashed_password: Some(b"5e8953ab".to_vec()),
        },
        batch_item: vec![
            ResponseMessageBatchItemVersioned::V21(ResponseMessageBatchItem {
                operation: Some(OperationEnumeration::Locate),
                unique_batch_item_id: Some(b"1234".to_vec()),
                response_payload: Some(Operation::LocateResponse(LocateResponse {
                    located_items: Some(134),
                    unique_identifiers: Some(vec![UniqueIdentifier::TextString(
                        "some_id".to_owned(),
                    )]),
                })),
                message_extension: Some(MessageExtension {
                    vendor_identification: "CosmianVendor".to_owned(),
                    criticality_indicator: false,
                    vendor_extension: vec![42_u8],
                }),
                result_status: ResultStatusEnumeration::OperationPending,
                result_reason: None,
                result_message: None,
                asynchronous_correlation_value: Some("42_u8, 5".to_owned()),
            }),
            ResponseMessageBatchItemVersioned::V21(ResponseMessageBatchItem {
                operation: Some(OperationEnumeration::Decrypt),
                unique_batch_item_id: Some(b"1235".to_vec()),
                response_payload: Some(Operation::DecryptResponse(DecryptResponse {
                    unique_identifier: UniqueIdentifier::TextString("id_12345".to_owned()),
                    data: Some(Zeroizing::from(b"decrypted_data".to_vec())),
                    correlation_value: Some(vec![9_u8, 13]),
                })),
                message_extension: Some(MessageExtension {
                    vendor_identification: "CosmianVendor".to_owned(),
                    criticality_indicator: true,
                    vendor_extension: vec![42_u8],
                }),
                result_status: ResultStatusEnumeration::OperationUndone,
                result_reason: Some(ErrorReason::Response_Too_Large),
                result_message: Some("oversized data".to_owned()),
                asynchronous_correlation_value: Some("43_u8, 6".to_owned()),
            }),
        ],
    };
    let ttlv = to_ttlv(&res).unwrap();
    let res_: ResponseMessage = from_ttlv(ttlv).unwrap();
    assert_eq!(res_.batch_item.len(), 2);
    let ResponseMessageBatchItemVersioned::V21(batch_item) = &res_.batch_item[0] else {
        panic!("not a v2.1 batch item");
    };
    assert_eq!(batch_item.operation, Some(OperationEnumeration::Locate));
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::OperationPending
    );
    let ResponseMessageBatchItemVersioned::V21(batch_item) = &res_.batch_item[1] else {
        panic!("not a v2.1 batch item");
    };
    assert_eq!(batch_item.operation, Some(OperationEnumeration::Decrypt));
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::OperationUndone
    );

    let Some(Operation::DecryptResponse(decrypt)) = &batch_item.response_payload else {
        panic!("not a decrypt operation's response payload");
    };
    assert_eq!(
        decrypt.data,
        Some(Zeroizing::from(b"decrypted_data".to_vec()))
    );
    assert_eq!(
        decrypt.unique_identifier,
        UniqueIdentifier::TextString("id_12345".to_owned())
    );
    assert_eq!(res, res_);
}

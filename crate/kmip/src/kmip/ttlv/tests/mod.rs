use std::time::SystemTime;

use chrono::{DateTime, Utc};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use tracing::trace;

use crate::{
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Create, Import, ImportResponse},
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, Link,
            LinkedObjectIdentifier,
        },
        ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLVEnumeration, TTLValue, TTLV},
    },
    log_utils::log_init,
};

pub(crate) fn aes_key_material(key_value: &[u8]) -> KeyMaterial {
    KeyMaterial::TransparentSymmetricKey {
        key: key_value.to_vec(),
    }
}

pub(crate) fn aes_key_value(key_value: &[u8]) -> KeyValue {
    KeyValue {
        key_material: aes_key_material(key_value),
        attributes: Some(Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            ..Attributes::new(ObjectType::SymmetricKey)
        }),
    }
}

pub(crate) fn aes_key_block(key_value: &[u8]) -> KeyBlock {
    KeyBlock {
        key_format_type: KeyFormatType::TransparentSymmetricKey,
        key_compression_type: None,
        key_value: aes_key_value(key_value),
        cryptographic_algorithm: CryptographicAlgorithm::AES,
        cryptographic_length: 256,
        key_wrapping_data: None,
    }
}

pub(crate) fn aes_key(key_value: &[u8]) -> Object {
    Object::SymmetricKey {
        key_block: aes_key_block(key_value),
    }
}

pub(crate) fn aes_key_material_ttlv(key_value: &[u8]) -> TTLV {
    TTLV {
        tag: "KeyMaterial".to_string(),
        value: TTLValue::Structure(vec![TTLV {
            tag: "Key".to_string(),
            value: TTLValue::ByteString(key_value.to_vec()),
        }]),
    }
}

pub(crate) fn aes_key_value_ttlv(key_value: &[u8]) -> TTLV {
    TTLV {
        tag: "KeyValue".to_string(),
        value: TTLValue::Structure(vec![
            aes_key_material_ttlv(key_value),
            TTLV {
                tag: "Attributes".to_string(),
                value: TTLValue::Structure(vec![
                    TTLV {
                        tag: "CryptographicAlgorithm".to_string(),
                        value: TTLValue::Enumeration(TTLVEnumeration::Name("AES".to_string())),
                    },
                    TTLV {
                        tag: "CryptographicLength".to_string(),
                        value: TTLValue::Integer(256),
                    },
                    TTLV {
                        tag: "CryptographicUsageMask".to_string(),
                        value: TTLValue::Integer(4),
                    },
                    TTLV {
                        tag: "KeyFormatType".to_string(),
                        value: TTLValue::Enumeration(TTLVEnumeration::Name(
                            "TransparentSymmetricKey".to_string(),
                        )),
                    },
                    TTLV {
                        tag: "ObjectType".to_string(),
                        value: TTLValue::Enumeration(TTLVEnumeration::Name(
                            "SymmetricKey".to_string(),
                        )),
                    },
                ]),
            },
        ]),
    }
}

pub(crate) fn aes_key_block_ttlv(key_value: &[u8]) -> TTLV {
    TTLV {
        tag: "KeyBlock".to_string(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "KeyFormatType".to_string(),
                value: TTLValue::Enumeration(TTLVEnumeration::Name(
                    "TransparentSymmetricKey".to_string(),
                )),
            },
            aes_key_value_ttlv(key_value),
            TTLV {
                tag: "CryptographicAlgorithm".to_string(),
                value: TTLValue::Enumeration(TTLVEnumeration::Name("AES".to_string())),
            },
            TTLV {
                tag: "CryptographicLength".to_string(),
                value: TTLValue::Integer(256),
            },
        ]),
    }
}

pub(crate) fn aes_key_ttlv(key_value: &[u8]) -> TTLV {
    TTLV {
        tag: "Object".to_string(),
        value: TTLValue::Structure(vec![aes_key_block_ttlv(key_value)]),
    }
}

#[test]
fn test_enumeration() {
    let es = TTLVEnumeration::Name("blah".to_string());
    let s = serde_json::to_string_pretty(&es).unwrap();
    assert_eq!(es, serde_json::from_str(&s).unwrap());

    let i_plus = TTLVEnumeration::Integer(1);
    let s = serde_json::to_string_pretty(&i_plus).unwrap();
    assert_eq!(i_plus, serde_json::from_str(&s).unwrap());

    let i_minus = TTLVEnumeration::Integer(-1);
    let s = serde_json::to_string_pretty(&i_minus).unwrap();
    assert_eq!(i_minus, serde_json::from_str(&s).unwrap());
}

#[test]
fn test_serialization_deserialization() {
    let now: DateTime<Utc> = SystemTime::now().into();
    let ttlv = TTLV {
        tag: "Test".to_string(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "AnInt".to_string(),
                value: TTLValue::Integer(42),
            },
            TTLV {
                tag: "ABitMask".to_string(),
                value: TTLValue::BitMask(42),
            },
            TTLV {
                tag: "ALongInt".to_string(),
                value: TTLValue::LongInteger(-42_i64),
            },
            TTLV {
                tag: "ABigInteger".to_string(),
                value: TTLValue::BigInteger(BigUint::from(2_487_678_887_987_987_798_676_u128)),
            },
            TTLV {
                tag: "AnEnumeration_1".to_string(),
                value: TTLValue::Enumeration(TTLVEnumeration::Integer(54)),
            },
            TTLV {
                tag: "AnEnumeration_2".to_string(),
                value: TTLValue::Enumeration(TTLVEnumeration::Name("blah".to_string())),
            },
            TTLV {
                tag: "ABoolean".to_string(),
                value: TTLValue::Boolean(true),
            },
            TTLV {
                tag: "ATextString".to_string(),
                value: TTLValue::TextString("blah".to_string()),
            },
            TTLV {
                tag: "AnByteString".to_string(),
                value: TTLValue::ByteString(b"hello".to_vec()),
            },
            TTLV {
                tag: "ADateTime".to_string(),
                value: TTLValue::DateTime(now),
            },
            TTLV {
                tag: "AnInterval".to_string(),
                value: TTLValue::Interval(27),
            },
            TTLV {
                tag: "ADateTimeExtended".to_string(),
                value: TTLValue::DateTimeExtended(now),
            },
        ]),
    };
    let j = serde_json::to_string_pretty(&ttlv).unwrap();
    let rec: TTLV = serde_json::from_str(&j).unwrap();
    match rec.value {
        TTLValue::Structure(s) => match &s[0].value {
            TTLValue::Integer(i) => assert_eq!(42, *i),
            x => panic!("unexpected 2nd level type : {:?}", x),
        },
        x => panic!("unexpected type : {:?}", x),
    };
}

#[test]
fn test_ser_int() {
    log_init("debug,hyper=info,reqwest=info");
    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        an_int: u32,
    }

    let test = Test {
        an_int: 1,
        // seq: vec!["a", "b"],
    };
    let ttlv = to_ttlv(&test).unwrap();
    let expected =
        r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "AnInt", value: Integer(1) }]) }"#;
    let ttlv_s = format!("{:?}", ttlv);
    assert_eq!(ttlv_s, expected);
}

#[test]
fn test_ser_array() {
    log_init("debug,hyper=info,reqwest=info");
    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        seq: Vec<&'static str>,
    }

    let test = Test {
        seq: vec!["a", "b"],
    };
    let ttlv = to_ttlv(&test).unwrap();
    let expected = r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "Seq", value: Structure([TTLV { tag: "Seq", value: TextString("a") }, TTLV { tag: "Seq", value: TextString("b") }]) }]) }"#;
    let ttlv_s = format!("{:?}", ttlv);
    // println!("{}", serde_json::to_string_pretty(&ttlv).unwrap());
    assert_eq!(ttlv_s, expected);
}

#[test]
fn test_ser_big_int() {
    log_init("debug,hyper=info,reqwest=info");
    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        big_int: BigUint,
    }

    let test = Test {
        big_int: BigUint::from(0x1111_1111_1222_2222_u128),
    };
    let ttlv = to_ttlv(&test).unwrap();
    // println!("{:#?}", ttlv);
    let expected = r#"TTLV {
    tag: "Test",
    value: Structure(
        [
            TTLV {
                tag: "BigInt",
                value: BigInteger(
                    1229782938265199138,
                ),
            },
        ],
    ),
}"#;
    let ttlv_s = format!("{:#?}", ttlv);
    // println!("{}", serde_json::to_string_pretty(&ttlv).unwrap());
    assert_eq!(ttlv_s, expected);
}

#[test]
fn test_ser_aes_key() {
    log_init("debug,hyper=info,reqwest=info");
    let key_bytes: &[u8] = b"this_is_a_test";
    let aes_key = aes_key(key_bytes);
    let ttlv = to_ttlv(&aes_key).unwrap();
    assert_eq!(aes_key_ttlv(key_bytes), ttlv);
}

#[test]
fn test_des_int() {
    log_init("debug,hyper=info,reqwest=info");

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        an_int: i32,
        another_int: u32,
    }

    let ttlv = TTLV {
        tag: "Test".to_string(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "AnInt".to_string(),
                value: TTLValue::Integer(2),
            },
            TTLV {
                tag: "AnotherInt".to_string(),
                value: TTLValue::BitMask(4),
            },
        ]),
    };

    let rec: Test = from_ttlv(&ttlv).unwrap();
    assert_eq!(
        &Test {
            an_int: 2,
            another_int: 4
        },
        &rec
    )
}

#[test]
fn test_des_array() {
    log_init("debug,hyper=info,reqwest=info");

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        ints: Vec<i32>,
    }

    let ttlv = TTLV {
        tag: "Test".to_string(),
        value: TTLValue::Structure(vec![TTLV {
            tag: "Ints".to_string(),
            value: TTLValue::Structure(vec![
                TTLV {
                    tag: "Ints".to_string(),
                    value: TTLValue::Integer(2),
                },
                TTLV {
                    tag: "Ints".to_string(),
                    value: TTLValue::Integer(4),
                },
            ]),
        }]),
    };

    let rec: Test = from_ttlv(&ttlv).unwrap();
    assert_eq!(&Test { ints: vec![2, 4] }, &rec)
}

#[test]
fn test_des_enum() {
    log_init("debug,hyper=info,reqwest=info");

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        crypto_algo: CryptographicAlgorithm,
    }

    let ttlv = TTLV {
        tag: "Test".to_string(),
        value: TTLValue::Structure(vec![TTLV {
            tag: "CryptoAlgo".to_string(),
            value: TTLValue::Enumeration(TTLVEnumeration::Name("AES".to_string())),
        }]),
    };

    let rec: Test = from_ttlv(&ttlv).unwrap();
    assert_eq!(
        &Test {
            crypto_algo: CryptographicAlgorithm::AES
        },
        &rec
    )
}

#[test]
fn test_key_material_vec_deserialization() {
    log_init("debug,hyper=info,reqwest=info");
    let bytes = vec![
        116, 104, 105, 115, 95, 105, 115, 95, 97, 95, 116, 101, 115, 116,
    ];
    let ttlv = TTLV {
        tag: "KeyMaterial".to_string(),
        value: TTLValue::Structure(vec![TTLV {
            tag: "Key".to_string(),
            value: TTLValue::ByteString(bytes.clone()),
        }]),
    };
    let km_: KeyMaterial = from_ttlv(&ttlv).unwrap();
    let km = KeyMaterial::TransparentSymmetricKey { key: bytes };
    assert_eq!(km, km_);
}

#[test]
fn test_key_material_big_int_deserialization() {
    log_init("debug,hyper=info,reqwest=info");
    let ttlv = TTLV {
        tag: "KeyMaterial".to_string(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "P".to_string(),
                value: TTLValue::BigInteger(BigUint::from(u32::MAX)),
            },
            TTLV {
                tag: "Q".to_string(),
                value: TTLValue::BigInteger(BigUint::from(1_u32)),
            },
            TTLV {
                tag: "G".to_string(),
                value: TTLValue::BigInteger(BigUint::from(2_u32)),
            },
            TTLV {
                tag: "X".to_string(),
                value: TTLValue::BigInteger(BigUint::from(u128::MAX)),
            },
        ]),
    };
    let km = KeyMaterial::TransparentDHPrivateKey {
        p: BigUint::from(u32::MAX),
        q: Some(BigUint::from(1_u64)),
        g: BigUint::from(2_u32),
        j: None,
        x: BigUint::from(u128::MAX),
    };
    let ttlv_ = to_ttlv(&km).unwrap();
    assert_eq!(ttlv, ttlv_);
    let km_: KeyMaterial = from_ttlv(&ttlv_).unwrap();
    assert_eq!(km, km_);
}

#[test]
fn test_big_int_deserialization() {
    let km = KeyMaterial::TransparentDHPrivateKey {
        p: BigUint::from(u32::MAX),
        q: Some(BigUint::from(1_u64)),
        g: BigUint::from(2_u32),
        j: None,
        x: BigUint::from(u128::MAX - 1),
    };
    let j = serde_json::to_value(&km).unwrap();
    let km_: KeyMaterial = serde_json::from_value(j).unwrap();
    assert_eq!(km, km_);
}

#[test]
fn test_des_aes_key() {
    log_init("trace,hyper=info,reqwest=info");
    let key_bytes: &[u8] = b"this_is_a_test";
    trace!("HELLO");

    let json = serde_json::to_value(aes_key(key_bytes)).unwrap();
    let o: Object = serde_json::from_value(json).unwrap();
    // Deserialization cannot make the difference
    // between a `SymmetricKey` or a `PrivateKey`
    assert_eq!(
        aes_key(key_bytes),
        Object::post_fix(ObjectType::SymmetricKey, o)
    );

    let ttlv = aes_key_ttlv(key_bytes);
    let rec: Object = from_ttlv(&ttlv).unwrap();
    // Deserialization cannot make the difference
    // between a `SymmetricKey` or a `PrivateKey`
    assert_eq!(
        aes_key(key_bytes),
        Object::post_fix(ObjectType::SymmetricKey, rec)
    )
}

#[test]
fn test_aes_key_block() {
    log_init("debug,hyper=info,reqwest=info");
    let key_bytes: &[u8] = b"this_is_a_test";
    //
    let json = serde_json::to_value(aes_key_block(key_bytes)).unwrap();
    let kv: KeyBlock = serde_json::from_value(json).unwrap();
    assert_eq!(aes_key_block(key_bytes), kv);
    //
    let ttlv = aes_key_block_ttlv(key_bytes);
    let rec: KeyBlock = from_ttlv(&ttlv).unwrap();
    assert_eq!(aes_key_block(key_bytes), rec)
}

#[test]
fn test_aes_key_value() {
    log_init("trace,hyper=info,reqwest=info");
    let key_bytes: &[u8] = b"this_is_a_test";
    //
    let json = serde_json::to_value(aes_key_value(key_bytes)).unwrap();
    // println!("JSON {:?}", json);
    let kv: KeyValue = serde_json::from_value(json).unwrap();
    assert_eq!(aes_key_value(key_bytes), kv);

    let ttlv = aes_key_value_ttlv(key_bytes);
    let rec: KeyValue = from_ttlv(&ttlv).unwrap();
    assert_eq!(aes_key_value(key_bytes), rec);
}

#[test]
fn test_aes_key_material() {
    log_init("debug,hyper=info,reqwest=info");
    let key_bytes: &[u8] = b"this_is_a_test";
    let ttlv = aes_key_material_ttlv(key_bytes);
    let rec: KeyMaterial = from_ttlv(&ttlv).unwrap();
    assert_eq!(aes_key_material(key_bytes), rec)
}

#[test]
#[allow(clippy::large_enum_variant)]
fn test_some_attributes() {
    log_init("debug,hyper=info,reqwest=info");
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    #[serde(untagged)]
    enum Wrapper {
        Attr {
            #[serde(skip_serializing_if = "Option::is_none", rename = "Attributes")]
            attributes: Option<Attributes>,
        },
        NoAttr {
            whatever: i32,
        },
    }
    let value = Wrapper::Attr {
        attributes: Some(Attributes::new(ObjectType::SymmetricKey)),
    };
    let ttlv = to_ttlv(&value).unwrap();
    // println!("TTLV: {:#?}", &ttlv);
    let json = serde_json::to_value(&ttlv).unwrap();
    // println!("JSON: {:#?}", &json);
    let ttlv_: TTLV = serde_json::from_value(json).unwrap();
    assert_eq!(ttlv, ttlv_);
    let rec: Wrapper = from_ttlv(&ttlv_).unwrap();
    // println!("REC: {:#?}", &rec);
    assert_eq!(value, rec);
}

#[test]
fn test_java_import_request() {
    log_init("debug,hyper=info,reqwest=info");
    let ir_java = r#"
{
  "tag" : "Import",
  "value" : [ {
    "tag" : "UniqueIdentifier",
    "type" : "TextString",
    "value" : "unique_identifier"
  }, {
    "tag" : "ObjectType",
    "type" : "Enumeration",
    "value" : "SymmetricKey"
  }, {
    "tag" : "ReplaceExisting",
    "type" : "Boolean",
    "value" : true
  }, {
    "tag" : "KeyWrapType",
    "type" : "Enumeration",
    "value" : "AsRegistered"
  }, {
    "tag" : "Attributes",
    "value" : [ {
      "tag" : "Link",
      "value" : [ ]
    }, {
      "tag" : "ObjectType",
      "type" : "Enumeration",
      "value" : "OpaqueObject"
    } ]
  }, {
    "tag" : "Object",
    "value" : [ {
      "tag" : "KeyBlock",
      "value" : [ {
        "tag" : "KeyFormatType",
        "type" : "Enumeration",
        "value" : "TransparentSymmetricKey"
      }, {
        "tag" : "KeyValue",
        "value" : [ {
          "tag" : "KeyMaterial",
          "value" : [ {
            "tag" : "Key",
            "type" : "ByteString",
            "value" : "6279746573"
          } ]
        } ]
      }, {
        "tag" : "CryptographicAlgorithm",
        "type" : "Enumeration",
        "value" : "AES"
      }, {
        "tag" : "CryptographicLength",
        "type" : "Integer",
        "value" : 256
      } ]
    } ]
  } ]
}
"#;
    let ttlv: TTLV = serde_json::from_str(ir_java).unwrap();
    let _import_request: Import = from_ttlv(&ttlv).unwrap();
}

#[test]
pub fn test_java_import_request_2() {
    log_init("info");
    let json = include_str!("./import_abe_public_key_java.json");
    let ttlv: TTLV = serde_json::from_str(json).unwrap();
    let _import_request: Import = from_ttlv(&ttlv).unwrap();
}

#[test]
fn test_java_import_response() {
    log_init("info");
    let ir = ImportResponse {
        unique_identifier: "blah".to_string(),
    };
    let json = serde_json::to_string(&to_ttlv(&ir).unwrap()).unwrap();
    let ir_ = from_ttlv(&serde_json::from_str::<TTLV>(&json).unwrap()).unwrap();
    assert_eq!(ir, ir_);
}

#[test]
fn test_byte_string_key_material() {
    log_init("info");
    let key_bytes: &[u8] = b"this_is_a_test";
    let key_value = KeyValue {
        key_material: KeyMaterial::ByteString(key_bytes.to_vec()),
        attributes: Some(Attributes::new(ObjectType::SymmetricKey)),
    };
    let ttlv = to_ttlv(&key_value).unwrap();
    // println!("{:#?}", &ttlv);
    let key_value_: KeyValue = from_ttlv(&ttlv).unwrap();
    assert_eq!(key_value, key_value_);
}

#[test]
fn test_aes_key_full() {
    log_init("info");
    let key_bytes: &[u8] = b"this_is_a_test";
    let aes_key = aes_key(key_bytes);
    let ttlv = to_ttlv(&aes_key).unwrap();
    // println!("{:#?}", &ttlv);
    let aes_key_: Object = from_ttlv(&ttlv).unwrap();
    assert_eq!(
        aes_key,
        Object::post_fix(ObjectType::SymmetricKey, aes_key_)
    )
}

#[test]
pub fn test_attributes_with_links() {
    log_init("info");
    let json = include_str!("./attributes_with_links.json");
    let ttlv: TTLV = serde_json::from_str(json).unwrap();
    let _attributes: Attributes = from_ttlv(&ttlv).unwrap();
}

#[test]
pub fn test_import_correct_object() {
    log_init("debug,hyper=info,reqwest=info");
    let json = include_str!("./import.json");
    let ttlv: TTLV = serde_json::from_str(json).unwrap();
    let import: Import = from_ttlv(&ttlv).unwrap();

    assert_eq!(ObjectType::PublicKey, import.object_type);
    assert_eq!(ObjectType::PublicKey, import.object.object_type());
    assert_eq!(
        CryptographicAlgorithm::ABE,
        import.object.key_block().unwrap().cryptographic_algorithm
    );
}

#[test]
pub fn test_create() {
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        link: Some(vec![Link {
            link_type: crate::kmip::kmip_types::LinkType::ParentLink,
            linked_object_identifier: crate::kmip::kmip_types::LinkedObjectIdentifier::TextString(
                "SK".to_string(),
            ),
        }]),
        ..Attributes::new(ObjectType::SymmetricKey)
    };
    let create = Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    };
    let ttlv = to_ttlv(&create).unwrap();
    // println!("{}", serde_json::to_string_pretty(&ttlv).unwrap());
    let create_: Create = from_ttlv(&ttlv).unwrap();
    assert_eq!(ObjectType::SymmetricKey, create_.object_type);
    assert_eq!(
        CryptographicAlgorithm::AES,
        create_.attributes.cryptographic_algorithm.unwrap()
    );
    assert_eq!(
        LinkedObjectIdentifier::TextString("SK".to_string(),),
        create_.attributes.link.as_ref().unwrap()[0].linked_object_identifier
    );
}

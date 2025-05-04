use cosmian_logger::log_init;
use num_bigint_dig::BigInt;
use time::OffsetDateTime;

use crate::{
    kmip_2_1::kmip_objects::Object,
    ttlv::ttlv_struct::{KmipEnumerationVariant, TTLV, TTLValue},
};

#[test]
fn test_enumeration() {
    let es = KmipEnumerationVariant {
        value: 1,
        name: "blah".to_owned(),
    };
    let s = serde_json::to_string_pretty(&es).unwrap();
    assert_eq!(es, serde_json::from_str(&s).unwrap());

    let i_plus = KmipEnumerationVariant {
        value: 1,
        name: String::new(),
    };
    let s = serde_json::to_string_pretty(&i_plus).unwrap();
    assert_eq!(i_plus, serde_json::from_str(&s).unwrap());

    let i_max = KmipEnumerationVariant {
        value: u32::MAX,
        name: String::new(),
    };
    let s = serde_json::to_string_pretty(&i_max).unwrap();
    assert_eq!(i_max, serde_json::from_str(&s).unwrap());
}

#[test]
fn test_serialization_deserialization() {
    log_init(option_env!("RUST_LOG"));
    let now = OffsetDateTime::now_utc();
    let ttlv = TTLV {
        tag: "Test".to_owned(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "AnInt".to_owned(),
                value: TTLValue::Integer(42),
            },
            TTLV {
                tag: "ALongInt".to_owned(),
                value: TTLValue::LongInteger(-42_i64),
            },
            TTLV {
                tag: "ABigInteger".to_owned(),
                value: TTLValue::BigInteger(
                    BigInt::from(2_487_678_887_987_987_798_676_u128).into(),
                ),
            },
            TTLV {
                tag: "AnEnumeration_1".to_owned(),
                value: TTLValue::Enumeration(KmipEnumerationVariant {
                    value: 54,
                    name: String::new(),
                }),
            },
            TTLV {
                tag: "AnEnumeration_2".to_owned(),
                value: TTLValue::Enumeration(KmipEnumerationVariant {
                    value: 1,
                    name: "blah".to_owned(),
                }),
            },
            TTLV {
                tag: "ABoolean".to_owned(),
                value: TTLValue::Boolean(true),
            },
            TTLV {
                tag: "ATextString".to_owned(),
                value: TTLValue::TextString("blah".to_owned()),
            },
            TTLV {
                tag: "AnByteString".to_owned(),
                value: TTLValue::ByteString(b"hello".to_vec()),
            },
            TTLV {
                tag: "ADateTime".to_owned(),
                value: TTLValue::DateTime(now),
            },
            TTLV {
                tag: "AnInterval".to_owned(),
                value: TTLValue::Interval(27),
            },
            TTLV {
                tag: "ADateTimeExtended".to_owned(),
                value: TTLValue::DateTimeExtended(now.unix_timestamp_nanos() / 1000),
            },
        ]),
    };
    let j = serde_json::to_string_pretty(&ttlv).unwrap();
    let rec: TTLV = serde_json::from_str(&j).unwrap();

    match rec.value {
        TTLValue::Structure(s) => {
            assert_eq!(s.len(), 11);
            assert_eq!(s[0].tag, "AnInt");
            match &s[0].value {
                TTLValue::Integer(i) => assert_eq!(*i, 42),
                _ => panic!("Wrong type for AnInt"),
            }
            assert_eq!(s[1].tag, "ALongInt");
            match &s[1].value {
                TTLValue::LongInteger(l) => assert_eq!(*l, -42),
                _ => panic!("Wrong type for ALongInt"),
            }
            assert_eq!(s[2].tag, "ABigInteger");
            match &s[2].value {
                TTLValue::BigInteger(b) => {
                    assert_eq!(*b, BigInt::from(2_487_678_887_987_987_798_676_u128).into());
                }
                _ => panic!("Wrong type for ABigInteger"),
            }
            assert_eq!(s[3].tag, "AnEnumeration_1");
            match &s[3].value {
                TTLValue::Enumeration(en) => {
                    assert_eq!(en.value, 54);
                }
                _ => panic!("Wrong type for AnEnumeration_1"),
            }
            assert_eq!(s[4].tag, "AnEnumeration_2");
            match &s[4].value {
                TTLValue::Enumeration(en) => {
                    assert_eq!(&en.name, "blah");
                }
                _ => panic!("Wrong type for AnEnumeration_2"),
            }
            assert_eq!(s[5].tag, "ABoolean");
            match &s[5].value {
                TTLValue::Boolean(b) => assert!(b),
                _ => panic!("Wrong type for ABoolean"),
            }
            assert_eq!(s[6].tag, "ATextString");
            match &s[6].value {
                TTLValue::TextString(t) => assert_eq!(t, "blah"),
                _ => panic!("Wrong type for ATextString"),
            }
            assert_eq!(s[7].tag, "AnByteString");
            match &s[7].value {
                TTLValue::ByteString(b) => assert_eq!(b, b"hello"),
                _ => panic!("Wrong type for AnByteString"),
            }
            assert_eq!(s[8].tag, "ADateTime");
            match &s[8].value {
                TTLValue::DateTime(d) => assert_eq!(*d, now),
                _ => panic!("Wrong type for ADateTime"),
            }
            assert_eq!(s[9].tag, "AnInterval");
            match &s[9].value {
                TTLValue::Interval(i) => assert_eq!(*i, 27),
                _ => panic!("Wrong type for AnInterval"),
            }
            assert_eq!(s[10].tag, "ADateTimeExtended");
            match &s[10].value {
                TTLValue::DateTimeExtended(d) => {
                    assert_eq!(*d, now.unix_timestamp_nanos() / 1000);
                }
                _ => panic!("Wrong type for ADateTimeExtended"),
            }
        }
        _ => panic!("Expected Structure type at top level"),
    }
}

#[test]
fn test_enumerations_deserialize() {
    log_init(option_env!("RUST_LOG"));
    let json_string = r#"
    {
        "tag": "Test",
        "type": "Structure",
        "value": [
            {
                "tag": "AnEnumeration_1",
                "type": "Enumeration",
                "value": "0x00000036"
            },
            {
                "tag": "AnEnumeration_2",
                "type": "Enumeration",
                "value": "blah"
            },
            {
                "tag": "AnEnumeration_2",
                "type": "Enumeration",
                "value": 12
            }
        ]
    }
    "#;
    let rec: TTLV = serde_json::from_str(json_string).unwrap();
    let json_string = serde_json::to_string_pretty(&rec).unwrap();
    let rec: TTLV = serde_json::from_str(&json_string).unwrap();
    assert_eq!(
        rec.value,
        TTLValue::Structure(vec![
            TTLV {
                tag: "AnEnumeration_1".to_owned(),
                value: TTLValue::Enumeration(KmipEnumerationVariant {
                    value: 54,
                    name: String::new(),
                }),
            },
            TTLV {
                tag: "AnEnumeration_2".to_owned(),
                value: TTLValue::Enumeration(KmipEnumerationVariant {
                    value: 0,
                    name: "blah".to_owned(),
                }),
            },
            TTLV {
                tag: "AnEnumeration_2".to_owned(),
                value: TTLValue::Enumeration(KmipEnumerationVariant {
                    value: 12,
                    name: String::new(),
                }),
            },
        ])
    );
}

#[test]
fn test_arrays() {
    let json_string = r#"
    {
        "tag": "Test",
        "type": "Structure",
        "value": [
            {
                "tag": "AnArray",
                "type": "Structure",
                "value": [
                    {
                        "tag": "AnInt",
                        "type": "Integer",
                        "value": 42
                    },
                    {
                        "tag": "AnInt",
                        "type": "Integer",
                        "value": -42
                    }
                ]
            }
        ]
    }
    "#;
    let rec: TTLV = serde_json::from_str(json_string).unwrap();
    let json_string = serde_json::to_string_pretty(&rec).unwrap();
    let rec: TTLV = serde_json::from_str(&json_string).unwrap();
    assert_eq!(
        rec.value,
        TTLValue::Structure(vec![TTLV {
            tag: "AnArray".to_owned(),
            value: TTLValue::Structure(vec![
                TTLV {
                    tag: "AnInt".to_owned(),
                    value: TTLValue::Integer(42),
                },
                TTLV {
                    tag: "AnInt".to_owned(),
                    value: TTLValue::Integer(-42),
                },
            ]),
        }])
    );
}

#[test]
fn test_mixed_fields_order() {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("trace"));
    let json = r#"
{
  "SymmetricKey": {
    "KeyBlock": {
      "KeyValue": {
        "Attributes": {
          "Attribute": [
            {
              "AttributeName": "tag",
              "AttributeValue": {
                "_c": "[\"_kk\"]",
                "_t": "TextString"
              },
              "VendorIdentification": "cosmian"
            }
          ],
          "ObjectType": "SymmetricKey",
          "KeyFormatType": "TransparentSymmetricKey",
          "UniqueIdentifier": "0a44dd07-2916-4ebd-9c00-ff5394422300",
          "CryptographicLength": 256,
          "CryptographicAlgorithm": "AES",
          "CryptographicUsageMask": 2108
        },
        "KeyMaterial": {
          "Key": [
            179,
            52,
            155,
            4,
            85,
            226,
            254,
            21,
            55,
            38,
            77,
            156,
            144,
            87,
            57,
            174,
            5,
            97,
            106,
            208,
            184,
            60,
            218,
            113,
            248,
            222,
            160,
            115,
            253,
            0,
            249,
            89
          ]
        }
      },
      "KeyFormatType": "TransparentSymmetricKey",
      "CryptographicLength": 256,
      "CryptographicAlgorithm": "AES"
    }
  }
}    
    "#;
    // the key format type must be known to deserialize the key value
    assert!(serde_json::from_str::<Object>(json).is_err());
}

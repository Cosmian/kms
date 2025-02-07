use cosmian_logger::log_init;
use num_bigint_dig::BigUint;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLVEnumeration, TTLValue, TTLV};

#[test]
fn test_enumeration() {
    let es = TTLVEnumeration::Name("blah".to_owned());
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
    let now = OffsetDateTime::now_utc();
    let ttlv = TTLV {
        tag: "Test".to_owned(),
        value: TTLValue::Structure(vec![
            TTLV {
                tag: "AnInt".to_owned(),
                value: TTLValue::Integer(42),
            },
            // TTLV {
            //     tag: "ABitMask".to_owned(),
            //     value: TTLValue::BitMask(42),
            // },
            TTLV {
                tag: "ALongInt".to_owned(),
                value: TTLValue::LongInteger(-42_i64),
            },
            TTLV {
                tag: "ABigInteger".to_owned(),
                value: TTLValue::BigInteger(BigUint::from(2_487_678_887_987_987_798_676_u128)),
            },
            TTLV {
                tag: "AnEnumeration_1".to_owned(),
                value: TTLValue::Enumeration(TTLVEnumeration::Integer(54)),
            },
            TTLV {
                tag: "AnEnumeration_2".to_owned(),
                value: TTLValue::Enumeration(TTLVEnumeration::Name("blah".to_owned())),
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
                value: TTLValue::DateTimeExtended(now),
            },
        ]),
    };
    let j = serde_json::to_string_pretty(&ttlv).unwrap();
    let rec: TTLV = serde_json::from_str(&j).unwrap();

    match rec.value {
        TTLValue::Structure(s) => {
            assert_eq!(s.len(), 12);
            assert_eq!(s[0].tag, "AnInt");
            match &s[0].value {
                TTLValue::Integer(i) => assert_eq!(*i, 42),
                _ => panic!("Wrong type for AnInt"),
            }
            assert_eq!(s[1].tag, "ABitMask");
            // match &s[1].value {
            //     TTLValue::BitMask(b) => assert_eq!(*b, 42),
            //     _ => panic!("Wrong type for ABitMask"),
            // }
            assert_eq!(s[2].tag, "ALongInt");
            match &s[2].value {
                TTLValue::LongInteger(l) => assert_eq!(*l, -42),
                _ => panic!("Wrong type for ALongInt"),
            }
            assert_eq!(s[3].tag, "ABigInteger");
            match &s[3].value {
                TTLValue::BigInteger(b) => {
                    assert_eq!(*b, BigUint::from(2_487_678_887_987_987_798_676_u128));
                }
                _ => panic!("Wrong type for ABigInteger"),
            }
            assert_eq!(s[4].tag, "AnEnumeration_1");
            match &s[4].value {
                TTLValue::Enumeration(TTLVEnumeration::Integer(i)) => assert_eq!(*i, 54),
                _ => panic!("Wrong type for AnEnumeration_1"),
            }
            assert_eq!(s[5].tag, "AnEnumeration_2");
            match &s[5].value {
                TTLValue::Enumeration(TTLVEnumeration::Name(n)) => assert_eq!(n, "blah"),
                _ => panic!("Wrong type for AnEnumeration_2"),
            }
            assert_eq!(s[6].tag, "ABoolean");
            match &s[6].value {
                TTLValue::Boolean(b) => assert!(b),
                _ => panic!("Wrong type for ABoolean"),
            }
            assert_eq!(s[7].tag, "ATextString");
            match &s[7].value {
                TTLValue::TextString(t) => assert_eq!(t, "blah"),
                _ => panic!("Wrong type for ATextString"),
            }
            assert_eq!(s[8].tag, "AnByteString");
            match &s[8].value {
                TTLValue::ByteString(b) => assert_eq!(b, b"hello"),
                _ => panic!("Wrong type for AnByteString"),
            }
            assert_eq!(s[9].tag, "ADateTime");
            match &s[9].value {
                TTLValue::DateTime(d) => assert_eq!(*d, now),
                _ => panic!("Wrong type for ADateTime"),
            }
            assert_eq!(s[10].tag, "AnInterval");
            match &s[10].value {
                TTLValue::Interval(i) => assert_eq!(*i, 27),
                _ => panic!("Wrong type for AnInterval"),
            }
            assert_eq!(s[11].tag, "ADateTimeExtended");
            match &s[11].value {
                TTLValue::DateTimeExtended(d) => assert_eq!(*d, now),
                _ => panic!("Wrong type for ADateTimeExtended"),
            }
        }
        _ => panic!("Expected Structure type at top level"),
    }
}

#[test]
fn test_ser_int() {
    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        an_int: u32,
    }
    log_init(Some("info,hyper=info,reqwest=info"));

    let test = Test {
        an_int: 1,
        // seq: vec!["a", "b"],
    };
    let ttlv = to_ttlv(&test).unwrap();
    let expected =
        r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "AnInt", value: Integer(1) }]) }"#;
    let ttlv_s = format!("{ttlv:?}");
    assert_eq!(ttlv_s, expected);
}

#[test]
fn test_ser_array() {
    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        seq: Vec<&'static str>,
    }
    log_init(Some("info,hyper=info,reqwest=info"));

    let test = Test {
        seq: vec!["a", "b"],
    };
    let ttlv = to_ttlv(&test).unwrap();
    let expected = r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "Seq", value: Structure([TTLV { tag: "Seq", value: TextString("a") }, TTLV { tag: "Seq", value: TextString("b") }]) }]) }"#;
    let ttlv_s = format!("{ttlv:?}");
    assert_eq!(ttlv_s, expected);
}

#[test]
fn test_ser_big_int() {
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        big_int: BigUint,
    }
    log_init(Some("info,hyper=info,reqwest=info"));

    let test = Test {
        big_int: BigUint::from(0x1111_1111_1222_2222_u128),
    };
    let ttlv = to_ttlv(&test).unwrap();
    let value = serde_json::to_value(&ttlv).unwrap();
    assert!(value.is_object());
    assert_eq!(value["tag"], "Test");
    assert_eq!(value["value"][0]["tag"], "BigInt");
    assert_eq!(value["value"][0]["type"], "BigInteger");
    assert_eq!(value["value"][0]["value"], "0x1111111112222222");
    let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
    let rec: Test = from_ttlv(&re_ttlv).unwrap();
    assert_eq!(test.big_int, rec.big_int);
}

use cosmian_logger::log_init;
use kmip_derive::KmipEnumSerialize;
use num_bigint_dig::{BigInt, BigUint};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::ttlv::{
    kmip_ttlv_deserializer::from_ttlv, kmip_ttlv_serializer::to_ttlv, ttlv_struct::TTLV,
    KmipEnumerationVariant, TTLValue,
};

#[test]
fn test_ser_int() {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        uint8: u8,
        int8: i8,
        uint16: u16,
        int16: i16,
        uint32: u32,
        int32: i32,
        uint64: u64,
        int64: i64,
    }
    log_init(Some("info,hyper=info,reqwest=info"));

    let test = Test {
        uint32: 1,
        uint8: 2,
        int8: 3,
        uint16: 4,
        int16: 5,
        int32: 6,
        uint64: 7,
        int64: 8,
    };

    //Serializer
    let ttlv = to_ttlv(&test).unwrap();
    let expected = r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "Uint8", value: Integer(2) }, TTLV { tag: "Int8", value: Integer(3) }, TTLV { tag: "Uint16", value: Integer(4) }, TTLV { tag: "Int16", value: Integer(5) }, TTLV { tag: "Uint32", value: Integer(1) }, TTLV { tag: "Int32", value: Integer(6) }, TTLV { tag: "Uint64", value: LongInteger(7) }, TTLV { tag: "Int64", value: LongInteger(8) }]) }"#;
    let ttlv_s = format!("{ttlv:?}");
    assert_eq!(ttlv_s, expected);

    //Serialize
    let json = serde_json::to_string_pretty(&ttlv).unwrap();
    //Deserialize
    let re_ttlv = serde_json::from_str::<TTLV>(&json).unwrap();
    assert_eq!(ttlv, re_ttlv);

    //Deserializer
    info!("*** Running Deserializer: {:?}", re_ttlv);
    let rec: Test = from_ttlv(re_ttlv).unwrap();
    assert_eq!(test, rec);
}

#[test]
fn test_ser_big_int() {
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    #[derive(PartialEq, Eq, Debug)]
    struct Test {
        big_int_neg: BigInt,
        big_int_pos: BigInt,
    }
    log_init(Some("info,hyper=info,reqwest=info"));

    let tests = [
        (
            Test {
                big_int_neg: BigInt::from(-1_234_567_890_i128),
                big_int_pos: BigInt::from(0x0000_1111_1222_2222_u128),
            },
            ["0xFFFFFFFFB669FD2E", "0x0000111112222222"],
        ),
        (
            Test {
                big_int_neg: BigInt::from(-1_234_567_i64),
                big_int_pos: BigInt::from(1_234_567_i64),
            },
            ["0xFFFFFFFFFFED2979", "0x000000000012D687"],
        ),
    ];
    for (test, [s1, s2]) in tests {
        // serializer
        let ttlv = to_ttlv(&test).unwrap();

        // serialize
        let value = serde_json::to_value(&ttlv).unwrap();
        assert!(value.is_object());
        assert_eq!(value["tag"], "Test");
        assert_eq!(value["value"][0]["tag"], "BigIntNeg");
        assert_eq!(value["value"][0]["type"], "BigInteger");
        assert_eq!(value["value"][0]["value"], s1);
        assert_eq!(value["value"][1]["tag"], "BigIntPos");
        assert_eq!(value["value"][1]["type"], "BigInteger");
        assert_eq!(value["value"][1]["value"], s2);

        // deserialize
        let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
        assert_eq!(ttlv, re_ttlv);

        // Deserializer
        info!("*** Running Deserializer: {:?}", re_ttlv);
        let rec: Test = from_ttlv(re_ttlv).unwrap();
        assert_eq!(test, rec);
    }
}

#[test]
fn test_ser_big_uint() {
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        big_uint: BigUint,
    }
    log_init(Some("info,hyper=info,reqwest=info"));

    let tests = [
        (
            Test {
                big_uint: BigUint::from(1_234_567_890_u128),
            },
            "0x00000000499602D2",
        ),
        (
            Test {
                big_uint: BigUint::from(0x0000_1111_1222_2222_u128),
            },
            "0x0000111112222222",
        ),
    ];
    for (test, s) in tests {
        // Serializer
        let ttlv = to_ttlv(&test).unwrap();

        // Serialize
        let value = serde_json::to_value(&ttlv).unwrap();
        assert!(value.is_object());
        assert_eq!(value["tag"], "Test");
        assert_eq!(value["value"][0]["tag"], "BigUint");
        assert_eq!(value["value"][0]["type"], "BigInteger");
        assert_eq!(value["value"][0]["value"], s);

        // Deserialize
        let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
        assert_eq!(ttlv, re_ttlv);

        // Deserializer
        let rec: Test = from_ttlv(re_ttlv).unwrap();
        assert_eq!(test.big_uint, rec.big_uint);
    }
}

#[test]
fn test_ser_array() {
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Element {
        elem: i32,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        string_seq: Vec<String>,
        struct_seq: Vec<Element>,
    }
    log_init(Some("info,hyper=info,reqwest=info"));

    let test = Test {
        string_seq: vec!["a".to_owned(), "b".to_owned()],
        struct_seq: vec![Element { elem: 1 }, Element { elem: 2 }],
    };

    // Serializer
    let ttlv = to_ttlv(&test).unwrap();
    let expected = r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "StringSeq", value: Structure([TTLV { tag: "StringSeq", value: TextString("a") }, TTLV { tag: "StringSeq", value: TextString("b") }]) }, TTLV { tag: "StructSeq", value: Structure([TTLV { tag: "StructSeq", value: Structure([TTLV { tag: "Elem", value: Integer(1) }]) }, TTLV { tag: "StructSeq", value: Structure([TTLV { tag: "Elem", value: Integer(2) }]) }]) }]) }"#;
    let ttlv_s = format!("{ttlv:?}");
    assert_eq!(ttlv_s, expected);

    //Serialize
    let json = serde_json::to_string_pretty(&ttlv).unwrap();
    //Deserialize
    let re_ttlv = serde_json::from_str::<TTLV>(&json).unwrap();
    assert_eq!(ttlv, re_ttlv);

    //Deserializer
    let rec: Test = from_ttlv(re_ttlv).unwrap();
    assert_eq!(test.string_seq, rec.string_seq);
}

#[test]
fn test_enum_unit_variant() {
    #[derive(
        Deserialize, PartialEq, Eq, Debug, KmipEnumSerialize, Copy, Clone, strum::IntoStaticStr,
    )]
    #[repr(u32)]
    enum Enumeration {
        Ten = 0x0A,
        Big = 0x1111_2222,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        an_enum: Enumeration,
    }
    log_init(Some("info,hyper=info,reqwest=info"));

    // Try with Ten
    let test = Test {
        an_enum: Enumeration::Ten,
    };
    // Serializer
    let ttlv = to_ttlv(&test).unwrap();

    // Serialize
    let value = serde_json::to_value(&ttlv).unwrap();
    info!("VALUE: {}", serde_json::to_string_pretty(&value).unwrap());
    assert!(value.is_object());
    assert_eq!(value["tag"], "Test");
    assert_eq!(value["value"][0]["tag"], "AnEnum");
    assert_eq!(value["value"][0]["type"], "Enumeration");
    assert_eq!(value["value"][0]["value"], "Ten");

    // Deserialize
    let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
    assert_eq!(ttlv, re_ttlv);

    // Deserializer
    let rec: Test = from_ttlv(re_ttlv).unwrap();
    assert_eq!(test.an_enum, rec.an_enum);

    // Try with direct deserialization
    let ttlv = TTLV {
        tag: "Test".to_owned(),
        value: TTLValue::Structure(vec![TTLV {
            tag: "AnEnum".to_owned(),
            value: TTLValue::Enumeration(KmipEnumerationVariant {
                value: 0x0A,
                name: "Ten".to_owned(),
            }),
        }]),
    };
    let rec: Test = from_ttlv(ttlv).unwrap();
    assert_eq!(test.an_enum, rec.an_enum);
}

#[test]
fn test_enumeration_untagged() {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    #[serde(untagged)]
    enum Enumeration {
        OneInt(u32),
        TwoString(String),
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        an_enum: Enumeration,
    }
    log_init(Some("info,hyper=info,reqwest=info"));

    let test = Test {
        an_enum: Enumeration::OneInt(42),
    };
    // Serializer
    let ttlv = to_ttlv(&test).unwrap();

    // Serialize
    let value = serde_json::to_value(&ttlv).unwrap();
    info!("VALUE: {}", serde_json::to_string_pretty(&value).unwrap());
    assert!(value.is_object());
    assert_eq!(value["tag"], "Test");
    assert_eq!(value["value"][0]["tag"], "AnEnum");
    assert_eq!(value["value"][0]["type"], "Integer");
    assert_eq!(value["value"][0]["value"], 42);

    // Deserialize
    let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
    assert_eq!(ttlv, re_ttlv);

    // Deserializer
    let rec: Test = from_ttlv(re_ttlv).unwrap();
    assert_eq!(test.an_enum, rec.an_enum);

    // The same test with a string
    let test = Test {
        an_enum: Enumeration::TwoString("blah".to_owned()),
    };

    // Serializer
    let ttlv = to_ttlv(&test).unwrap();

    // Serialize
    let value = serde_json::to_value(&ttlv).unwrap();
    info!("VALUE: {}", serde_json::to_string_pretty(&value).unwrap());
    assert!(value.is_object());
    assert_eq!(value["tag"], "Test");
    assert_eq!(value["value"][0]["tag"], "AnEnum");
    assert_eq!(value["value"][0]["type"], "TextString");
    assert_eq!(value["value"][0]["value"], "blah");

    // Deserialize
    let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
    assert_eq!(ttlv, re_ttlv);

    // Deserializer
    let rec: Test = from_ttlv(re_ttlv).unwrap();
    assert_eq!(test.an_enum, rec.an_enum);
}

#[test]
fn test_enumeration_untagged_variant_struct() {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Int {
        int_value: u32,
    }

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct TwoStrings {
        string_a: String,
        string_b: String,
    }
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    #[serde(untagged)]
    enum Enumeration {
        OneInt(Int),
        TwoInt(Int),
        TwoStrings(TwoStrings),
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        an_enum: Enumeration,
    }
    log_init(Some("info"));

    let test = Test {
        an_enum: Enumeration::OneInt(Int { int_value: 42 }),
    };
    // Serializer
    let ttlv = to_ttlv(&test).unwrap();
    assert_eq!(
        format!("{ttlv:?}"),
        r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "AnEnum", value: Structure([TTLV { tag: "IntValue", value: Integer(42) }]) }]) }"#
    );

    // Serialize
    let value = serde_json::to_value(&ttlv).unwrap();
    // Deserialize
    let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
    assert_eq!(ttlv, re_ttlv);

    // Deserializer
    let rec: Test = from_ttlv(re_ttlv).unwrap();
    assert_eq!(test, rec);

    // The same test with a string
    let test = Test {
        an_enum: Enumeration::TwoStrings(TwoStrings {
            string_a: "blah_a".to_owned(),
            string_b: "blah_b".to_owned(),
        }),
    };

    // Serializer
    let ttlv = to_ttlv(&test).unwrap();
    assert_eq!(
        format!("{ttlv:?}"),
        r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "AnEnum", value: Structure([TTLV { tag: "string_a", value: TextString("blah_a") }, TTLV { tag: "string_b", value: TextString("blah_b") }]) }]) }"#
    );

    // Serialize
    let value = serde_json::to_value(&ttlv).unwrap();
    // Deserialize
    let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
    assert_eq!(ttlv, re_ttlv);

    // Deserializer
    let rec: Test = from_ttlv(re_ttlv).unwrap();
    assert_eq!(test, rec);

    //This should fail because on untagged enum, the deserializer finds the first variant that
    // can hold the structure and uses it.
    let test = Test {
        an_enum: Enumeration::TwoInt(Int { int_value: 42 }),
    };
    // Serializer
    let ttlv = to_ttlv(&test).unwrap();
    assert_eq!(
        format!("{ttlv:?}"),
        r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "AnEnum", value: Structure([TTLV { tag: "IntValue", value: Integer(42) }]) }]) }"#
    );

    // Serialize
    let value = serde_json::to_value(&ttlv).unwrap();
    // Deserialize
    let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
    assert_eq!(ttlv, re_ttlv);

    // Deserializer
    let rec: Test = from_ttlv(re_ttlv).unwrap();
    // rec should have deserialized as OneInt instead of TwoInt
    assert_ne!(test, rec);
}

#[test]
fn test_nested_structures() {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    #[serde(untagged)]
    enum Enumeration {
        OneInt(u32),
        TwoString(String),
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    #[serde(rename_all = "PascalCase")]
    struct Child {
        enumeration: Enumeration,
        an_int: u32,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    #[serde(rename_all = "PascalCase")]
    struct Root {
        the_child: Child,
    }
    log_init(Some("info,hyper=info,reqwest=info"));

    let child = Child {
        enumeration: Enumeration::OneInt(42),
        an_int: 1,
    };
    let root = Root { the_child: child };
    let ttlv = to_ttlv(&root).unwrap();
    let value = serde_json::to_value(&ttlv).unwrap();
    info!("VALUE: {}", serde_json::to_string_pretty(&value).unwrap());
    assert!(value.is_object());
    assert_eq!(value["tag"], "Root");
    assert_eq!(value["value"][0]["tag"], "TheChild");
    assert_eq!(value["value"][0]["value"][0]["tag"], "Enumeration");
    assert_eq!(value["value"][0]["value"][0]["type"], "Integer");
    assert_eq!(value["value"][0]["value"][0]["value"], 42);
    assert_eq!(value["value"][0]["value"][1]["tag"], "AnInt");
    assert_eq!(value["value"][0]["value"][1]["type"], "Integer");
    assert_eq!(value["value"][0]["value"][1]["value"], 1);
    // Deserialize
    let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
    assert_eq!(ttlv, re_ttlv);
    // Deserializer
    let rec: Root = from_ttlv(re_ttlv).unwrap();
    assert_eq!(root, rec);
}

#[derive(
    Deserialize, PartialEq, Eq, Debug, KmipEnumSerialize, Copy, Clone, strum::IntoStaticStr,
)]
#[repr(u32)]
enum MyEnum {
    Ten = 0x0A,
    Big = 0x1111_2222,
}

#[test]
fn test_enum_unit_variant_with_value() {
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        an_enum: MyEnum,
    }
    log_init(Some("info,hyper=info,reqwest=info"));

    // Try with Ten
    let test = Test {
        an_enum: MyEnum::Ten,
    };
    // Serializer
    let ttlv = to_ttlv(&test).unwrap();
    assert_eq!(
        format!("{ttlv:?}"),
        r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "AnEnum", value: Enumeration(KmipEnumerationVariant { value: 10, name: "Ten" }) }]) }"#
    );

    // Try with Big
    let test = Test {
        an_enum: MyEnum::Big,
    };
    // Serializer
    let ttlv = to_ttlv(&test).unwrap();
    assert_eq!(
        format!("{ttlv:?}"),
        r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "AnEnum", value: Enumeration(KmipEnumerationVariant { value: 286335522, name: "Big" }) }]) }"#
    );
}

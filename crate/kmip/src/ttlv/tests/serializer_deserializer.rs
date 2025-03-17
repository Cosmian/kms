use cosmian_logger::log_init;
use kmip_derive::KmipEnumSerialize;
use num_bigint_dig::{BigInt, BigUint};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, UtcOffset};
use tracing::info;

use crate::ttlv::{
    kmip_ttlv_deserializer::from_ttlv, kmip_ttlv_serializer::to_ttlv, ttlv_struct::TTLV,
    KmipEnumerationVariant, TTLValue,
};

#[test]
fn test_ser_int() {
    // According to the KMIP spec, only i32 is supported for Integer
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        uint8: u8,
        int8: i8,
        uint16: u16,
        int16: i16,
        // u32 is reserved for Interval
        // uint32: u32,
        int32: i32,
        uint64: u64,
        int64: i64,
    }
    log_init(option_env!("RUST_LOG"));

    let test = Test {
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
    let expected = r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "Uint8", value: Integer(2) }, TTLV { tag: "Int8", value: Integer(3) }, TTLV { tag: "Uint16", value: Integer(4) }, TTLV { tag: "Int16", value: Integer(5) }, TTLV { tag: "Int32", value: Integer(6) }, TTLV { tag: "Uint64", value: LongInteger(7) }, TTLV { tag: "Int64", value: LongInteger(8) }]) }"#;
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
    log_init(option_env!("RUST_LOG"));

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
        let rec: Test = from_ttlv(re_ttlv).unwrap();
        assert_eq!(test, rec);
    }
}

#[test]
fn test_ser_big_uint() {
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        the_big_uint: BigUint,
    }
    log_init(option_env!("RUST_LOG"));

    let tests = [
        (
            Test {
                the_big_uint: BigUint::from(1_234_567_890_u128),
            },
            "0x00000000499602D2",
        ),
        (
            Test {
                the_big_uint: BigUint::from(0x0000_1111_1222_2222_u128),
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
        assert_eq!(value["value"][0]["tag"], "TheBigUint");
        assert_eq!(value["value"][0]["type"], "BigInteger");
        assert_eq!(value["value"][0]["value"], s);

        // Deserialize
        let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
        assert_eq!(ttlv, re_ttlv);

        // Deserializer
        let rec: Test = from_ttlv(re_ttlv).unwrap();
        assert_eq!(test.the_big_uint, rec.the_big_uint);
    }
}

#[test]
// Note::serializing direct arrays is not supported in the spec
fn test_direct_array() {
    #[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
    #[serde(rename_all = "PascalCase")]
    struct Element {
        elem: i32,
    }
    log_init(option_env!("RUST_LOG"));

    let array = vec![Element { elem: 1 }, Element { elem: 2 }];

    // Serializer
    let ttlv = to_ttlv(&array).unwrap();

    //Serialize
    let json = serde_json::to_string_pretty(&ttlv).unwrap();

    //Deserialize
    let re_ttlv = serde_json::from_str::<TTLV>(&json).unwrap();
    assert_eq!(ttlv, re_ttlv);

    //Deserializer
    let rec: Vec<Element> = from_ttlv(re_ttlv).unwrap();
    assert_eq!(array, rec);
}

#[test]
fn test_ser_array() {
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    #[serde(rename_all = "PascalCase")]
    struct Element {
        elem: i32,
    }
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        string_seq: Vec<String>,
        struct_seq: Vec<Element>,
    }
    log_init(option_env!("RUST_LOG"));

    let test = Test {
        string_seq: vec!["a".to_owned(), "b".to_owned()],
        struct_seq: vec![Element { elem: 1 }, Element { elem: 2 }],
    };

    // Serializer
    let ttlv = to_ttlv(&test).unwrap();

    //Serialize
    let json = serde_json::to_string_pretty(&ttlv).unwrap();

    //Deserialize
    let re_ttlv = serde_json::from_str::<TTLV>(&json).unwrap();
    assert_eq!(json, serde_json::to_string_pretty(&re_ttlv).unwrap());
    assert_eq!(ttlv, re_ttlv);

    //Deserializer
    let rec: Test = from_ttlv(re_ttlv).unwrap();
    assert_eq!(test, rec);
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
    log_init(option_env!("RUST_LOG"));

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

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        an_enum: Enumeration,
    }
    log_init(option_env!("RUST_LOG"));

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
        int_value: i32,
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
    log_init(option_env!("RUST_LOG"));

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
        OneInt(i32),
        TwoString(String),
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    #[serde(rename_all = "PascalCase")]
    struct Child {
        enumeration: Enumeration,
        an_int: i32,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    #[serde(rename_all = "PascalCase")]
    struct Root {
        the_child: Child,
    }
    log_init(option_env!("RUST_LOG"));

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
    log_init(option_env!("RUST_LOG"));

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

#[test]
fn test_byte_string() {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        byte_string: Vec<u8>,
    }
    log_init(option_env!("RUST_LOG"));

    let test = Test {
        byte_string: vec![0x01, 0x02, 0x03, 0xef],
    };
    // Serializer
    let ttlv = to_ttlv(&test).unwrap();
    assert_eq!(
        format!("{ttlv:?}"),
        r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "ByteString", value: ByteString([1, 2, 3, 239]) }]) }"#
    );

    // Serialize
    let value = serde_json::to_value(&ttlv).unwrap();
    info!("VALUE: {}", serde_json::to_string_pretty(&value).unwrap());
    assert!(value.is_object());
    assert_eq!(value["tag"], "Test");
    assert_eq!(value["value"][0]["tag"], "ByteString");
    assert_eq!(value["value"][0]["type"], "ByteString");
    assert_eq!(value["value"][0]["value"], "010203EF");

    // Deserialize
    let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
    assert_eq!(ttlv, re_ttlv);

    // Deserializer
    let rec: Test = from_ttlv(re_ttlv).unwrap();
    assert_eq!(test, rec);
}

#[test]
fn test_long_integer() {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        long_integer: i64,
    }
    log_init(option_env!("RUST_LOG"));

    let test = Test {
        long_integer: 0x1234_5678_9ABC_DEF0,
    };
    // Serializer
    let ttlv = to_ttlv(&test).unwrap();
    assert_eq!(
        format!("{ttlv:?}"),
        r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "LongInteger", value: LongInteger(1311768467463790320) }]) }"#
    );

    // Serialize
    let value = serde_json::to_value(&ttlv).unwrap();
    info!("VALUE: {}", serde_json::to_string_pretty(&value).unwrap());
    assert!(value.is_object());
    assert_eq!(value["tag"], "Test");
    assert_eq!(value["value"][0]["tag"], "LongInteger");
    assert_eq!(value["value"][0]["type"], "LongInteger");
    assert_eq!(value["value"][0]["value"], "0x123456789ABCDEF0");

    // Deserialize
    let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
    assert_eq!(ttlv, re_ttlv);

    // Deserializer
    let rec: Test = from_ttlv(re_ttlv).unwrap();
    assert_eq!(test, rec);
}

#[test]
fn test_date_time() {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        date_time: OffsetDateTime,
    }
    log_init(option_env!("RUST_LOG"));

    let test = Test {
        date_time: OffsetDateTime::new_utc(
            time::Date::from_calendar_date(2021, time::Month::October, 1).unwrap(),
            time::Time::from_hms(12, 34, 56).unwrap(),
        )
        .to_offset(UtcOffset::from_hms(-1, -2, 3).unwrap()),
    };
    // Serializer
    let ttlv = to_ttlv(&test).unwrap();
    assert_eq!(
        format!("{ttlv:?}"),
        r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "DateTime", value: DateTime(2021-10-01 11:32:53.0 -01:02:03) }]) }"#
    );

    // Serialize
    let value = serde_json::to_value(&ttlv).unwrap();
    info!("VALUE: {}", serde_json::to_string_pretty(&value).unwrap());
    assert!(value.is_object());
    assert_eq!(value["tag"], "Test");
    assert_eq!(value["value"][0]["tag"], "DateTime");
    assert_eq!(value["value"][0]["type"], "DateTime");
    assert_eq!(value["value"][0]["value"], "2021-10-01T12:34:56Z");

    // Deserialize
    let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
    assert_eq!(ttlv, re_ttlv);

    // Deserializer
    let rec: Test = from_ttlv(re_ttlv).unwrap();
    assert_eq!(test, rec);
}

#[test]
fn test_date_time_extended() {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        date_time: i128,
    }
    log_init(option_env!("RUST_LOG"));

    let micros = OffsetDateTime::new_utc(
        time::Date::from_calendar_date(2021, time::Month::October, 1).unwrap(),
        time::Time::from_hms(12, 34, 56).unwrap(),
    )
    .to_offset(UtcOffset::from_hms(-1, -2, 3).unwrap())
    .unix_timestamp_nanos()
        / 1000;
    let test = Test { date_time: micros };
    // Serializer
    let ttlv = to_ttlv(&test).unwrap();
    assert_eq!(
        format!("{ttlv:?}"),
        r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "DateTime", value: DateTimeExtended(1633091696000000) }]) }"#
    );

    // Serialize
    let value = serde_json::to_value(&ttlv).unwrap();
    info!("VALUE: {}", serde_json::to_string_pretty(&value).unwrap());
    assert!(value.is_object());
    assert_eq!(value["tag"], "Test");
    assert_eq!(value["value"][0]["tag"], "DateTime");
    assert_eq!(value["value"][0]["type"], "DateTimeExtended");
    assert_eq!(value["value"][0]["value"], "0x0005CD49CA6CFC00");

    // Deserialize
    let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
    assert_eq!(ttlv, re_ttlv);

    // Deserializer
    let rec: Test = from_ttlv(re_ttlv).unwrap();
    assert_eq!(test, rec);
}

#[test]
fn test_interval() {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        interval: u32,
    }
    log_init(option_env!("RUST_LOG"));

    let test = Test { interval: 42 };
    // Serializer
    let ttlv = to_ttlv(&test).unwrap();
    assert_eq!(
        format!("{ttlv:?}"),
        r#"TTLV { tag: "Test", value: Structure([TTLV { tag: "Interval", value: Interval(42) }]) }"#
    );

    // Serialize
    let value = serde_json::to_value(&ttlv).unwrap();
    info!("VALUE: {}", serde_json::to_string_pretty(&value).unwrap());
    assert!(value.is_object());
    assert_eq!(value["tag"], "Test");
    assert_eq!(value["value"][0]["tag"], "Interval");
    assert_eq!(value["value"][0]["type"], "Interval");
    assert_eq!(value["value"][0]["value"], 42);

    // Deserialize
    let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
    assert_eq!(ttlv, re_ttlv);

    // Deserializer
    let rec: Test = from_ttlv(re_ttlv).unwrap();
    assert_eq!(test, rec);
}

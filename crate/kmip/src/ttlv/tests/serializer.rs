use cosmian_logger::log_init;
use num_bigint_dig::BigInt;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::ttlv::{deserializer::from_ttlv, serializer::to_ttlv, ttlv_struct::TTLV};

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
        big_int: BigInt,
    }
    log_init(Some("trace,hyper=info,reqwest=info"));

    let tests = [
        (
            Test {
                big_int: BigInt::from(-1_234_567_890_i128),
            },
            "0xFFFFFFFFB669FD2E",
        ),
        (
            Test {
                big_int: BigInt::from(0x0000_1111_1222_2222_u128),
            },
            "0x0000111112222222",
        ),
    ];
    for (test, s) in tests {
        let ttlv = to_ttlv(&test).unwrap();
        let value = serde_json::to_value(&ttlv).unwrap();
        info!("VALUE: {}", serde_json::to_string_pretty(&value).unwrap());
        assert!(value.is_object());
        assert_eq!(value["tag"], "Test");
        assert_eq!(value["value"][0]["tag"], "BigInt");
        assert_eq!(value["value"][0]["type"], "BigInteger");
        assert_eq!(value["value"][0]["value"], s);
        let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
        assert_eq!(ttlv, re_ttlv);

        // Deserializer
        let rec: Test = from_ttlv(&re_ttlv).unwrap();
        assert_eq!(test.big_int, rec.big_int);
    }
}

#[test]
fn test_enumeration() {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    enum Enumeration {
        OneInt(u32),
        TwoString(String),
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Test {
        enumeration: Enumeration,
    }
    log_init(Some("trace,hyper=info,reqwest=info"));

    let test = Test {
        enumeration: Enumeration::OneInt(42),
    };
    let ttlv = to_ttlv(&test).unwrap();
    let value = serde_json::to_value(&ttlv).unwrap();
    info!("VALUE: {}", serde_json::to_string_pretty(&value).unwrap());
    assert!(value.is_object());
    assert_eq!(value["tag"], "Test");
    assert_eq!(value["value"][0]["tag"], "Enumeration");
    assert_eq!(value["value"][0]["type"], "Integer");
    assert_eq!(value["value"][0]["value"], 42);
    // Deserialize
    let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
    assert_eq!(ttlv, re_ttlv);
    // Deserializer
    let rec: Test = from_ttlv(&re_ttlv).unwrap();
    assert_eq!(test.enumeration, rec.enumeration);

    let test = Test {
        enumeration: Enumeration::TwoString("blah".to_owned()),
    };
    let ttlv = to_ttlv(&test).unwrap();
    let value = serde_json::to_value(&ttlv).unwrap();
    info!("VALUE: {}", serde_json::to_string_pretty(&value).unwrap());
    assert!(value.is_object());
    assert_eq!(value["tag"], "Test");
    assert_eq!(value["value"][0]["tag"], "Enumeration");
    assert_eq!(value["value"][0]["type"], "TextString");
    assert_eq!(value["value"][0]["value"], "blah");
    // Deserialize
    let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
    assert_eq!(ttlv, re_ttlv);
    // Deserializer
    let rec: Test = from_ttlv(&re_ttlv).unwrap();
    assert_eq!(test.enumeration, rec.enumeration);
}

#[test]
fn test_nested_structures() {
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
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
    log_init(Some("trace,hyper=info,reqwest=info"));

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
    let rec: Root = from_ttlv(&re_ttlv).unwrap();
    assert_eq!(root, rec);
}

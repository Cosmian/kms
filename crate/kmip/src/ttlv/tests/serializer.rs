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
            "0x0000_1111_1222_2222_u128",
        ),
    ];
    for (test, s) in tests {
        let ttlv = to_ttlv(&test).unwrap();
        let value = serde_json::to_value(&ttlv).unwrap();
        info!("VALUE: {}", serde_json::to_string_pretty(&value).unwrap());
        assert!(value.is_object());
        assert_eq!(value["tag"], "Test");
        // assert_eq!(value["value"][0]["tag"], "BigInt");
        assert_eq!(value["value"][0]["type"], "BigInteger");
        assert_eq!(value["value"][0]["value"], s);
        let re_ttlv = serde_json::from_value::<TTLV>(value).unwrap();
        let rec: Test = from_ttlv(&re_ttlv).unwrap();
        assert_eq!(test.big_int, rec.big_int);
    }
}

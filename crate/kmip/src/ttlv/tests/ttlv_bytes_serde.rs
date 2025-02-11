use std::io::Cursor;

use num_bigint_dig::BigInt;
use strum::Display;
use time::OffsetDateTime;

use crate::ttlv::{
    ttlv_bytes_deserializer::TTLVBytesDeserializer,
    ttlv_bytes_serializer::{KmipTag, TTLVBytesSerializer},
    TTLValue, TTLV,
};

#[test]
fn test_serialization_deserialization() {
    // Helper enum implementing KmipTag
    #[derive(Debug, Clone, Display)]
    enum TestTag {
        Test1,
        Test2,
    }

    impl KmipTag for TestTag {}

    impl TryFrom<u32> for TestTag {
        type Error = ();

        fn try_from(v: u32) -> Result<Self, Self::Error> {
            match v {
                1 => Ok(Self::Test1),
                2 => Ok(Self::Test2),
                _ => Err(()),
            }
        }
    }

    impl From<TestTag> for u32 {
        fn from(tag: TestTag) -> Self {
            match tag {
                TestTag::Test1 => 1,
                TestTag::Test2 => 2,
            }
        }
    }

    impl TryFrom<String> for TestTag {
        type Error = ();

        fn try_from(s: String) -> Result<Self, Self::Error> {
            match s.as_str() {
                "Test1" => Ok(Self::Test1),
                "Test2" => Ok(Self::Test2),
                _ => Err(()),
            }
        }
    }

    let test_cases = vec![
        // Test integer
        TTLV {
            tag: "Test1".to_owned(),
            value: TTLValue::Integer(42),
        },
        // Test long integer
        TTLV {
            tag: "Test2".to_owned(),
            value: TTLValue::LongInteger(9_223_372_036_854_775_807),
        },
        // Test big integer
        TTLV {
            tag: "Test1".to_owned(),
            value: TTLValue::BigInteger(BigInt::from(123_456_789_u64).into()),
        },
        // Test boolean
        TTLV {
            tag: "Test2".to_owned(),
            value: TTLValue::Boolean(true),
        },
        // Test text string
        TTLV {
            tag: "Test1".to_owned(),
            value: TTLValue::TextString("Hello KMIP".to_owned()),
        },
        // Test byte string
        TTLV {
            tag: "Test2".to_owned(),
            value: TTLValue::ByteString(vec![1, 2, 3, 4, 5]),
        },
        // Test datetime
        TTLV {
            tag: "Test1".to_owned(),
            value: TTLValue::DateTime(OffsetDateTime::from_unix_timestamp(1_234_567_890).unwrap()),
        },
        // Test interval
        TTLV {
            tag: "Test2".to_owned(),
            value: TTLValue::Interval(86400),
        },
        // Test nested structure
        TTLV {
            tag: "Test1".to_owned(),
            value: TTLValue::Structure(vec![
                TTLV {
                    tag: "Test2".to_owned(),
                    value: TTLValue::Integer(123),
                },
                TTLV {
                    tag: "Test1".to_owned(),
                    value: TTLValue::TextString("Nested".to_owned()),
                },
            ]),
        },
    ];

    for test_case in test_cases {
        let mut buffer = Vec::new();
        let mut serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer.write_ttlv::<TestTag>(&test_case).unwrap();

        let mut deserializer = TTLVBytesDeserializer::new(Cursor::new(&buffer));
        let result = deserializer.read_ttlv::<TestTag>().unwrap();

        assert_eq!(test_case.tag, result.tag);
        match (&test_case.value, &result.value) {
            (TTLValue::Integer(a), TTLValue::Integer(b)) => assert_eq!(a, b),
            (TTLValue::LongInteger(a), TTLValue::LongInteger(b)) => assert_eq!(a, b),
            (TTLValue::BigInteger(a), TTLValue::BigInteger(b)) => assert_eq!(a, b),
            (TTLValue::Boolean(a), TTLValue::Boolean(b)) => assert_eq!(a, b),
            (TTLValue::TextString(a), TTLValue::TextString(b)) => assert_eq!(a, b),
            (TTLValue::ByteString(a), TTLValue::ByteString(b)) => assert_eq!(a, b),
            (TTLValue::DateTime(a), TTLValue::DateTime(b)) => assert_eq!(a, b),
            (TTLValue::Interval(a), TTLValue::Interval(b)) => assert_eq!(a, b),
            (TTLValue::Structure(a), TTLValue::Structure(b)) => {
                assert_eq!(a.len(), b.len());
                for (a, b) in a.iter().zip(b.iter()) {
                    assert_eq!(a.tag, b.tag);
                    match (&a.value, &b.value) {
                        (TTLValue::Integer(a), TTLValue::Integer(b)) => assert_eq!(a, b),
                        (TTLValue::TextString(a), TTLValue::TextString(b)) => assert_eq!(a, b),
                        _ => panic!("Type mismatch"),
                    }
                }
            }
            _ => panic!("Type mismatch"),
        }
    }
}

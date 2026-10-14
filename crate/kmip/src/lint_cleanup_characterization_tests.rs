use num_bigint_dig::BigInt;
use time::{OffsetDateTime, macros::datetime};

use crate::ttlv::{KmipBigInt, KmipEnumerationVariant, KmipFlavor, TTLV, TTLValue, from_ttlv};

fn node(tag: &str, value: TTLValue) -> TTLV {
    TTLV {
        tag: tag.to_owned(),
        value,
    }
}

fn kmip1_tree() -> TTLV {
    node(
        "Link",
        TTLValue::Structure(vec![
            node("BatchCount", TTLValue::Integer(123)),
            node(
                "IterationCount",
                TTLValue::LongInteger(1_234_567_890_123_456_789),
            ),
            node(
                "D",
                TTLValue::BigInteger(KmipBigInt::from(BigInt::from(
                    12_345_678_901_234_567_890_123_456_789_012_345_678_i128,
                ))),
            ),
            node(
                "CryptographicAlgorithm",
                TTLValue::Enumeration(KmipEnumerationVariant {
                    value: 3,
                    name: "AES".to_owned(),
                }),
            ),
            node("Sensitive", TTLValue::Boolean(true)),
            node("Name", TTLValue::TextString("Hello KMIP".to_owned())),
            node("KeyValue", TTLValue::ByteString(vec![1, 2, 3, 4, 5])),
            node(
                "DeactivationDate",
                TTLValue::DateTime(datetime!(2024-03-05 12:34:56 UTC)),
            ),
            node("ValidityIndicator", TTLValue::Interval(86400)),
            node(
                "ActivationDate",
                TTLValue::DateTimeExtended(1_709_642_096_123_456),
            ),
        ]),
    )
}

fn kmip2_tree() -> TTLV {
    let mut tree = kmip1_tree();
    if let TTLValue::Structure(children) = &mut tree.value {
        children.push(node("CertificateAttributes", TTLValue::Integer(7)));
    }
    tree
}

const KMIP1_HEX: &str = "42004a01000000b042000d02000000040000007b0000000042003c0300000008112210f47de9811542002e04000000100949b0f6f0023313c4499050de38f34e4200280500000004000000030000000042012006000000080000000000000001420053070000000a48656c6c6f204b4d49500000000000004200450800000005010203040500000042002f09000000080000000065e7117042009b0a0000000400015180000000004200010b00000008000612e911d51e40";
const KMIP2_HEX: &str = "42004a01000000c042000d02000000040000007b0000000042003c0300000008112210f47de9811542002e04000000100949b0f6f0023313c4499050de38f34e4200280500000004000000030000000042012006000000080000000000000001420053070000000a48656c6c6f204b4d49500000000000004200450800000005010203040500000042002f09000000080000000065e7117042009b0a0000000400015180000000004200010b00000008000612e911d51e4054000102000000040000000700000000";
const EXT_TAG_HEX: &str = "54000102000000040000000700000000";

#[test]
fn characterization_ttlv_to_bytes_kmip1_all_types() {
    let bytes = kmip1_tree().to_bytes(KmipFlavor::Kmip1).unwrap();
    assert_eq!(hex::encode(&bytes), KMIP1_HEX);
    let back = TTLV::from_bytes(&bytes, KmipFlavor::Kmip1).unwrap();
    assert_eq!(back, kmip1_tree());
}

#[test]
fn characterization_ttlv_to_bytes_kmip2_all_types() {
    let bytes = kmip2_tree().to_bytes(KmipFlavor::Kmip2).unwrap();
    assert_eq!(hex::encode(&bytes), KMIP2_HEX);
    let back = TTLV::from_bytes(&bytes, KmipFlavor::Kmip2).unwrap();
    assert_eq!(back, kmip2_tree());
}

#[test]
fn characterization_ttlv_to_bytes_kmip2_extension_tag() {
    let bytes = node("CertificateAttributes", TTLValue::Integer(7))
        .to_bytes(KmipFlavor::Kmip2)
        .unwrap();
    assert_eq!(hex::encode(&bytes), EXT_TAG_HEX);
}

#[test]
fn characterization_offset_date_time_deserialize() {
    let dt = datetime!(2024-03-05 12:34:56 UTC);
    let out: OffsetDateTime = from_ttlv(node("ActivationDate", TTLValue::DateTime(dt))).unwrap();
    assert_eq!(out, dt);
}

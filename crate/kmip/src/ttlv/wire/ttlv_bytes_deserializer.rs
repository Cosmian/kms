use std::io::Read;

use time::OffsetDateTime;

use crate::ttlv::{
    KmipEnumerationVariant, TTLV, TTLValue, TtlvType, error::TtlvError, kmip_big_int::KmipBigInt,
    wire::kmip_tag::KmipTag,
};

/// Maximum nesting depth for TTLV structures.
///
/// A deeply-nested binary TTLV blob can exhaust the call stack (`DoS` via stack overflow)
/// because `read_ttlv_inner` is recursive. Limiting depth to 64 is far above any
/// legitimate KMIP nesting depth (typical maximum is ~8) while preventing the attack.
pub(crate) const MAX_TTLV_DEPTH: u32 = 64;

/// Maximum byte length for a single TTLV leaf field (`ByteString`, `TextString``BigInteger`er).
///
/// Without this guard an attacker can craft a tiny HTTP request whose TTLV header
/// claims a field length of, say, 500 MB. The server would then call
/// `vec![0_u8; 500_000_000]`, zero-initialising all pages and exhausting RAM,
/// before `read_exact` fails on the actual (small) payload.
///
/// 64 MiB matches Actix-web's HTTP-body payload limit so no legitimate single
/// field can ever exceed this value.
pub(crate) const MAX_TTLV_FIELD_BYTES: usize = 64 * 1024 * 1024;

pub struct TTLVBytesDeserializer<R> {
    reader: R,
}

impl<R> TTLVBytesDeserializer<R>
where
    R: Read,
{
    pub const fn new(reader: R) -> Self {
        Self { reader }
    }

    /// Parse one TTLV item from the reader.
    ///
    /// Delegates to the depth-tracking inner implementation starting at depth 0.
    pub fn read_ttlv<TAG: KmipTag>(&mut self) -> Result<(TTLV, usize), TtlvError> {
        self.read_ttlv_inner::<TAG>(0)
    }

    fn read_ttlv_inner<TAG: KmipTag>(&mut self, depth: u32) -> Result<(TTLV, usize), TtlvError> {
        if depth > MAX_TTLV_DEPTH {
            return Err(TtlvError::from(format!(
                "TTLV structure depth exceeds maximum allowed depth ({MAX_TTLV_DEPTH})"
            )));
        }
        // Read Tag (3 bytes)
        let mut tag_bytes = [0_u8; 3];
        self.reader.read_exact(&mut tag_bytes)?;
        // append a leading empty byte to tag_bytes
        // to make it 4 bytes
        let mut full_tag_bytes = [0_u8; 4];
        full_tag_bytes[1..].copy_from_slice(&tag_bytes);
        let tag_value = u32::from_be_bytes(full_tag_bytes);
        let tag = TAG::from_u32(tag_value).map_err(|_e| {
            TtlvError::from(format!(
                "Invalid tag number: Ox{}",
                hex::encode_upper(&tag_value.to_be_bytes()[1..])
            ))
        })?;

        // Read Type (1 byte)
        let mut type_byte = [0_u8; 1];
        self.reader.read_exact(&mut type_byte)?;
        let item_type = TtlvType::try_from(type_byte[0])?;

        // Read Length (4 bytes)
        let mut buf4 = [0_u8; 4];
        self.reader.read_exact(&mut buf4)?;
        let length = u32::from_be_bytes(buf4);
        let length = usize::try_from(length)
            .map_err(|_e| TtlvError::from(format!("Length too large: {length}")))?;

        // Read Value based on type
        let (value, value_len) = match item_type {
            TtlvType::Structure => {
                let mut items = Vec::new();
                let mut remaining = length;
                while remaining > 0 {
                    let (item, item_length) = self.read_ttlv_inner::<TAG>(depth + 1)?;
                    if item_length > remaining {
                        return Err(TtlvError::from(format!(
                            "TTLV Structure child length ({item_length}) exceeds remaining \
                             parent length ({remaining}): malformed Structure"
                        )));
                    }
                    remaining -= item_length;
                    items.push(item);
                }
                (TTLValue::Structure(items), length)
            }
            TtlvType::Integer => {
                let mut buf4 = [0_u8; 4];
                self.reader.read_exact(&mut buf4)?;
                let value = TTLValue::Integer(i32::from_be_bytes(buf4));
                // read the 4 bytes of padding
                self.reader.read_exact(&mut buf4)?;
                (value, 8)
            }
            TtlvType::LongInteger => {
                let mut buf8 = [0_u8; 8];
                self.reader.read_exact(&mut buf8)?;
                (TTLValue::LongInteger(i64::from_be_bytes(buf8)), 8)
            }
            TtlvType::BigInteger => {
                if length > MAX_TTLV_FIELD_BYTES {
                    return Err(TtlvError::from(format!(
                        "TTLV BigInteger field length {length} exceeds maximum allowed \
                         ({MAX_TTLV_FIELD_BYTES} bytes)"
                    )));
                }
                let mut buf = vec![0_u8; length];
                self.reader.read_exact(&mut buf)?;
                (
                    TTLValue::BigInteger(KmipBigInt::from_signed_bytes_be(&buf)),
                    length,
                )
            }
            TtlvType::Enumeration => {
                let mut buf4 = [0_u8; 4];
                self.reader.read_exact(&mut buf4)?;
                let value = TTLValue::Enumeration(KmipEnumerationVariant {
                    value: u32::from_be_bytes(buf4),
                    name: String::new(),
                });
                // read the 4 bytes of padding
                self.reader.read_exact(&mut buf4)?;
                (value, 8)
            }
            TtlvType::Boolean => {
                let mut buf8 = [0_u8; 8];
                self.reader.read_exact(&mut buf8)?;
                (TTLValue::Boolean(buf8[7] != 0), 8)
            }
            TtlvType::TextString => {
                if length > MAX_TTLV_FIELD_BYTES {
                    return Err(TtlvError::from(format!(
                        "TTLV TextString field length {length} exceeds maximum allowed \
                         ({MAX_TTLV_FIELD_BYTES} bytes)"
                    )));
                }
                let mut buf = vec![0_u8; length];
                self.reader.read_exact(&mut buf)?;
                let value = TTLValue::TextString(String::from_utf8(buf)?);
                // calculate the padding
                let padding = (8 - (length % 8)) % 8;
                if padding != 0 {
                    // read the padding bytes
                    let mut padding_bytes = vec![0_u8; padding];
                    self.reader.read_exact(&mut padding_bytes)?;
                }
                (value, length + padding)
            }
            TtlvType::ByteString => {
                if length > MAX_TTLV_FIELD_BYTES {
                    return Err(TtlvError::from(format!(
                        "TTLV ByteString field length {length} exceeds maximum allowed \
                         ({MAX_TTLV_FIELD_BYTES} bytes)"
                    )));
                }
                let mut buf = vec![0_u8; length];
                self.reader.read_exact(&mut buf)?;
                let value = TTLValue::ByteString(buf);
                // calculate the padding
                let padding = (8 - (length % 8)) % 8;
                if padding != 0 {
                    // read the padding bytes
                    let mut padding_bytes = vec![0_u8; padding];
                    self.reader.read_exact(&mut padding_bytes)?;
                }
                (value, length + padding)
            }
            TtlvType::DateTime => {
                let mut buf8 = [0_u8; 8];
                self.reader.read_exact(&mut buf8)?;
                let timestamp = i64::from_be_bytes(buf8);
                let t = OffsetDateTime::from_unix_timestamp(timestamp)?;
                (TTLValue::DateTime(t), 8)
            }
            TtlvType::Interval => {
                let mut buf4 = [0_u8; 4];
                self.reader.read_exact(&mut buf4)?;
                let value = TTLValue::Interval(u32::from_be_bytes(buf4));
                // read the 4 bytes of padding
                self.reader.read_exact(&mut buf4)?;
                (value, 8)
            }
            TtlvType::DateTimeExtended => {
                let mut buf8 = [0_u8; 8];
                self.reader.read_exact(&mut buf8)?;
                let micros = i64::from_be_bytes(buf8);
                (TTLValue::DateTimeExtended(i128::from(micros)), 8)
            }
        };

        Ok((
            TTLV {
                tag: tag.to_string(),
                value,
            },
            value_len + 8,
        ))
    }
}

#[expect(clippy::unwrap_used)]
#[cfg(test)]
mod tests {

    use num_bigint_dig::BigInt;

    use super::*;
    use crate::{
        kmip_1_4,
        ttlv::{
            KmipEnumerationVariant, TTLV, TTLValue,
            wire::ttlv_bytes_serializer::TTLVBytesSerializer,
        },
    };

    fn serialize_and_deserialize(ttlv: &TTLV) {
        let mut buffer = Vec::new();
        let mut serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(ttlv)
            .unwrap();

        let mut deserializer = TTLVBytesDeserializer::new(buffer.as_slice());
        let (ttlv_, length) = deserializer
            .read_ttlv::<kmip_1_4::kmip_types::Tag>()
            .unwrap();
        assert_eq!(length, buffer.len(), "Length mismatch");
        assert_eq!(ttlv.tag, ttlv_.tag, "Tag mismatch");
        assert_eq!(ttlv.value, ttlv_.value, "Value mismatch");
    }

    #[test]
    fn test_integer() {
        let original = TTLV {
            tag: kmip_1_4::kmip_types::Tag::BatchCount.to_string(),
            value: TTLValue::Integer(123),
        };
        serialize_and_deserialize(&original);
    }

    #[test]
    fn test_long_integer() {
        let original = TTLV {
            tag: kmip_1_4::kmip_types::Tag::IterationCount.to_string(),
            value: TTLValue::LongInteger(1_234_567_890_123_456_789),
        };
        serialize_and_deserialize(&original);
    }

    #[test]
    fn test_big_integer() {
        let bi = BigInt::from(12_345_678_901_234_567_890_123_456_789_012_345_678_i128);
        let original = TTLV {
            tag: kmip_1_4::kmip_types::Tag::D.to_string(),
            value: TTLValue::BigInteger(KmipBigInt::from(bi)),
        };
        serialize_and_deserialize(&original);
    }

    #[test]
    #[expect(clippy::as_conversions)]
    fn test_enumeration() {
        let variant = KmipEnumerationVariant {
            value: kmip_1_4::kmip_types::CryptographicAlgorithm::AES as u32,
            name: "AES".to_owned(),
        };
        let original = TTLV {
            tag: kmip_1_4::kmip_types::Tag::CryptographicAlgorithm.to_string(),
            value: TTLValue::Enumeration(variant),
        };
        serialize_and_deserialize(&original);
    }

    #[test]
    fn test_boolean() {
        let original = TTLV {
            tag: kmip_1_4::kmip_types::Tag::Sensitive.to_string(),
            value: TTLValue::Boolean(true),
        };
        serialize_and_deserialize(&original);
    }

    #[test]
    fn test_text_string() {
        let original = TTLV {
            tag: kmip_1_4::kmip_types::Tag::Name.to_string(),
            value: TTLValue::TextString("Hello KMIP".to_owned()),
        };
        serialize_and_deserialize(&original);
    }

    #[test]
    fn test_byte_string() {
        let original = TTLV {
            tag: kmip_1_4::kmip_types::Tag::KeyValue.to_string(),
            value: TTLValue::ByteString(vec![1, 2, 3, 4, 5]),
        };
        serialize_and_deserialize(&original);
    }

    #[test]
    fn test_date_time() {
        let now = OffsetDateTime::now_utc();
        let original = TTLV {
            tag: kmip_1_4::kmip_types::Tag::DeactivationDate.to_string(),
            value: TTLValue::DateTime(now),
        };
        serialize_and_deserialize(&original);
    }

    #[test]
    fn test_interval() {
        let original = TTLV {
            tag: kmip_1_4::kmip_types::Tag::ValidityIndicator.to_string(),
            value: TTLValue::Interval(86400),
        };
        serialize_and_deserialize(&original);
    }

    #[test]
    fn test_date_time_extended() {
        let now = OffsetDateTime::now_utc();
        let micros = i64::try_from(now.unix_timestamp_nanos() / 1_000).unwrap();
        let original = TTLV {
            tag: kmip_1_4::kmip_types::Tag::ActivationDate.to_string(),
            value: TTLValue::DateTimeExtended(i128::from(micros)),
        };
        serialize_and_deserialize(&original);
    }

    #[test]
    fn test_structure() {
        let original = TTLV {
            tag: kmip_1_4::kmip_types::Tag::Link.to_string(),
            value: TTLValue::Structure(vec![
                TTLV {
                    tag: kmip_1_4::kmip_types::Tag::LinkType.to_string(),
                    value: TTLValue::Integer(123),
                },
                TTLV {
                    tag: kmip_1_4::kmip_types::Tag::LinkedObjectIdentifier.to_string(),
                    value: TTLValue::TextString("Hello KMIP".to_owned()),
                },
            ]),
        };
        serialize_and_deserialize(&original);
    }

    /// Build a TTLV tree that is `depth` levels deep (each level wraps the next in a Structure).
    fn build_nested_structure(depth: u32) -> TTLV {
        if depth == 0 {
            return TTLV {
                tag: kmip_1_4::kmip_types::Tag::BatchCount.to_string(),
                value: TTLValue::Integer(0),
            };
        }
        TTLV {
            tag: kmip_1_4::kmip_types::Tag::Link.to_string(),
            value: TTLValue::Structure(vec![build_nested_structure(depth - 1)]),
        }
    }

    #[test]
    fn test_depth_at_limit_is_ok() {
        // A tree exactly at the maximum depth must parse successfully.
        let original = build_nested_structure(MAX_TTLV_DEPTH);
        serialize_and_deserialize(&original);
    }

    #[test]
    fn test_depth_exceeds_limit_is_err() {
        // One level deeper than MAX_TTLV_DEPTH must be rejected.
        let over_limit = build_nested_structure(MAX_TTLV_DEPTH + 1);
        let mut buffer = Vec::new();
        let mut serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&over_limit)
            .unwrap();

        let mut deserializer = TTLVBytesDeserializer::new(buffer.as_slice());
        let result = deserializer.read_ttlv::<kmip_1_4::kmip_types::Tag>();
        assert!(result.is_err(), "expected error when depth exceeds maximum");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("depth"),
            "error message should mention 'depth', got: {err_msg}"
        );
    }
}

use std::io::Write;

use crate::ttlv::{TTLV, TTLValue, TtlvType, error::TtlvError, wire::kmip_tag::KmipTag};

/// Write a tag as a 3-byte big-endian integer
fn write_tag<W: Write, TAG: KmipTag>(writer: &mut W, tag_str: &str) -> Result<(), TtlvError> {
    let tag =
        TAG::from_str(tag_str).map_err(|_e| TtlvError::from(format!("Unknown tag: {tag_str}")))?;
    let tag_value: u32 = tag.to_u32();
    let tag_bytes = tag_value.to_be_bytes();
    // Write only the lowest 3 bytes in big-endian
    writer.write_all(&tag_bytes[1..])?;
    Ok(())
}

/// Write a type as a 1-byte integer
fn write_type<W: Write>(writer: &mut W, item_type: TtlvType) -> Result<(), TtlvError> {
    writer.write_all(&[item_type.to_byte()])?;
    Ok(())
}

/// Write a length as a 4-byte big-endian integer
fn write_length<W: Write>(writer: &mut W, length: usize) -> Result<(), TtlvError> {
    let l = u32::try_from(length)
        .map_err(|_e| TtlvError::from(format!("Length too large: {length}")))?;
    writer.write_all(&l.to_be_bytes())?;
    Ok(())
}

pub struct TTLVBytesSerializer<W> {
    writer: W,
}

impl<W> TTLVBytesSerializer<W>
where
    W: Write,
{
    pub const fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn write_ttlv<TAG: KmipTag>(&mut self, ttlv: &TTLV) -> Result<(), TtlvError> {
        #[cfg(test)]
        cosmian_logger::debug!("[serialize] writing tag: {}", ttlv.tag);
        // Write Tag (3 bytes)
        write_tag::<W, TAG>(&mut self.writer, &ttlv.tag)?;

        match &ttlv.value {
            TTLValue::Structure(items) => {
                // Write Type (1 byte)
                write_type(&mut self.writer, TtlvType::Structure)?;
                // Calculate total length of nested items
                let mut temp_buffer = Vec::new();
                let mut temp_serializer = TTLVBytesSerializer::new(&mut temp_buffer);
                for item in items {
                    temp_serializer.write_ttlv::<TAG>(item)?;
                }
                // Write Length (4 bytes)
                write_length(&mut self.writer, temp_buffer.len())?;
                // Write actual nested items
                self.writer.write_all(&temp_buffer)?;
            }
            TTLValue::Integer(value) => {
                write_type(&mut self.writer, TtlvType::Integer)?;
                write_length(&mut self.writer, 4)?;
                self.writer.write_all(&value.to_be_bytes())?;
                // 4 bytes padding
                self.writer.write_all(&[0; 4])?;
            }
            TTLValue::LongInteger(value) => {
                write_type(&mut self.writer, TtlvType::LongInteger)?;
                write_length(&mut self.writer, 8)?;
                self.writer.write_all(&value.to_be_bytes())?;
            }
            TTLValue::BigInteger(value) => {
                let bytes = value.to_signed_bytes_be();
                write_type(&mut self.writer, TtlvType::BigInteger)?;
                write_length(&mut self.writer, bytes.len())?;
                self.writer.write_all(&bytes)?;
            }
            TTLValue::Enumeration(en) => {
                write_type(&mut self.writer, TtlvType::Enumeration)?;
                write_length(&mut self.writer, 4)?;
                self.writer.write_all(&en.value.to_be_bytes())?;
                // 4 bytes padding
                self.writer.write_all(&[0; 4])?;
            }
            TTLValue::Boolean(value) => {
                write_type(&mut self.writer, TtlvType::Boolean)?;
                write_length(&mut self.writer, 8)?;
                // booleans are encoded on 8 bytes
                let mut buf = [0_u8; 8];
                buf[7] = u8::from(*value);
                self.writer.write_all(&buf)?;
            }
            TTLValue::TextString(value) => {
                write_type(&mut self.writer, TtlvType::TextString)?;
                let utf8_bytes = value.as_bytes();
                write_length(&mut self.writer, utf8_bytes.len())?;
                self.writer.write_all(utf8_bytes)?;
                // pad to a multiple of 8 bytes
                let padding = 8 - (utf8_bytes.len() % 8);
                if padding != 8 {
                    let padding_bytes = vec![0_u8; padding];
                    self.writer.write_all(&padding_bytes)?;
                }
            }
            TTLValue::ByteString(value) => {
                write_type(&mut self.writer, TtlvType::ByteString)?;
                write_length(&mut self.writer, value.len())?;
                self.writer.write_all(value)?;
                // pad to a multiple of 8 bytes
                let padding = 8 - (value.len() % 8);
                if padding != 8 {
                    let padding_bytes = vec![0_u8; padding];
                    self.writer.write_all(&padding_bytes)?;
                }
            }
            TTLValue::DateTime(value) => {
                write_type(&mut self.writer, TtlvType::DateTime)?;
                write_length(&mut self.writer, 8)?;
                self.writer
                    .write_all(&value.unix_timestamp().to_be_bytes())?;
            }
            TTLValue::Interval(value) => {
                write_type(&mut self.writer, TtlvType::Interval)?;
                write_length(&mut self.writer, 4)?;
                self.writer.write_all(&value.to_be_bytes())?;
                // 4 bytes padding
                self.writer.write_all(&[0; 4])?;
            }
            TTLValue::DateTimeExtended(value) => {
                write_type(&mut self.writer, TtlvType::DateTimeExtended)?;
                write_length(&mut self.writer, 8)?;
                let v_64 = i64::try_from(*value).map_err(|_e| {
                    TtlvError::from(format!("Date Time Extended value too large: {value}"))
                })?;
                self.writer.write_all(&v_64.to_be_bytes())?;
            }
        }
        Ok(())
    }
}

#[expect(clippy::unwrap_used)]
#[expect(clippy::as_conversions)]
#[expect(clippy::indexing_slicing)]
#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use num_bigint_dig::BigInt;
    use time::{OffsetDateTime, macros::datetime};

    use crate::{
        kmip_1_4, kmip_2_1,
        ttlv::{
            KmipBigInt, KmipEnumerationVariant, TTLV, TTLVBytesSerializer, TTLValue, TtlvError,
            TtlvType,
            wire::ttlv_bytes_serializer::{write_length, write_tag, write_type},
        },
    };

    #[test]
    fn test_tag_u32_from_tag_name() {
        let tag = kmip_2_1::kmip_types::Tag::from_str("Link").unwrap();
        let tag_u32 = tag as u32;
        assert_eq!(tag_u32, 0x42_004A);

        let tag = kmip_2_1::kmip_types::Tag::from_str("PublicProtectionStorageMasks").unwrap();
        let tag_u32 = tag as u32;
        assert_eq!(tag_u32, 0x42_0165);

        let tag = kmip_1_4::kmip_types::Tag::from_str("Link").unwrap();
        let tag_u32 = tag as u32;
        assert_eq!(tag_u32, 0x42_004A);
    }

    #[test]
    fn test_tag_last_three_bytes_big_endian() {
        use std::str::FromStr;

        // Get a Tag value (Link = 0x42_004A)
        let tag = kmip_1_4::kmip_types::Tag::from_str("Link").unwrap();
        let tag_u32: u32 = tag as u32;

        // Convert to big-endian bytes
        let tag_bytes = tag_u32.to_be_bytes();

        // Get last 3 bytes (ignore first byte)
        let last_three_bytes = &tag_bytes[1..];

        // Verify against expected values
        assert_eq!(last_three_bytes, [0x42, 0x00, 0x4A]);

        // Test with another tag (ObjectType = 0x42_0057)
        let tag2 = kmip_1_4::kmip_types::Tag::from_str("ObjectType").unwrap();
        let tag2_u32: u32 = tag2 as u32;
        let tag2_bytes = tag2_u32.to_be_bytes();
        let last_three_bytes2 = &tag2_bytes[1..];

        assert_eq!(last_three_bytes2, [0x42, 0x00, 0x57]);
    }

    #[test]
    fn test_write_tag() {
        let tag = kmip_1_4::kmip_types::Tag::from_str("Link").unwrap();
        let tag_u32: u32 = tag as u32;
        let tag_bytes = tag_u32.to_be_bytes();
        let last_three_bytes = &tag_bytes[1..];

        let mut buffer = Vec::new();
        write_tag::<Vec<u8>, kmip_1_4::kmip_types::Tag>(&mut buffer, "Link").unwrap();

        assert_eq!(buffer, last_three_bytes);
    }

    #[test]
    fn test_write_type() {
        let mut buffer = Vec::new();
        write_type(&mut buffer, crate::ttlv::TtlvType::Structure).unwrap();
        assert_eq!(buffer, [0x01]);
        buffer.clear();
        write_type(&mut buffer, crate::ttlv::TtlvType::Integer).unwrap();
        assert_eq!(buffer, [0x02]);
        buffer.clear();
        write_type(&mut buffer, crate::ttlv::TtlvType::LongInteger).unwrap();
        assert_eq!(buffer, [0x03]);
        buffer.clear();
        write_type(&mut buffer, crate::ttlv::TtlvType::BigInteger).unwrap();
        assert_eq!(buffer, [0x04]);
        buffer.clear();
        write_type(&mut buffer, crate::ttlv::TtlvType::Enumeration).unwrap();
        assert_eq!(buffer, [0x05]);
        buffer.clear();
        write_type(&mut buffer, crate::ttlv::TtlvType::Boolean).unwrap();
        assert_eq!(buffer, [0x06]);
        buffer.clear();
        write_type(&mut buffer, crate::ttlv::TtlvType::TextString).unwrap();
        assert_eq!(buffer, [0x07]);
        buffer.clear();
        write_type(&mut buffer, crate::ttlv::TtlvType::ByteString).unwrap();
        assert_eq!(buffer, [0x08]);
        buffer.clear();
        write_type(&mut buffer, crate::ttlv::TtlvType::DateTime).unwrap();
        assert_eq!(buffer, [0x09]);
        buffer.clear();
        write_type(&mut buffer, crate::ttlv::TtlvType::Interval).unwrap();
        assert_eq!(buffer, [0x0A]);
        buffer.clear();
        write_type(&mut buffer, crate::ttlv::TtlvType::DateTimeExtended).unwrap();
        assert_eq!(buffer, [0x0B]);
        buffer.clear();
    }

    #[test]
    fn test_write_length() {
        let mut buffer = Vec::new();
        write_length(&mut buffer, 4).unwrap();
        assert_eq!(buffer, [0x00, 0x00, 0x00, 0x04]);
        buffer.clear();
        write_length(&mut buffer, 8).unwrap();
        assert_eq!(buffer, [0x00, 0x00, 0x00, 0x08]);
        buffer.clear();
        write_length(&mut buffer, 16).unwrap();
        assert_eq!(buffer, [0x00, 0x00, 0x00, 0x10]);
        buffer.clear();
    }

    #[test]
    fn test_write_integer() {
        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::BatchCount.to_string(),
            value: TTLValue::Integer(123),
        };
        let mut buffer = Vec::new();
        let mut serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();

        assert_eq!(
            buffer.len(),
            3 /* tag */ + 1 /* type */ + 4 /* length */ + 4 /* i32 value */ + 4 /* padding */
        );
        // Check the first 3 bytes (tag) - BatchCount
        assert_eq!(
            &buffer[0..3],
            &(kmip_1_4::kmip_types::Tag::BatchCount as u32).to_be_bytes()[1..4]
        );
        // Check the type byte
        assert_eq!(buffer[3], TtlvType::Integer as u8);
        // Check the length bytes
        assert_eq!(&buffer[4..8], &[0x00, 0x00, 0x00, 0x04]);
        // Check the value bytes
        assert_eq!(&buffer[8..12], u32::to_be_bytes(123));
        // Check the padding bytes
        assert_eq!(&buffer[12..16], &[0; 4]);
    }

    #[test]
    fn test_long_integer() {
        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::IterationCount.to_string(),
            value: TTLValue::LongInteger(1_234_567_890_123_456_789),
        };
        let mut buffer = Vec::new();
        let mut serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();

        assert_eq!(
            buffer.len(),
            3 /* tag */ + 1 /* type */ + 4 /* length */ + 8 /* i64 value */
        );
        // Check the first 3 bytes (tag) - IterationCount
        assert_eq!(
            &buffer[0..3],
            &(kmip_1_4::kmip_types::Tag::IterationCount as u32).to_be_bytes()[1..4]
        );
        // Check the type byte
        assert_eq!(buffer[3], TtlvType::LongInteger as u8);
        // Check the length bytes
        assert_eq!(&buffer[4..8], &[0x00, 0x00, 0x00, 0x08]);
        // Check the value bytes
        assert_eq!(&buffer[8..16], &i64::to_be_bytes(1_234_567_890_123_456_789));
    }

    #[test]
    fn test_big_integer() {
        let bi = KmipBigInt::from(BigInt::from(
            12_345_678_901_234_567_890_123_456_789_012_345_678_i128,
        ));
        let bi_bytes = bi.to_signed_bytes_be();
        let bi_len = bi_bytes.len();
        assert_eq!(bi_bytes.len() % 8, 0);

        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::D.to_string(),
            value: TTLValue::BigInteger(bi.clone()),
        };
        let mut buffer = Vec::new();
        let mut serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();

        assert_eq!(
            buffer.len(),
            3 /* tag */ + 1 /* type */ + 4 /* length */ + bi_len /* BigInt value */
        );
        // Check the first 3 bytes (tag) - D
        assert_eq!(
            &buffer[0..3],
            &(kmip_1_4::kmip_types::Tag::D as u32).to_be_bytes()[1..4]
        );
        // Check the type byte
        assert_eq!(buffer[3], TtlvType::BigInteger as u8);
        // Check the length bytes
        assert_eq!(
            &buffer[4..8],
            u32::try_from(bi.to_signed_bytes_be().len())
                .unwrap()
                .to_be_bytes()
        );
        // Check the value bytes
        assert_eq!(&buffer[8..], bi_bytes.as_slice());
    }

    #[test]
    fn test_enumeration() {
        let variant = KmipEnumerationVariant {
            value: 0x03,
            name: "AES".to_owned(),
        };
        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::CryptographicAlgorithm.to_string(),
            value: TTLValue::Enumeration(variant),
        };
        let mut buffer = Vec::new();
        let mut serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();

        assert_eq!(
            buffer.len(),
            3 /* tag */ + 1 /* type */ + 4 /* length */ + 4 /* variant */ + 4 /* padding */
        );
        // Check the first 3 bytes (tag) - CryptographicAlgorithm
        assert_eq!(
            &buffer[0..3],
            &(kmip_1_4::kmip_types::Tag::CryptographicAlgorithm as u32).to_be_bytes()[1..4]
        );
        // Check the type byte
        assert_eq!(buffer[3], TtlvType::Enumeration as u8);
        // Check the length bytes
        assert_eq!(&buffer[4..8], &[0x00, 0x00, 0x00, 0x04]);
        // Check the value bytes
        assert_eq!(
            &buffer[8..12],
            u32::to_be_bytes(kmip_1_4::kmip_types::CryptographicAlgorithm::AES as u32)
        );
        // Check the padding bytes
        assert_eq!(&buffer[12..16], &[0; 4]);
    }

    #[test]
    fn test_boolean() {
        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::Sensitive.to_string(),
            value: TTLValue::Boolean(true),
        };
        let mut buffer = Vec::new();
        let mut serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();

        assert_eq!(
            buffer.len(),
            3 /* tag */ + 1 /* type */ + 4 /* length */ + 8 /* boolean */
        );
        // Check the first 3 bytes (tag) - Sensitive
        assert_eq!(
            &buffer[0..3],
            &(kmip_1_4::kmip_types::Tag::Sensitive as u32).to_be_bytes()[1..4]
        );
        // Check the type byte
        assert_eq!(buffer[3], TtlvType::Boolean as u8);
        // Check the length bytes
        assert_eq!(&buffer[4..8], &[0x00, 0x00, 0x00, 0x08]);
        // Check the value bytes
        assert_eq!(&buffer[8..15], &[0; 7]);
        assert_eq!(&buffer[15], &0x01);
    }

    #[test]
    fn test_text_string() {
        let msg = "Hello KMIP";
        let msg_bytes = msg.as_bytes();
        let msg_len = msg_bytes.len();

        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::Name.to_string(),
            value: TTLValue::TextString(msg.to_owned()),
        };
        let mut buffer = Vec::new();
        let mut serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();

        assert_eq!(
            buffer.len(),
            3 /* tag */ + 1 /* type */ + 4 /* length */ + 10 /* string */ + 6 /* padding */
        );
        // Check the first 3 bytes (tag) - Name
        assert_eq!(
            &buffer[0..3],
            &(kmip_1_4::kmip_types::Tag::Name as u32).to_be_bytes()[1..4]
        );
        // Check the type byte
        assert_eq!(buffer[3], TtlvType::TextString as u8);
        // Check the length bytes
        assert_eq!(&buffer[4..8], u32::try_from(msg_len).unwrap().to_be_bytes());
        // Check the value bytes
        assert_eq!(&buffer[8..8 + msg_len], b"Hello KMIP");
        // Check the padding bytes
        assert_eq!(&buffer[8 + msg_len..], &[0; 6]);
    }

    #[test]
    fn test_bytes_string() {
        let msg = vec![1, 2, 3, 4, 5];
        let msg_len = msg.len();

        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::KeyValue.to_string(),
            value: TTLValue::ByteString(msg),
        };
        let mut buffer = Vec::new();
        let mut serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();

        assert_eq!(
            buffer.len(),
            3 /* tag */ + 1 /* type */ + 4 /* length */ + msg_len /* string */ + 3 /* padding */
        );
        // Check the first 3 bytes (tag) - KeyValue
        assert_eq!(
            &buffer[0..3],
            &(kmip_1_4::kmip_types::Tag::KeyValue as u32).to_be_bytes()[1..4]
        );
        // Check the type byte
        assert_eq!(buffer[3], TtlvType::ByteString as u8);
        // Check the length bytes
        assert_eq!(&buffer[4..8], u32::try_from(msg_len).unwrap().to_be_bytes());
        // Check the value bytes
        assert_eq!(&buffer[8..8 + msg_len], &[1, 2, 3, 4, 5]);
        // Check the padding bytes
        assert_eq!(&buffer[8 + msg_len..], &[0; 3]);
    }

    #[test]
    fn test_date_time() {
        let now = OffsetDateTime::now_utc();
        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::DeactivationDate.to_string(),
            value: TTLValue::DateTime(now),
        };
        let mut buffer = Vec::new();
        let mut serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();

        assert_eq!(
            buffer.len(),
            3 /* tag */ + 1 /* type */ + 4 /* length */ + 8 /* datetime */
        );
        // Check the first 3 bytes (tag) - DeactivationDate
        assert_eq!(
            &buffer[0..3],
            &(kmip_1_4::kmip_types::Tag::DeactivationDate as u32).to_be_bytes()[1..4]
        );
        // Check the type byte
        assert_eq!(buffer[3], TtlvType::DateTime as u8);
        // Check the length bytes
        assert_eq!(&buffer[4..8], &[0x00, 0x00, 0x00, 0x08]);
        // Check the value bytes
        assert_eq!(&buffer[8..16], &now.unix_timestamp().to_be_bytes());
    }

    #[test]
    fn test_interval() {
        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::ValidityIndicator.to_string(),
            value: TTLValue::Interval(86400),
        };
        let mut buffer = Vec::new();
        let mut serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();

        assert_eq!(
            buffer.len(),
            3 /* tag */ + 1 /* type */ + 4 /* length */ + 4 /* interval */ + 4 /* padding */
        );
        // Check the first 3 bytes (tag) - ValidityIndicator
        assert_eq!(
            &buffer[0..3],
            &(kmip_1_4::kmip_types::Tag::ValidityIndicator as u32).to_be_bytes()[1..4]
        );
        // Check the type byte
        assert_eq!(buffer[3], TtlvType::Interval as u8);
        // Check the length bytes
        assert_eq!(&buffer[4..8], &[0x00, 0x00, 0x00, 0x04]);
        // Check the value bytes
        assert_eq!(&buffer[8..12], 86400_u32.to_be_bytes());
        // Check the padding bytes
        assert_eq!(&buffer[12..16], &[0; 4]);
    }

    #[test]
    fn test_date_time_extended() {
        let now = OffsetDateTime::now_utc();
        let micros = i64::try_from(now.unix_timestamp_nanos() / 1_000)
            .map_err(|_e| TtlvError::from(format!("Date Time Extended value too large: {now}")))
            .unwrap();
        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::ActivationDate.to_string(),
            value: TTLValue::DateTimeExtended(i128::from(micros)),
        };
        let mut buffer = Vec::new();
        let mut serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();

        assert_eq!(
            buffer.len(),
            3 /* tag */ + 1 /* type */ + 4 /* length */ + 8 /* datetime extended */
        );
        // Check the first 3 bytes (tag) - ActivationDate
        assert_eq!(
            &buffer[0..3],
            &(kmip_1_4::kmip_types::Tag::ActivationDate as u32).to_be_bytes()[1..4]
        );
        // Check the type byte
        assert_eq!(buffer[3], TtlvType::DateTimeExtended as u8);
        // Check the length bytes
        assert_eq!(&buffer[4..8], &[0x00, 0x00, 0x00, 0x08]);
        // Check the value bytes
        assert_eq!(&buffer[8..16], &micros.to_be_bytes());
    }

    #[test]
    fn test_structure() {
        let ttlv = TTLV {
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
        let mut buffer = Vec::new();
        let mut serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();

        assert_eq!(
            buffer.len(),
            3 /* tag */ + 1 /* type */ + 4 /* length */
                + 8 + 8 // (Integer)
                + 8 + 16 // (TextString)
        );

        // Check the first 3 bytes (tag) - Link
        assert_eq!(
            &buffer[0..3],
            &(kmip_1_4::kmip_types::Tag::Link as u32).to_be_bytes()[1..4]
        );
        // Check the type byte
        assert_eq!(buffer[3], TtlvType::Structure as u8);
        // Check the length bytes
        assert_eq!(&buffer[4..8], &(8_u32 + 8 + 8 + 16).to_be_bytes());

        // Check LinkType inner structure
        #[expect(clippy::items_after_statements)]
        const OFFSET_1: usize = 8;
        assert_eq!(
            &buffer[OFFSET_1..3 + OFFSET_1],
            &(kmip_1_4::kmip_types::Tag::LinkType as u32).to_be_bytes()[1..4]
        );
        // Check the type byte
        assert_eq!(buffer[3 + OFFSET_1], TtlvType::Integer as u8);
        // Check the length bytes
        assert_eq!(
            &buffer[4 + OFFSET_1..8 + OFFSET_1],
            &[0x00, 0x00, 0x00, 0x04]
        );
        // Check the value bytes
        assert_eq!(&buffer[8 + OFFSET_1..12 + OFFSET_1], u32::to_be_bytes(123));
        // Check the padding bytes
        assert_eq!(&buffer[12 + OFFSET_1..16 + OFFSET_1], &[0; 4]);

        // Check LinkedObjectIdentifier inner structure
        #[expect(clippy::items_after_statements)]
        const OFFSET_2: usize = 8 + 16;
        assert_eq!(
            &buffer[OFFSET_2..3 + OFFSET_2],
            &(kmip_1_4::kmip_types::Tag::LinkedObjectIdentifier as u32).to_be_bytes()[1..4]
        );
        // Check the type byte
        assert_eq!(buffer[3 + OFFSET_2], TtlvType::TextString as u8);
        // Check the length bytes
        assert_eq!(
            &buffer[4 + OFFSET_2..8 + OFFSET_2],
            u32::try_from(10).unwrap().to_be_bytes()
        );
        // Check the value bytes
        assert_eq!(&buffer[8 + OFFSET_2..8 + 10 + OFFSET_2], b"Hello KMIP");
        // Check the padding bytes
        assert_eq!(&buffer[10 + 8 + OFFSET_2..], &[0; 6]);
    }

    /// Section 9.1.2
    #[test]
    fn normative_tests_1_4() {
        // An Integer containing the decimal value 8:
        // 42 00 20 | 02 | 00 00 00 04 | 00 00 00 08 00 00 00 00
        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::CompromiseDate.to_string(),
            value: TTLValue::Integer(8),
        };
        let mut buffer = Vec::new();
        let mut serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();
        assert_eq!(
            buffer,
            vec![
                0x42, 0x00, 0x20, // Tag
                0x02, // Type
                0x00, 0x00, 0x00, 0x04, // Length
                0x00, 0x00, 0x00, 0x08, // Value
                0x00, 0x00, 0x00, 0x00, // Padding
            ]
        );

        // A Long Integer containing the decimal value 123456789000000000:
        // 42 00 20 | 03 | 00 00 00 08 | 01 B6 9B 4B A5 74 92 00
        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::CompromiseDate.to_string(), // tag 42 00 20
            value: TTLValue::LongInteger(123_456_789_000_000_000),
        };
        buffer.clear();
        serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();
        assert_eq!(
            buffer,
            vec![
                0x42, 0x00, 0x20, // Tag
                0x03, // Type
                0x00, 0x00, 0x00, 0x08, // Length
                0x01, 0xB6, 0x9B, 0x4B, 0xA5, 0x74, 0x92, 0x00, // Value
            ]
        );

        // A Big Integer containing the decimal value 1234567890000000000000000000:
        // 42 00 20 | 04 | 00 00 00 10 | 00 00 00 00 03 FD 35 EB 6B C2 DF 46 18 08 00 00
        let bi =
            KmipBigInt::from(BigInt::parse_bytes(b"1234567890000000000000000000", 10).unwrap());
        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::CompromiseDate.to_string(),
            value: TTLValue::BigInteger(bi),
        };
        buffer.clear();
        serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();
        assert_eq!(
            buffer,
            vec![
                0x42, 0x00, 0x20, // Tag
                0x04, // Type
                0x00, 0x00, 0x00, 0x10, // Length
                0x00, 0x00, 0x00, 0x00, 0x03, 0xFD, 0x35, 0xEB, 0x6B, 0xC2, 0xDF, 0x46, 0x18, 0x08,
                0x00, 0x00, // Value
            ]
        );

        // An Enumeration with value 255:
        // 42 00 20 | 05 | 00 00 00 04 | 00 00 00 FF 00 00 00 00
        let variant = KmipEnumerationVariant {
            value: 255,
            name: "TestEnum".to_owned(),
        };
        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::CompromiseDate.to_string(),
            value: TTLValue::Enumeration(variant),
        };
        buffer.clear();
        serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();
        assert_eq!(
            buffer,
            vec![
                0x42, 0x00, 0x20, // Tag
                0x05, // Type
                0x00, 0x00, 0x00, 0x04, // Length
                0x00, 0x00, 0x00, 0xFF, // Value
                0x00, 0x00, 0x00, 0x00, // Padding
            ]
        );

        // A Boolean with the value True:
        // 42 00 20 | 06 | 00 00 00 08 | 00 00 00 00 00 00 00 01
        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::CompromiseDate.to_string(),
            value: TTLValue::Boolean(true),
        };
        buffer.clear();
        serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();
        assert_eq!(
            buffer,
            vec![
                0x42, 0x00, 0x20, // Tag
                0x06, // Type
                0x00, 0x00, 0x00, 0x08, // Length
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Value
            ]
        );

        // A Text String with the value "Hello World":
        // 42 00 20 | 07 | 00 00 00 0B | 48 65 6C 6C 6F 20 57 6F 72 6C 64 00 00 00 00 00
        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::CompromiseDate.to_string(),
            value: TTLValue::TextString("Hello World".to_owned()),
        };
        buffer.clear();
        serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();
        assert_eq!(
            buffer,
            vec![
                0x42, 0x00, 0x20, // Tag
                0x07, // Type
                0x00, 0x00, 0x00, 0x0B, // Length
                0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x00, 0x00, 0x00,
                0x00, 0x00, // Value + Padding
            ]
        );

        // A Byte String with the value { 0x01, 0x02, 0x03 }:
        // 42 00 20 | 08 | 00 00 00 03 | 01 02 03 00 00 00 00 00
        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::CompromiseDate.to_string(),
            value: TTLValue::ByteString(vec![0x01, 0x02, 0x03]),
        };
        buffer.clear();
        serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();
        assert_eq!(
            buffer,
            vec![
                0x42, 0x00, 0x20, // Tag
                0x08, // Type
                0x00, 0x00, 0x00, 0x03, // Length
                0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, // Value + Padding
            ]
        );

        // A Date-Time, containing the value for Friday, March 14, 2008, 11:56:40 GMT:
        // 42 00 20 | 09 | 00 00 00 08 | 00 00 00 00 47 DA 67 F8
        let dt = datetime!(2008-03-14 11:56:40 UTC);
        // let dt = OffsetDateTime::from_unix_timestamp(1205499400).unwrap();
        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::CompromiseDate.to_string(),
            value: TTLValue::DateTime(dt),
        };
        buffer.clear();
        serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();
        assert_eq!(
            buffer,
            vec![
                0x42, 0x00, 0x20, // Tag
                0x09, // Type
                0x00, 0x00, 0x00, 0x08, // Length
                0x00, 0x00, 0x00, 0x00, 0x47, 0xDA, 0x67, 0xF8, // Value
            ]
        );

        // An Interval, containing the value for 10 days:
        // 42 00 20 | 0A | 00 00 00 04 | 00 0D 2F 00 00 00 00 00
        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::CompromiseDate.to_string(),
            value: TTLValue::Interval(864_000), // 10 days in seconds
        };
        buffer.clear();
        serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();
        assert_eq!(
            buffer,
            vec![
                0x42, 0x00, 0x20, // Tag
                0x0A, // Type
                0x00, 0x00, 0x00, 0x04, // Length
                0x00, 0x0D, 0x2F, 0x00, // Value
                0x00, 0x00, 0x00, 0x00, // Padding
            ]
        );

        // A Structure containing an Enumeration, value 254, followed by an Integer, value 255:
        // 42 00 20 | 01 | 00 00 00 20 |
        // 42 00 04 | 05 | 00 00 00 04 | 00 00 00 FE 00 00 00 00 |
        // 42 00 05 | 02 | 00 00 00 04 | 00 00 00 FF 00 00 00 00
        let enum_variant = KmipEnumerationVariant {
            value: 254,
            name: "TestEnum".to_owned(),
        };
        let ttlv_enum = TTLV {
            tag: kmip_1_4::kmip_types::Tag::ApplicationSpecificInformation.to_string(), // "420004", Custom tag from example
            value: TTLValue::Enumeration(enum_variant),
        };
        let ttlv_int = TTLV {
            tag: kmip_1_4::kmip_types::Tag::ArchiveDate.to_string(), //"420005", Custom tag from example
            value: TTLValue::Integer(255),
        };
        let ttlv = TTLV {
            tag: kmip_1_4::kmip_types::Tag::CompromiseDate.to_string(),
            value: TTLValue::Structure(vec![ttlv_enum, ttlv_int]),
        };
        buffer.clear();
        serializer = TTLVBytesSerializer::new(&mut buffer);
        serializer
            .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
            .unwrap();
        assert_eq!(
            buffer,
            vec![
                0x42, 0x00, 0x20, // Tag
                0x01, // Type
                0x00, 0x00, 0x00, 0x20, // Length
                // First nested item (Enumeration)
                0x42, 0x00, 0x04, // Tag
                0x05, // Type
                0x00, 0x00, 0x00, 0x04, // Length
                0x00, 0x00, 0x00, 0xFE, // Value
                0x00, 0x00, 0x00, 0x00, // Padding
                // Second nested item (Integer)
                0x42, 0x00, 0x05, // Tag
                0x02, // Type
                0x00, 0x00, 0x00, 0x04, // Length
                0x00, 0x00, 0x00, 0xFF, // Value
                0x00, 0x00, 0x00, 0x00, // Padding
            ]
        );
    }
}

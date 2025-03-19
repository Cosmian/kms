use std::io::Write;

use crate::ttlv::{error::TtlvError, TTLValue, TtlvType, TTLV};

/// This trait is used to define the KMIP 1.4 and KMIP 2.1 tags that can be used in TTLV serialization
pub trait KmipTag: TryFrom<u32> + Into<u32> + TryFrom<String> + ToString {}

/// Write a tag as a 3-byte big-endian integer
fn write_tag<W: Write, TAG: strum::EnumString + Into<u32>>(
    writer: &mut W,
    tag_str: &str,
) -> Result<(), TtlvError> {
    let tag = TAG::try_from(tag_str.to_owned())
        .map_err(|_e| TtlvError::from(format!("Unknown tag: {tag_str}")))?;
    let tag_value: u32 = tag.into();
    let tag_bytes = tag_value.to_be_bytes();
    // Write only the lowest 3 bytes in big-endian
    writer.write_all(&tag_bytes[1..])?;
    Ok(())
}

/// Write a type as a 1-byte integer
fn write_type<W: Write>(writer: &mut W, item_type: TtlvType) -> Result<(), TtlvError> {
    // Clippy doesn't like the as conversion, but it's safe here
    #[allow(clippy::as_conversions)]
    writer.write_all(&[item_type as u8])?;
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
            }
            TTLValue::Boolean(value) => {
                write_type(&mut self.writer, TtlvType::Boolean)?;
                write_length(&mut self.writer, 8)?;
                let mut buf = [0_u8; 8];
                buf[7] = u8::from(*value);
                self.writer.write_all(&buf)?;
            }
            TTLValue::TextString(value) => {
                write_type(&mut self.writer, TtlvType::TextString)?;
                write_length(&mut self.writer, value.len())?;
                self.writer.write_all(value.as_bytes())?;
            }
            TTLValue::ByteString(value) => {
                write_type(&mut self.writer, TtlvType::ByteString)?;
                write_length(&mut self.writer, value.len())?;
                self.writer.write_all(value)?;
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
            }
            TTLValue::DateTimeExtended(value) => {
                write_type(&mut self.writer, TtlvType::DateTimeExtended)?;
                write_length(&mut self.writer, 8)?;
                self.writer.write_all(&value.to_be_bytes())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{kmip_1_4, kmip_2_1, ttlv::wire::ttlv_bytes_serializer::write_tag};

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
}

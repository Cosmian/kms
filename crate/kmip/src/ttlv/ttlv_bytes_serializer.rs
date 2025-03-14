use std::io::Write;

use super::{error::TtlvError, TTLValue, TtlvType, TTLV};

/// This trait is used to define the KMIP 1.4 and KMIP 2.1 tags that can be used in TTLV serialization
pub trait KmipTag: TryFrom<u32> + Into<u32> + TryFrom<String> + std::string::ToString {}

/// Write a tag as a 3-byte big-endian integer
fn write_tag<W: Write, TAG: KmipTag>(writer: &mut W, tag_str: &str) -> Result<(), TtlvError> {
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
                let bytes = value.to_bytes_be();
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

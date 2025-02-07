use std::io::{Read, Write};

use time::OffsetDateTime;

use super::{error::TtlvError, ItemTypeEnumeration, TTLValue, TTLV};
use crate::kmip_2_1::kmip_types::Tag;

// /// Serialize a TTLV structure into a bytes sequence following KMIP 10.1 spec
// pub fn to_writer<W, T>(writer: &mut W, value: &T) -> Result<, TtlvError()>
// where
//     W: Write,
//     T: Serialize,
// {
//     let mut serializer = TTLVSerializer::new(writer);
//     value.serialize(&mut serializer)
// }

/// Write a tag as a 3-byte big-endian integer
fn write_tag<W: Write>(writer: &mut W, tag_str: &str) -> Result<(), TtlvError> {
    let tag = Tag::try_from(tag_str)?;
    let tag_value = tag as u32;
    // Write only the lowest 3 bytes in big-endian
    let buf = [
        (tag_value >> 16) as u8,
        (tag_value >> 8) as u8,
        tag_value as u8,
    ];
    writer.write_all(&buf)?;
    Ok(())
}

/// Write a type as a 1-byte integer
fn write_type<W: Write>(writer: &mut W, item_type: ItemTypeEnumeration) -> Result<(), TtlvError> {
    writer.write_all(&[item_type as u8])?;
    Ok(())
}

/// Write a length as a 4-byte big-endian integer
fn write_length<W: Write>(writer: &mut W, length: u32) -> Result<(), TtlvError> {
    writer.write_all(&length.to_be_bytes())?;
    Ok(())
}

pub struct TTLVSerializer<W> {
    writer: W,
}

impl<W> TTLVSerializer<W>
where
    W: Write,
{
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    fn write_ttlv(&mut self, ttlv: &TTLV) -> Result<(), TtlvError> {
        // Write Tag (3 bytes)
        write_tag(&mut self.writer, &ttlv.tag)?;

        match &ttlv.value {
            TTLValue::Structure(items) => {
                // Write Type (1 byte)
                write_type(&mut self.writer, ItemTypeEnumeration::Structure)?;

                // Calculate total length of nested items
                let mut temp_buffer = Vec::new();
                let mut temp_serializer = TTLVSerializer::new(&mut temp_buffer);
                for item in items {
                    temp_serializer.write_ttlv(item)?;
                }

                // Write Length (4 bytes)
                write_length(&mut self.writer, temp_buffer.len() as u32)?;

                // Write actual nested items
                self.writer.write_all(&temp_buffer)?;
            }
            TTLValue::Integer(value) => {
                write_type(&mut self.writer, ItemTypeEnumeration::Integer)?;
                write_length(&mut self.writer, 4)?;
                self.writer.write_all(&value.to_be_bytes())?;
            }
            TTLValue::BitMask(value) => {
                write_type(&mut self.writer, ItemTypeEnumeration::Integer)?;
                write_length(&mut self.writer, 4)?;
                self.writer.write_all(&value.to_be_bytes())?;
            }
            TTLValue::LongInteger(value) => {
                write_type(&mut self.writer, ItemTypeEnumeration::LongInteger)?;
                write_length(&mut self.writer, 8)?;
                self.writer.write_all(&value.to_be_bytes())?;
            }
            TTLValue::BigInteger(value) => {
                let bytes = value.to_bytes_be();
                write_type(&mut self.writer, ItemTypeEnumeration::BigInteger)?;
                write_length(&mut self.writer, bytes.len() as u32)?;
                self.writer.write_all(&bytes)?;
            }
            TTLValue::Enumeration(value) => {
                write_type(&mut self.writer, ItemTypeEnumeration::Enumeration)?;
                write_length(&mut self.writer, 4)?;
                match value {
                    super::TTLVEnumeration::Integer(i) => {
                        self.writer.write_all(&i.to_be_bytes())?
                    }
                    super::TTLVEnumeration::Name(_) => {
                        return Err(TtlvError::from(
                            "Enumeration names not supported in TTLV format",
                        ))
                    }
                }
            }
            TTLValue::Boolean(value) => {
                write_type(&mut self.writer, ItemTypeEnumeration::Boolean)?;
                write_length(&mut self.writer, 8)?;
                let mut buf = [0_u8; 8];
                buf[7] = if *value { 1 } else { 0 };
                self.writer.write_all(&buf)?;
            }
            TTLValue::TextString(value) => {
                write_type(&mut self.writer, ItemTypeEnumeration::TextString)?;
                write_length(&mut self.writer, value.len() as u32)?;
                self.writer.write_all(value.as_bytes())?;
            }
            TTLValue::ByteString(value) => {
                write_type(&mut self.writer, ItemTypeEnumeration::ByteString)?;
                write_length(&mut self.writer, value.len() as u32)?;
                self.writer.write_all(value)?;
            }
            TTLValue::DateTime(value) => {
                write_type(&mut self.writer, ItemTypeEnumeration::DateTime)?;
                write_length(&mut self.writer, 8)?;
                self.writer
                    .write_all(&value.unix_timestamp().to_be_bytes())?;
            }
            TTLValue::Interval(value) => {
                write_type(&mut self.writer, ItemTypeEnumeration::Interval)?;
                write_length(&mut self.writer, 4)?;
                self.writer.write_all(&value.to_be_bytes())?;
            }
            TTLValue::DateTimeExtended(value) => {
                write_type(&mut self.writer, ItemTypeEnumeration::DateTimeExtended)?;
                write_length(&mut self.writer, 8)?;
                self.writer
                    .write_all(&((value.unix_timestamp_nanos() / 1000) as u64).to_be_bytes())?;
            }
        }
        Ok(())
    }
}

// /// Deserialize from a reader implementing Read into a TTLV structure
// pub fn from_reader<R, T>(reader: &mut R) -> Result<T>
// wh, TtlvErrorere
//     R: Read,
//     T: for<'de> serde::Deserialize<'de>,
// {
//     let mut deserializer = TTLVDeserializer::new(reader);
//     T::deserialize(&mut deserializer).map_err(|e| KmipError::DeserializationError(e.to_string()))
// }

pub struct TTLVDeserializer<R> {
    reader: R,
}

impl<R> TTLVDeserializer<R>
where
    R: Read,
{
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    fn read_ttlv(&mut self) -> Result<TTLV, TtlvError> {
        // Read Tag (3 bytes)
        let mut tag_bytes = [0u8; 3];
        self.reader.read_exact(&mut tag_bytes)?;
        let tag_value =
            u32::from(tag_bytes[0]) << 16 | u32::from(tag_bytes[1]) << 8 | u32::from(tag_bytes[2]);
        let tag = Tag::try_from(tag_value)?;

        // Read Type (1 byte)
        let mut type_byte = [0_u8; 1];
        self.reader.read_exact(&mut type_byte)?;
        let item_type = ItemTypeEnumeration::try_from(type_byte[0])?;

        // Read Length (4 bytes)
        let mut buf4 = [0_u8; 4];
        let length = self.reader.read_exact(&mut buf4)?;
        let length = u32::from_be_bytes(buf4);

        // Read Value based on type
        let value = match item_type {
            ItemTypeEnumeration::Structure => {
                let mut items = Vec::new();
                let mut remaining = length;
                while remaining > 0 {
                    let item = self.read_ttlv()?;
                    remaining -= item_size(&item)?;
                    items.push(item);
                }
                TTLValue::Structure(items)
            }
            ItemTypeEnumeration::Integer => {
                let mut buf4 = [0_u8; 4];
                self.reader.read_exact(&mut buf4)?;
                TTLValue::Integer(i32::from_be_bytes(buf4))
            }
            ItemTypeEnumeration::LongInteger => {
                let mut buf8 = [0_u8; 8];
                self.reader.read_exact(&mut buf8)?;
                TTLValue::LongInteger(i64::from_be_bytes(buf8))
            }
            ItemTypeEnumeration::BigInteger => {
                let mut buf = vec![0_u8; length as usize];
                self.reader.read_exact(&mut buf)?;
                TTLValue::BigInteger(num_bigint_dig::BigUint::from_bytes_be(&buf))
            }
            ItemTypeEnumeration::Enumeration => {
                let mut buf4 = [0_u8; 4];
                self.reader.read_exact(&mut buf4)?;
                TTLValue::Enumeration(super::TTLVEnumeration::Integer(i32::from_be_bytes(buf4)))
            }
            ItemTypeEnumeration::Boolean => {
                let mut buf8 = [0_u8; 8];
                self.reader.read_exact(&mut buf8)?;
                TTLValue::Boolean(buf8[7] != 0)
            }
            ItemTypeEnumeration::TextString => {
                let mut buf = vec![0_u8; length as usize];
                self.reader.read_exact(&mut buf)?;
                TTLValue::TextString(String::from_utf8(buf)?)
            }
            ItemTypeEnumeration::ByteString => {
                let mut buf = vec![0_u8; length as usize];
                self.reader.read_exact(&mut buf)?;
                TTLValue::ByteString(buf)
            }
            ItemTypeEnumeration::DateTime => {
                let mut buf8 = [0_u8; 8];
                self.reader.read_exact(&mut buf8)?;
                let timestamp = i64::from_be_bytes(buf8);
                let t = OffsetDateTime::from_unix_timestamp(timestamp)?;
                TTLValue::DateTime(t)
            }
            ItemTypeEnumeration::Interval => {
                let mut buf4 = [0_u8; 4];
                self.reader.read_exact(&mut buf4)?;
                TTLValue::Interval(u32::from_be_bytes(buf4))
            }
            ItemTypeEnumeration::DateTimeExtended => {
                let mut buf8 = [0_u8; 8];
                self.reader.read_exact(&mut buf8)?;
                let micros = u64::from_be_bytes(buf8);
                TTLValue::DateTimeExtended(
                    chrono::DateTime::from_timestamp(
                        (micros / 1_000_000) as i64,
                        ((micros % 1_000_000) * 1000) as u32,
                    )
                    .unwrap(),
                )
            }
            ItemTypeEnumeration::BitMask => {
                let mut buf4 = [0_u8; 4];
                self.reader.read_exact(&mut buf4)?;
                TTLValue::BitMask(u32::from_be_bytes(buf4))
            }
            v => return Err(TtlvError::from(format!("Unsupported type: {v:?}"))),
        };

        Ok(TTLV {
            tag: tag.to_string(),
            value,
        })
    }
}

/// Calculate the total size of a TTLV item including its tag, type, length, and value
fn item_size(ttlv: &TTLV) -> Result<u32, TtlvError> {
    // 8 bytes for tag (3), type (1), and length (4)
    let mut size = 8;

    size += match &ttlv.value {
        TTLValue::Structure(items) => {
            let mut struct_size = 0;
            for item in items {
                struct_size += item_size(item)?;
            }
            struct_size
        }
        TTLValue::Integer(_) | TTLValue::BitMask(_) => 4,
        TTLValue::LongInteger(_) | TTLValue::DateTimeExtended(_) | TTLValue::DateTime(_) => 8,
        TTLValue::BigInteger(value) => value.to_bytes_be().len() as u32,
        TTLValue::Enumeration(_) => 4,
        TTLValue::Boolean(_) => 8,
        TTLValue::TextString(value) => value.len() as u32,
        TTLValue::ByteString(value) => value.len() as u32,
        TTLValue::Interval(_) => 4,
    };

    Ok(size)
}

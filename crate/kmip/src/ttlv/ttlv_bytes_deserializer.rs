use std::io::Read;

use time::OffsetDateTime;

use super::{error::TtlvError, kmip_big_int::KmipBigInt, TTLValue, TtlvType, TTLV};

// /// Deserialize from a reader implementing Read into a TTLV structure
// pub fn from_reader<R, T>(reader: &mut R) -> Result<T>
// wh, TtlvErrorere
//     R: Read,
//     T: for<'de> serde::Deserialize<'de>,
// {
//     let mut deserializer = TTLVDeserializer::new(reader);
//     T::deserialize(&mut deserializer).map_err(|e| KmipError::DeserializationError(e.to_string()))
// }

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

    pub fn read_ttlv<TAG: TryFrom<u32> + std::string::ToString>(
        &mut self,
    ) -> Result<TTLV, TtlvError> {
        // Read Tag (3 bytes)
        let mut tag_bytes = [0_u8; 3];
        self.reader.read_exact(&mut tag_bytes)?;
        let tag_value =
            u32::from(tag_bytes[0]) << 16 | u32::from(tag_bytes[1]) << 8 | u32::from(tag_bytes[2]);
        let tag = TAG::try_from(tag_value)
            .map_err(|_e| TtlvError::from(format!("Invalid tag number: {tag_value}")))?;

        // Read Type (1 byte)
        let mut type_byte = [0_u8; 1];
        self.reader.read_exact(&mut type_byte)?;
        let item_type = TtlvType::try_from(type_byte[0])?;

        // Read Length (4 bytes)
        let mut buf4 = [0_u8; 4];
        self.reader.read_exact(&mut buf4)?;
        let length = u32::from_be_bytes(buf4);
        // convert to usize
        let length = usize::try_from(length)
            .map_err(|_e| TtlvError::from(format!("Length too large: {length}")))?;

        // Read Value based on type
        let value = match item_type {
            TtlvType::Structure => {
                let mut items = Vec::new();
                let mut remaining = length;
                while remaining > 0 {
                    let item = self.read_ttlv::<TAG>()?;
                    remaining -= item_size(&item)?;
                    items.push(item);
                }
                TTLValue::Structure(items)
            }
            TtlvType::Integer => {
                let mut buf4 = [0_u8; 4];
                self.reader.read_exact(&mut buf4)?;
                TTLValue::Integer(i32::from_be_bytes(buf4))
            }
            TtlvType::LongInteger => {
                let mut buf8 = [0_u8; 8];
                self.reader.read_exact(&mut buf8)?;
                TTLValue::LongInteger(i64::from_be_bytes(buf8))
            }
            TtlvType::BigInteger => {
                let mut buf = vec![0_u8; length];
                self.reader.read_exact(&mut buf)?;

                TTLValue::BigInteger(KmipBigInt::from_bytes_be(&buf))
            }
            TtlvType::Enumeration => {
                let mut buf4 = [0_u8; 4];
                self.reader.read_exact(&mut buf4)?;
                TTLValue::Enumeration(super::KmipEnumerationVariant {
                    value: u32::from_be_bytes(buf4),
                    name: String::new(),
                })
            }
            TtlvType::Boolean => {
                let mut buf8 = [0_u8; 8];
                self.reader.read_exact(&mut buf8)?;
                TTLValue::Boolean(buf8[7] != 0)
            }
            TtlvType::TextString => {
                let mut buf = vec![0_u8; length];
                self.reader.read_exact(&mut buf)?;
                TTLValue::TextString(String::from_utf8(buf)?)
            }
            TtlvType::ByteString => {
                let mut buf = vec![0_u8; length];
                self.reader.read_exact(&mut buf)?;
                TTLValue::ByteString(buf)
            }
            TtlvType::DateTime => {
                let mut buf8 = [0_u8; 8];
                self.reader.read_exact(&mut buf8)?;
                let timestamp = i64::from_be_bytes(buf8);
                let t = OffsetDateTime::from_unix_timestamp(timestamp)?;
                TTLValue::DateTime(t)
            }
            TtlvType::Interval => {
                let mut buf4 = [0_u8; 4];
                self.reader.read_exact(&mut buf4)?;
                TTLValue::Interval(u32::from_be_bytes(buf4))
            }
            TtlvType::DateTimeExtended => {
                let mut buf8 = [0_u8; 8];
                self.reader.read_exact(&mut buf8)?;
                let micros = i64::from_be_bytes(buf8);
                TTLValue::DateTimeExtended(i128::from(micros))
            }
        };

        Ok(TTLV {
            tag: tag.to_string(),
            value,
        })
    }
}

/// Calculate the total size of a TTLV item including its tag, type, length, and value
fn item_size(ttlv: &TTLV) -> Result<usize, TtlvError> {
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
        TTLValue::Integer(_) | TTLValue::Enumeration(_) | TTLValue::Interval(_) => 4,
        TTLValue::LongInteger(_)
        | TTLValue::DateTimeExtended(_)
        | TTLValue::DateTime(_)
        | TTLValue::Boolean(_) => 8,
        TTLValue::BigInteger(value) => value.to_bytes_be().len(),
        TTLValue::TextString(value) => value.len(),
        TTLValue::ByteString(value) => value.len(),
    };

    Ok(size)
}

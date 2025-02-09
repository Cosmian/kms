use std::io::{Read, Write};

use time::OffsetDateTime;

use super::{error::TtlvError, kmip_big_int::KmipBigInt, ItemTypeEnumeration, TTLValue, TTLV};

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
fn write_type<W: Write>(writer: &mut W, item_type: ItemTypeEnumeration) -> Result<(), TtlvError> {
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

pub struct TTLVSerializer<W> {
    writer: W,
}

impl<W> TTLVSerializer<W>
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
                write_type(&mut self.writer, ItemTypeEnumeration::Structure)?;

                // Calculate total length of nested items
                let mut temp_buffer = Vec::new();
                let mut temp_serializer = TTLVSerializer::new(&mut temp_buffer);
                for item in items {
                    temp_serializer.write_ttlv::<TAG>(item)?;
                }

                // Write Length (4 bytes)
                write_length(&mut self.writer, temp_buffer.len())?;

                // Write actual nested items
                self.writer.write_all(&temp_buffer)?;
            }
            TTLValue::Integer(value) => {
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
                write_length(&mut self.writer, bytes.len())?;
                self.writer.write_all(&bytes)?;
            }
            TTLValue::Enumeration(value) => {
                write_type(&mut self.writer, ItemTypeEnumeration::Enumeration)?;
                write_length(&mut self.writer, 4)?;
                match value {
                    super::TTLVEnumeration::Integer(i) => {
                        self.writer.write_all(&i.to_be_bytes())?;
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
                buf[7] = u8::from(*value);
                self.writer.write_all(&buf)?;
            }
            TTLValue::TextString(value) => {
                write_type(&mut self.writer, ItemTypeEnumeration::TextString)?;
                write_length(&mut self.writer, value.len())?;
                self.writer.write_all(value.as_bytes())?;
            }
            TTLValue::ByteString(value) => {
                write_type(&mut self.writer, ItemTypeEnumeration::ByteString)?;
                write_length(&mut self.writer, value.len())?;
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
                let t = u64::try_from(value.unix_timestamp_nanos() / 1000)
                    .map_err(|_e| TtlvError::from(format!("Timestamp too large: {value}")))?;
                self.writer.write_all(&t.to_be_bytes())?;
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
        let item_type = ItemTypeEnumeration::try_from(type_byte[0])?;

        // Read Length (4 bytes)
        let mut buf4 = [0_u8; 4];
        self.reader.read_exact(&mut buf4)?;
        let length = u32::from_be_bytes(buf4);
        // convert to usize
        let length = usize::try_from(length)
            .map_err(|_e| TtlvError::from(format!("Length too large: {length}")))?;

        // Read Value based on type
        let value = match item_type {
            ItemTypeEnumeration::Structure => {
                let mut items = Vec::new();
                let mut remaining = length;
                while remaining > 0 {
                    let item = self.read_ttlv::<TAG>()?;
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
                let mut buf = vec![0_u8; length];
                self.reader.read_exact(&mut buf)?;

                TTLValue::BigInteger(KmipBigInt::from_bytes_be(&buf))
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
                let mut buf = vec![0_u8; length];
                self.reader.read_exact(&mut buf)?;
                TTLValue::TextString(String::from_utf8(buf)?)
            }
            ItemTypeEnumeration::ByteString => {
                let mut buf = vec![0_u8; length];
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
                let micros = i64::from_be_bytes(buf8);
                let t: OffsetDateTime =
                    OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros))?;
                TTLValue::DateTimeExtended(t)
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::panic)]
mod tests {

    use std::io::Cursor;

    use num_bigint_dig::BigInt;
    use strum::Display;

    use super::*;

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
                value: TTLValue::DateTime(
                    OffsetDateTime::from_unix_timestamp(1_234_567_890).unwrap(),
                ),
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
            let mut serializer = TTLVSerializer::new(&mut buffer);
            serializer.write_ttlv::<TestTag>(&test_case).unwrap();

            let mut deserializer = TTLVDeserializer::new(Cursor::new(&buffer));
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
}

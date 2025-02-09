use time::OffsetDateTime;

use super::{error::TtlvError, kmip_big_int::KmipBigInt};

#[derive(PartialEq, Debug, Clone, Default)]
pub struct TTLV {
    pub tag: String,
    pub value: TTLValue,
}

#[derive(Debug, Clone)]
pub enum TTLValue {
    Structure(Vec<TTLV>),
    Integer(i32),
    LongInteger(i64),
    BigInteger(KmipBigInt),
    Enumeration(TTLVEnumeration),
    Boolean(bool),
    TextString(String),
    ByteString(Vec<u8>),
    DateTime(OffsetDateTime),
    Interval(u32),
    DateTimeExtended(OffsetDateTime),
}

impl Default for TTLValue {
    fn default() -> Self {
        Self::TextString(String::default())
    }
}

impl PartialEq for TTLValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Structure(l0), Self::Structure(r0)) => l0 == r0,
            (Self::Integer(l0), Self::Integer(r0)) => l0 == r0,
            (Self::LongInteger(l0), Self::LongInteger(r0)) => l0 == r0,
            (Self::BigInteger(l0), Self::BigInteger(r0)) => l0 == r0,
            (Self::Enumeration(l0), Self::Enumeration(r0)) => l0 == r0,
            (Self::Boolean(l0), Self::Boolean(r0)) => l0 == r0,
            (Self::TextString(l0), Self::TextString(r0)) => l0 == r0,
            (Self::ByteString(l0), Self::ByteString(r0)) => l0 == r0,
            (Self::DateTime(l0), Self::DateTime(r0)) => l0.unix_timestamp() == r0.unix_timestamp(),
            (Self::Interval(l0), Self::Interval(r0)) => l0 == r0,
            (Self::DateTimeExtended(l0), Self::DateTimeExtended(r0)) => {
                l0.unix_timestamp_nanos() / 1000 == r0.unix_timestamp_nanos() / 1000
            }
            (_, _) => false,
        }
    }
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub enum TTLVEnumeration {
    Integer(i32),
    Name(String),
}

pub enum ItemTypeEnumeration {
    Structure = 0x01,
    Integer = 0x02,
    LongInteger = 0x03,
    BigInteger = 0x04,
    Enumeration = 0x05,
    Boolean = 0x06,
    TextString = 0x07,
    ByteString = 0x08,
    DateTime = 0x09,
    Interval = 0x0A,
    DateTimeExtended = 0x0B,
}

impl TryFrom<u8> for ItemTypeEnumeration {
    type Error = TtlvError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Structure),
            0x02 => Ok(Self::Integer),
            0x03 => Ok(Self::LongInteger),
            0x04 => Ok(Self::BigInteger),
            0x05 => Ok(Self::Enumeration),
            0x06 => Ok(Self::Boolean),
            0x07 => Ok(Self::TextString),
            0x08 => Ok(Self::ByteString),
            0x09 => Ok(Self::DateTime),
            0x0A => Ok(Self::Interval),
            0x0B => Ok(Self::DateTimeExtended),
            _ => Err(TtlvError::from(format!("Invalid type byte: {value}"))),
        }
    }
}

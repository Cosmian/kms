use std::fmt::Debug;

use time::OffsetDateTime;

use super::{
    TTLVBytesDeserializer, TTLVBytesSerializer, error::TtlvError, kmip_big_int::KmipBigInt,
};
use crate::{KmipResultHelper, kmip_1_4, kmip_2_1};

#[derive(Debug, Copy, Clone)]
pub enum KmipFlavor {
    Kmip1,
    Kmip2,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TTLV {
    pub tag: String,
    pub value: TTLValue,
}

impl TTLV {
    pub fn find_version(bytes: &[u8]) -> Result<(i32, i32), TtlvError> {
        let mut major: i32 = i32::MAX;
        let mut minor: i32 = i32::MAX;
        let mut i = 0;
        while i < bytes.len() {
            if major != i32::MAX && minor != i32::MAX {
                // found them
                break;
            }
            if bytes.get(i..i + 8) == Some(&[0x42, 0x00, 0x6a, 0x02, 0x00, 0x00, 0x00, 0x04]) {
                // we found the protocol version major
                i += 8;
                // read the nez 4 bytes
                let Some(major_be) = bytes.get(i..i + 4) else {
                    return Err(TtlvError::from("Invalid KMIP version"));
                };
                major = i32::from_be_bytes(
                    major_be
                        .try_into()
                        .context("failed reading the major version")?,
                );
                i += 8;
            }
            if bytes.get(i..i + 8) == Some(&[0x42, 0x00, 0x6b, 0x02, 0x00, 0x00, 0x00, 0x04]) {
                // we found the protocol version minor
                i += 8;
                // read the nez 4 bytes
                let Some(minor_be) = bytes.get(i..i + 4) else {
                    return Err(TtlvError::from("Invalid KMIP version"));
                };
                minor = i32::from_be_bytes(
                    minor_be
                        .try_into()
                        .context("failed reading the minor version")?,
                );
            }
            i += 8;
        }
        Ok((major, minor))
    }

    pub fn to_bytes(&self, kmip_flavor: KmipFlavor) -> Result<Vec<u8>, TtlvError> {
        let mut writer = Vec::new();
        match kmip_flavor {
            KmipFlavor::Kmip1 => TTLVBytesSerializer::new(&mut writer)
                .write_ttlv::<kmip_1_4::kmip_types::Tag>(self)?,
            KmipFlavor::Kmip2 => TTLVBytesSerializer::new(&mut writer)
                .write_ttlv::<kmip_2_1::kmip_types::Tag>(self)?,
        }
        Ok(writer)
    }

    pub fn from_bytes(bytes: &[u8], kmip_flavor: KmipFlavor) -> Result<Self, TtlvError> {
        let (ttlv, _) = match kmip_flavor {
            KmipFlavor::Kmip1 => {
                TTLVBytesDeserializer::new(bytes).read_ttlv::<kmip_1_4::kmip_types::Tag>()?
            }
            KmipFlavor::Kmip2 => {
                TTLVBytesDeserializer::new(bytes).read_ttlv::<kmip_2_1::kmip_types::Tag>()?
            }
        };
        Ok(ttlv)
    }
}

#[derive(Debug, Clone, Eq)]
pub enum TTLValue {
    Structure(Vec<TTLV>),
    Integer(i32),
    LongInteger(i64),
    BigInteger(KmipBigInt),
    Enumeration(KmipEnumerationVariant),
    Boolean(bool),
    TextString(String),
    ByteString(Vec<u8>),
    DateTime(OffsetDateTime),
    Interval(u32),
    DateTimeExtended(i128),
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
            (Self::DateTimeExtended(l0), Self::DateTimeExtended(r0)) => l0 == r0,
            (_, _) => false,
        }
    }
}

/// This holds the KMIP enumeration variant value and name
/// JSON uses the name, the byte serializer uses the value
#[derive(Clone)]
pub struct KmipEnumerationVariant {
    pub value: u32,
    pub name: String,
}

impl Debug for KmipEnumerationVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KmipEnumerationVariant")
            .field("value", &format!("0x{:08x}", self.value))
            .field("name", &self.name)
            .finish()
    }
}

/// Two KMIP enumeration variants are equal if their names are equal
/// or if their values are equal
///
/// # Explanation
/// When serializing a TTLV from a KMIP Object which has an enumeration using
/// the `KmipEnumerationSerialize` derivation, both the name and the value
/// are serialized and will be present in the TTLV Output.
/// However, JSON serialization of the TTLV will only serialize the name and not the value.
/// Therefore, when deserializing from JSON, the value will be missing.
impl PartialEq for KmipEnumerationVariant {
    fn eq(&self, other: &Self) -> bool {
        if self.name.is_empty() || other.name.is_empty() {
            return self.value == other.value;
        }
        self.name == other.name
    }
}
impl Eq for KmipEnumerationVariant {}

pub enum TtlvType {
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

impl TtlvType {
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Structure => 0x01,
            Self::Integer => 0x02,
            Self::LongInteger => 0x03,
            Self::BigInteger => 0x04,
            Self::Enumeration => 0x05,
            Self::Boolean => 0x06,
            Self::TextString => 0x07,
            Self::ByteString => 0x08,
            Self::DateTime => 0x09,
            Self::Interval => 0x0A,
            Self::DateTimeExtended => 0x0B,
        }
    }
}

impl TryFrom<u8> for TtlvType {
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

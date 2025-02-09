//! TTLV (Tag, Type, Length, Value) implementation for KMIP protocol
//!
//! This module provides the core TTLV data structures and their serialization/deserialization implementations
//! for the KMIP (Key Management Interoperability Protocol) protocol.
//!
//! # Key Components
//!
//! * `ItemTypeEnumeration` - Defines the possible TTLV data types according to KMIP specification
//! * `TTLVEnumeration` - Represents enumeration values that can be either integers or named strings
//! * `TTLValue` - The main enum containing all possible TTLV value types
//! * `TTLV` - The complete TTLV structure combining a tag and its value
//!
//! # Value Types
//!
//! The module supports various KMIP data types including:
//! - Structure (nested TTLV objects)
//! - Integer types (32-bit, 64-bit, and arbitrary precision)
//! - Bitmasks
//! - Enumerations
//! - Boolean values
//! - Text and byte strings
//! - Date/time values (with standard and extended precision)
//! - Intervals
//!
//! # Serialization
//!
//! The module implements Serde's `Serialize` and `Deserialize` traits for all major types,
//! supporting both binary and text-based formats. Special handling is provided for:
//!
//! - Hexadecimal representations of integers and bitmasks
//! - ISO-8601 datetime formatting
//! - Extended precision timestamps
//! - Big integer conversion and padding
//!
//! # Examples
//!
//! ```no_run
//! use kmip::ttlv::{TTLV, TTLValue};
//!
//! // Create a simple text TTLV
//! let ttlv = TTLV {
//!     tag: "TextValue".to_string(),
//!     value: TTLValue::TextString("Hello KMIP".to_string())
//! };
//! ```
//!
//! # Note
//!
//! This implementation follows the KMIP specification for TTLV encoding,
//! ensuring compatibility with KMIP servers and clients. All numeric values
//! are handled in big-endian format as required by the protocol.
pub mod deserializer;
pub mod error;
pub mod kmip_big_int;
pub mod serde_ttlv;
pub mod serializer;

use core::fmt;

use error::TtlvError;
use kmip_big_int::KmipBigInt;
use serde::{
    de::{self, MapAccess, Visitor},
    ser::{self, SerializeStruct, Serializer},
    Deserialize, Serialize,
};
use time::{format_description::well_known::Iso8601, OffsetDateTime};

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::as_conversions,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#[cfg(test)]
mod tests;

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

#[derive(Eq, PartialEq, Debug, Clone)]
pub enum TTLVEnumeration {
    Integer(i32),
    Name(String),
}

impl Serialize for TTLVEnumeration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self {
            Self::Integer(i) => serializer.serialize_i32(*i),
            Self::Name(s) => serializer.serialize_str(s),
        }
    }
}

impl<'de> Deserialize<'de> for TTLVEnumeration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TTLVEnumerationVisitor;

        impl Visitor<'_> for TTLVEnumerationVisitor {
            type Value = TTLVEnumeration;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct TTLVEnumeration")
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(TTLVEnumeration::Integer(v.try_into().map_err(|_e| {
                    de::Error::custom(format!("Unexpected value: {v}, expected a 32 bit integer"))
                })?))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(TTLVEnumeration::Integer(v.try_into().map_err(|_e| {
                    de::Error::custom(format!("Unexpected value: {v}, expected a 32 bit integer"))
                })?))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(TTLVEnumeration::Name(v.to_owned()))
            }
        }
        deserializer.deserialize_any(TTLVEnumerationVisitor)
    }
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

#[derive(PartialEq, Debug, Clone, Default)]
pub struct TTLV {
    pub tag: String,
    pub value: TTLValue,
}

impl Serialize for TTLV {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        fn _serialize<S, T>(
            serializer: S,
            tag: &str,
            typ: &str,
            value: &T,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
            T: Serialize,
        {
            let mut ttlv = serializer.serialize_struct("TTLV", 3)?;
            ttlv.serialize_field("tag", tag)?;
            ttlv.serialize_field("type", typ)?;
            ttlv.serialize_field("value", value)?;
            ttlv.end()
        }

        match &self.value {
            TTLValue::Structure(v) => _serialize(serializer, &self.tag, "Structure", v),
            TTLValue::Integer(v) => _serialize(serializer, &self.tag, "Integer", v),
            TTLValue::LongInteger(v) => _serialize(
                serializer,
                &self.tag,
                "LongInteger",
                &("0x".to_owned() + &hex::encode_upper(v.to_be_bytes())),
            ),
            TTLValue::BigInteger(v) => {
                //TODO Note that Big Integers must be sign extended to
                //TODO  contain a multiple of 8 bytes, and as per LongInteger, JS numbers only
                // support a limited range of values.
                _serialize(
                    serializer,
                    &self.tag,
                    "BigInteger",
                    &("0x".to_owned() + &hex::encode_upper(v.to_bytes_be())),
                )
            }
            TTLValue::Enumeration(v) => _serialize(serializer, &self.tag, "Enumeration", v),
            TTLValue::Boolean(v) => _serialize(serializer, &self.tag, "Boolean", v),
            TTLValue::TextString(v) => _serialize(serializer, &self.tag, "TextString", v),
            TTLValue::ByteString(v) => {
                _serialize(serializer, &self.tag, "ByteString", &hex::encode_upper(v))
            }
            TTLValue::DateTime(v) => _serialize(
                serializer,
                &self.tag,
                "DateTime",
                &v.format(&Iso8601::DEFAULT).map_err(|err| {
                    ser::Error::custom(format!("Cannot format DateTime {v} into ISO8601: {err}"))
                })?,
            ),
            TTLValue::Interval(v) => _serialize(serializer, &self.tag, "Interval", v),
            TTLValue::DateTimeExtended(v) => _serialize(
                serializer,
                &self.tag,
                "DateTimeExtended",
                &("0x".to_owned()
                    + &hex::encode_upper((v.unix_timestamp_nanos() / 1000).to_be_bytes())),
            ),
        }
    }
}

// /// Used to deserialize the "Integer" type
// enum IntegerOrMask {
//     Integer(i32),
//     Mask(u32),
// }

// impl<'de> Deserialize<'de> for IntegerOrMask {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         struct IntegerOrMaskVisitor;

//         impl Visitor<'_> for IntegerOrMaskVisitor {
//             type Value = IntegerOrMask;

//             fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//                 formatter.write_str("struct IntegerOrMask")
//             }

//             fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
//             where
//                 E: de::Error,
//             {
//                 Ok(IntegerOrMask::Integer(v.try_into().map_err(|_e| {
//                     de::Error::custom(format!("Unexpected value: {v}, expected a 32 bit integer"))
//                 })?))
//             }

//             fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
//             where
//                 E: de::Error,
//             {
//                 Ok(IntegerOrMask::Integer(v.try_into().map_err(|_e| {
//                     de::Error::custom(format!(
//                         "Unexpected value: {v}, expected a 64 bit unaigned integer"
//                     ))
//                 })?))
//             }

//             // v is in hexadecimal format
//             fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
//             where
//                 E: de::Error,
//             {
//                 if v.get(0..2).ok_or_else(|| {
//                     de::Error::custom(format!("visit_str: indexing slicing failed for 0..2: {v}"))
//                 })? != "0x"
//                 {
//                     return Err(de::Error::custom(format!("Invalid value for Mask: {v}")))
//                 }
//                 let bytes = hex::decode(v.get(2..).ok_or_else(|| {
//                     de::Error::custom(format!("visit_str: indexing slicing failed for 2..: {v}"))
//                 })?)
//                 .map_err(|_e| de::Error::custom(format!("Invalid value for Mask: {v}")))?;
//                 let m: u32 = u32::from_be_bytes(
//                     bytes
//                         .as_slice()
//                         .try_into()
//                         .map_err(|_e| de::Error::custom(format!("Invalid value for Mask: {v}")))?,
//                 );
//                 Ok(IntegerOrMask::Mask(m))
//             }
//         }
//         deserializer.deserialize_any(IntegerOrMaskVisitor)
//     }
// }

impl<'de> Deserialize<'de> for TTLV {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // see https://serde.rs/deserialize-struct.html

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Tag,
            Type,
            Value,
        }

        struct TTLVVisitor;

        impl<'de> Visitor<'de> for TTLVVisitor {
            type Value = TTLV;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct TTLV")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut tag: Option<String> = None;
                let mut typ: Option<String> = None;
                let mut value: Option<TTLValue> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Tag => {
                            if tag.is_some() {
                                return Err(de::Error::duplicate_field("tag"))
                            }
                            tag = Some(map.next_value()?);
                        }
                        Field::Type => {
                            if typ.is_some() {
                                return Err(de::Error::duplicate_field("type"))
                            }
                            typ = Some(map.next_value()?);
                        }
                        Field::Value => {
                            if value.is_some() {
                                return Err(de::Error::duplicate_field("value"))
                            }
                            let typ = typ.clone().unwrap_or_else(|| "Structure".to_owned());
                            value = Some(match typ.as_str() {
                                "Structure" => TTLValue::Structure(map.next_value()?),
                                "Integer" => TTLValue::Integer(map.next_value()?),
                                "LongInteger" => {
                                    let hex: String = map.next_value()?;
                                    if hex.get(0..2).ok_or_else(|| {
                                        de::Error::custom(
                                            "visit_map: indexing slicing failed for LongInteger \
                                             0..2"
                                                .to_owned(),
                                        )
                                    })? != "0x"
                                    {
                                        return Err(de::Error::custom(format!(
                                            "Invalid value for i64 hex String: {hex} (should \
                                             start with 0x)"
                                        )))
                                    }
                                    let bytes = hex::decode(hex.get(2..).ok_or_else(|| {
                                        de::Error::custom(
                                            "visit_map: indexing slicing failed for LongInteger \
                                             2.."
                                            .to_owned(),
                                        )
                                    })?)
                                    .map_err(|e| {
                                        de::Error::custom(format!(
                                            "Invalid value for i64 hex String: {hex} (not a hex \
                                             string). Error: {e}",
                                        ))
                                    })?;
                                    let v: i64 = i64::from_be_bytes(
                                        bytes.as_slice().try_into().map_err(|e| {
                                            de::Error::custom(format!(
                                                "Invalid value for i64 hex String: {hex}. Error: \
                                                 {e}",
                                            ))
                                        })?,
                                    );
                                    TTLValue::LongInteger(v)
                                }
                                "BigInteger" => {
                                    let hex: String = map.next_value()?;
                                    if hex.get(0..2).ok_or_else(|| {
                                        de::Error::custom(format!(
                                            "visit_map: indexing slicing failed for BigInteger \
                                             0..2: {hex}"
                                        ))
                                    })? != "0x"
                                    {
                                        return Err(de::Error::custom(format!(
                                            "Invalid value for Mask: {hex}"
                                        )))
                                    }
                                    let bytes = hex::decode(hex.get(2..).ok_or_else(|| {
                                        de::Error::custom(format!(
                                            "visit_map: indexing slicing failed for BigInteger \
                                             2..: {hex}"
                                        ))
                                    })?)
                                    .map_err(|_e| {
                                        de::Error::custom(format!("Invalid value for Mask: {hex}"))
                                    })?;
                                    // build the `KmipBigInt` using the bytes representation.
                                    let v = KmipBigInt::from_bytes_be(bytes.as_slice());
                                    TTLValue::BigInteger(v)
                                }
                                "Enumeration" => {
                                    let e: TTLVEnumeration = map.next_value()?;
                                    TTLValue::Enumeration(e)
                                }
                                "Boolean" => {
                                    let b = map.next_value()?;
                                    TTLValue::Boolean(b)
                                }
                                "TextString" => {
                                    let s = map.next_value()?;
                                    TTLValue::TextString(s)
                                }
                                "ByteString" => {
                                    let hex: String = map.next_value()?;
                                    TTLValue::ByteString(hex::decode(&hex).map_err(|_e| {
                                        de::Error::custom(format!(
                                            "Invalid value for a ByteString: {}",
                                            &hex
                                        ))
                                    })?)
                                }
                                "DateTime" => {
                                    let d: String = map.next_value()?;
                                    let date = if d.starts_with("0x") {
                                        parse_hex_time::<V>(&d, HexTimeUnit::Seconds)?
                                    } else {
                                        OffsetDateTime::parse(&d, &Iso8601::DEFAULT).map_err(
                                            |_e| {
                                                de::Error::custom(format!(
                                                    "Invalid value for an RFC3339 date: {d}"
                                                ))
                                            },
                                        )?
                                    };
                                    TTLValue::DateTime(date)
                                }
                                "Interval" => TTLValue::Interval(map.next_value()?),
                                "DateTimeExtended" => {
                                    let hex: String = map.next_value()?;
                                    if hex.get(0..2).ok_or_else(|| {
                                        de::Error::custom(format!(
                                            "visit_map: indexing slicing failed for \
                                             DateTimeExtended 0..2: {hex}"
                                        ))
                                    })? != "0x"
                                    {
                                        return Err(de::Error::custom(format!(
                                            "Invalid value for i64 hex String: {hex} (should \
                                             start with 0x)"
                                        )))
                                    }
                                    let dt = parse_hex_time::<V>(&hex, HexTimeUnit::Microseconds)?;
                                    TTLValue::DateTimeExtended(dt)
                                }
                                t => return Err(de::Error::custom(format!("Unknown type: {t}"))),
                            });
                        }
                    }
                }
                let tag = tag.ok_or_else(|| de::Error::missing_field("tag"))?;
                let value = value.ok_or_else(|| de::Error::missing_field("value"))?;
                Ok(TTLV { tag, value })
            }
        }

        const FIELDS: &[&str] = &["tag", "value"];
        deserializer.deserialize_struct("TTLV", FIELDS, TTLVVisitor)
    }
}

#[derive(Debug, Copy, Clone)]
enum HexTimeUnit {
    Seconds,
    Microseconds,
}

/// Parse a hex string into a `OffsetDateTime`.
/// The hex string is expected to be in big-endian format
/// and in the format `0x<hex>`.
fn parse_hex_time<'de, V>(hex: &str, unit: HexTimeUnit) -> Result<OffsetDateTime, V::Error>
where
    V: MapAccess<'de>,
{
    let bytes = hex::decode(hex.get(2..).ok_or_else(|| {
        de::Error::custom(format!(
            "visit_map: indexing slicing failed for DateTimeExtended 2..: {hex}"
        ))
    })?)
    .map_err(|e| {
        de::Error::custom(format!(
            "Invalid value for i64 hex String: {hex} (not a hex string). Error: {e}",
        ))
    })?;

    Ok(match unit {
        HexTimeUnit::Seconds => {
            let v = i64::from_be_bytes(bytes.as_slice().try_into().map_err(|e| {
                de::Error::custom(format!(
                    "Invalid value for i64 hex String: {hex}. Error: {e}",
                ))
            })?);
            OffsetDateTime::from_unix_timestamp(v).map_err(|e| {
                de::Error::custom(format!(
                    "Invalid value for unix seconds timestamp: {hex}. Error: {e}",
                ))
            })?
        }
        HexTimeUnit::Microseconds => {
            let v = i128::from_be_bytes(bytes.as_slice().try_into().map_err(|e| {
                de::Error::custom(format!(
                    "Invalid value for i128 hex String: {hex}. Error: {e}",
                ))
            })?);
            OffsetDateTime::from_unix_timestamp_nanos(v * 1000).map_err(|e| {
                de::Error::custom(format!(
                    "Invalid value for unix micro-seconds timestamp: {hex}. Error: {e}",
                ))
            })?
        }
    })
}

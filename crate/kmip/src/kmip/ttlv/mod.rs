pub mod deserializer;
pub mod error;
pub mod serializer;

#[cfg(test)]
mod tests;

use core::fmt;
use std::convert::TryInto;

use chrono::{DateTime, TimeZone, Utc};
use num_bigint::BigUint;
use paperclip::actix::Apiv2Schema;
use serde::{
    de::{self, MapAccess, Visitor},
    ser::{SerializeStruct, Serializer},
    Deserialize, Serialize,
};

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
            TTLVEnumeration::Integer(i) => serializer.serialize_i32(*i),
            TTLVEnumeration::Name(s) => serializer.serialize_str(s),
        }
    }
}

impl<'de> Deserialize<'de> for TTLVEnumeration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TTLVEnumerationVisitor;

        impl<'de> Visitor<'de> for TTLVEnumerationVisitor {
            type Value = TTLVEnumeration;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct TTLVEnumeration")
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(TTLVEnumeration::Integer(v.try_into().map_err(|_e| {
                    de::Error::custom(format!(
                        "Unexpected value: {}, expected a 32 bit integer",
                        v
                    ))
                })?))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(TTLVEnumeration::Integer(v.try_into().map_err(|_e| {
                    de::Error::custom(format!(
                        "Unexpected value: {}, expected a 32 bit integer",
                        v
                    ))
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

#[derive(Debug, Clone, Apiv2Schema)]
#[openapi(empty)]
pub enum TTLValue {
    Structure(Vec<TTLV>),
    Integer(i32),
    BitMask(u32),
    LongInteger(i64),
    BigInteger(BigUint),
    Enumeration(TTLVEnumeration),
    Boolean(bool),
    TextString(String),
    ByteString(Vec<u8>),
    DateTime(DateTime<Utc>),
    Interval(u32),
    DateTimeExtended(DateTime<Utc>),
}

impl Default for TTLValue {
    fn default() -> Self {
        TTLValue::TextString(String::default())
    }
}

impl PartialEq for TTLValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Structure(l0), Self::Structure(r0)) => l0 == r0,
            (Self::Integer(l0), Self::Integer(r0)) => l0 == r0,
            (Self::BitMask(l0), Self::BitMask(r0)) => l0 == r0,
            (Self::LongInteger(l0), Self::LongInteger(r0)) => l0 == r0,
            (Self::BigInteger(l0), Self::BigInteger(r0)) => l0 == r0,
            (Self::Enumeration(l0), Self::Enumeration(r0)) => l0 == r0,
            (Self::Boolean(l0), Self::Boolean(r0)) => l0 == r0,
            (Self::TextString(l0), Self::TextString(r0)) => l0 == r0,
            (Self::ByteString(l0), Self::ByteString(r0)) => l0 == r0,
            (Self::DateTime(l0), Self::DateTime(r0)) => l0.timestamp() == r0.timestamp(),
            (Self::Interval(l0), Self::Interval(r0)) => l0 == r0,
            (Self::DateTimeExtended(l0), Self::DateTimeExtended(r0)) => {
                l0.timestamp_nanos() / 1000 == r0.timestamp_nanos() / 1000
            }
            (_, _) => false,
        }
    }
}

#[derive(PartialEq, Debug, Clone, Apiv2Schema, Default)]
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
            TTLValue::BitMask(v) => _serialize(
                serializer,
                &self.tag,
                "Integer",
                &("0x".to_string() + &hex::encode_upper(v.to_be_bytes())),
            ),
            TTLValue::LongInteger(v) => _serialize(
                serializer,
                &self.tag,
                "LongInteger",
                &("0x".to_string() + &hex::encode_upper(v.to_be_bytes())),
            ),
            TTLValue::BigInteger(v) => {
                //TODO Note that Big Integers must be sign extended to
                //TODO  contain a multiple of 8 bytes, and as per LongInteger, JS numbers only
                // support a limited range of values.
                _serialize(
                    serializer,
                    &self.tag,
                    "BigInteger",
                    &("0x".to_string() + &hex::encode_upper(v.to_bytes_be())),
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
                &format!("{}", v.format("%+")),
            ),
            TTLValue::Interval(v) => _serialize(serializer, &self.tag, "Interval", v),
            TTLValue::DateTimeExtended(v) => _serialize(
                serializer,
                &self.tag,
                "DateTimeExtended",
                &("0x".to_string()
                    + &hex::encode_upper((v.timestamp_nanos() / 1000).to_be_bytes())),
            ),
        }
    }
}

/// Used to deserialize the "Integer" type
enum IntegerOrMask {
    Integer(i32),
    Mask(u32),
}

impl<'de> Deserialize<'de> for IntegerOrMask {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct IntegerOrMaskVisitor;

        impl<'de> Visitor<'de> for IntegerOrMaskVisitor {
            type Value = IntegerOrMask;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct IntegerOrMask")
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(IntegerOrMask::Integer(v.try_into().map_err(|_e| {
                    de::Error::custom(format!(
                        "Unexpected value: {}, expected a 32 bit integer",
                        v
                    ))
                })?))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(IntegerOrMask::Integer(v.try_into().map_err(|_e| {
                    de::Error::custom(format!(
                        "Unexpected value: {}, expected a 32 bit integer",
                        v
                    ))
                })?))
            }

            fn visit_str<E>(self, hex: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if &hex[0..2] != "0x" {
                    return Err(de::Error::custom(format!("Invalid value for Mask: {hex}")))
                }
                let bytes = hex::decode(&hex[2..])
                    .map_err(|_e| de::Error::custom(format!("Invalid value for Mask: {hex}")))?;
                let m: u32 =
                    u32::from_be_bytes(bytes.as_slice().try_into().map_err(|_e| {
                        de::Error::custom(format!("Invalid value for Mask: {hex}"))
                    })?);
                Ok(IntegerOrMask::Mask(m))
            }
        }
        deserializer.deserialize_any(IntegerOrMaskVisitor)
    }
}

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
                            let typ = typ.clone().unwrap_or_else(|| "Structure".to_string());
                            value = Some(match typ.as_str() {
                                "Structure" => TTLValue::Structure(map.next_value()?),
                                "Integer" => {
                                    let im: IntegerOrMask = map.next_value()?;
                                    match im {
                                        IntegerOrMask::Integer(v) => TTLValue::Integer(v),
                                        IntegerOrMask::Mask(m) => TTLValue::BitMask(m),
                                    }
                                }
                                "LongInteger" => {
                                    let hex: String = map.next_value()?;
                                    if &hex[0..2] != "0x" {
                                        return Err(de::Error::custom(format!(
                                            "Invalid value for i64 hex String: {}",
                                            hex
                                        )))
                                    }
                                    let bytes = hex::decode(&hex[2..]).map_err(|_e| {
                                        de::Error::custom(format!(
                                            "Invalid value for i64 hex String: {}",
                                            hex
                                        ))
                                    })?;
                                    let v: i64 = i64::from_be_bytes(
                                        bytes.as_slice().try_into().map_err(|_e| {
                                            de::Error::custom(format!(
                                                "Invalid value for i64 hex String: {}",
                                                hex
                                            ))
                                        })?,
                                    );
                                    TTLValue::LongInteger(v)
                                }
                                "BigInteger" => {
                                    let hex: String = map.next_value()?;
                                    if &hex[0..2] != "0x" {
                                        return Err(de::Error::custom(format!(
                                            "Invalid value for Mask: {}",
                                            hex
                                        )))
                                    }
                                    let bytes = hex::decode(&hex[2..]).map_err(|_e| {
                                        de::Error::custom(format!(
                                            "Invalid value for Mask: {}",
                                            hex
                                        ))
                                    })?;
                                    let v = BigUint::from_bytes_be(bytes.as_slice());
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
                                    let date = DateTime::parse_from_rfc3339(&d).map_err(|_e| {
                                        de::Error::custom(format!(
                                            "Invalid value for an ISO 8601 date: {}",
                                            d
                                        ))
                                    })?;
                                    TTLValue::DateTime(date.into())
                                }
                                "Interval" => TTLValue::Interval(map.next_value()?),
                                "DateTimeExtended" => {
                                    let hex: String = map.next_value()?;
                                    if &hex[0..2] != "0x" {
                                        return Err(de::Error::custom(format!(
                                            "Invalid value for i64 hex String: {}",
                                            hex
                                        )))
                                    }
                                    let bytes = hex::decode(&hex[2..]).map_err(|_e| {
                                        de::Error::custom(format!(
                                            "Invalid value for i64 hex String: {}",
                                            hex
                                        ))
                                    })?;
                                    let v: i64 = i64::from_be_bytes(
                                        bytes.as_slice().try_into().map_err(|_e| {
                                            de::Error::custom(format!(
                                                "Invalid value for i64 hex String: {}",
                                                hex
                                            ))
                                        })?,
                                    );
                                    let dt = Utc.timestamp_nanos(v * 1000);
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

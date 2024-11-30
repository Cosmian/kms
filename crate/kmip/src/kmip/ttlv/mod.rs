pub mod deserializer;
pub mod error;
pub mod serializer;

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

use core::fmt;

use num_bigint_dig::BigUint;
use serde::{
    de::{self, MapAccess, Visitor},
    ser::{self, SerializeStruct, Serializer},
    Deserialize, Serialize,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::error::result::KmipResult;

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
    BitMask(u32),
    LongInteger(i64),
    BigInteger(BigUint),
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
            (Self::BitMask(l0), Self::BitMask(r0)) | (Self::Interval(l0), Self::Interval(r0)) => {
                l0 == r0
            }
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
            TTLValue::BitMask(v) => _serialize(
                serializer,
                &self.tag,
                "Integer",
                &("0x".to_owned() + &hex::encode_upper(v.to_be_bytes())),
            ),
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
                &v.format(&Rfc3339).map_err(|err| {
                    ser::Error::custom(format!("Cannot format DateTime {v} into RFC3339: {err}"))
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

        impl Visitor<'_> for IntegerOrMaskVisitor {
            type Value = IntegerOrMask;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct IntegerOrMask")
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(IntegerOrMask::Integer(v.try_into().map_err(|_e| {
                    de::Error::custom(format!("Unexpected value: {v}, expected a 32 bit integer"))
                })?))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(IntegerOrMask::Integer(v.try_into().map_err(|_e| {
                    de::Error::custom(format!("Unexpected value: {v}, expected a 32 bit integer"))
                })?))
            }

            // v is in hexadecimal format
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.get(0..2).ok_or_else(|| {
                    de::Error::custom(format!("visit_str: indexing slicing failed for 0..2: {v}"))
                })? != "0x"
                {
                    return Err(de::Error::custom(format!("Invalid value for Mask: {v}")))
                }
                let bytes = hex::decode(v.get(2..).ok_or_else(|| {
                    de::Error::custom(format!("visit_str: indexing slicing failed for 2..: {v}"))
                })?)
                .map_err(|_e| de::Error::custom(format!("Invalid value for Mask: {v}")))?;
                let m: u32 = u32::from_be_bytes(
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_e| de::Error::custom(format!("Invalid value for Mask: {v}")))?,
                );
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
                            let typ = typ.clone().unwrap_or_else(|| "Structure".to_owned());
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
                                    // build the `BigUint` using the `Vec<u32>` representation.
                                    let v = BigUint::from_slice(
                                        &to_u32_digits(&BigUint::from_bytes_be(bytes.as_slice()))
                                            .map_err(|e| {
                                            de::Error::custom(format!(
                                                "Invalid value for BigInteger: {}. Error: {}",
                                                &hex, e
                                            ))
                                        })?,
                                    );
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
                                    let date =
                                        OffsetDateTime::parse(&d, &Rfc3339).map_err(|_e| {
                                            de::Error::custom(format!(
                                                "Invalid value for an RFC3339 date: {d}"
                                            ))
                                        })?;
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
                                    let bytes = hex::decode(hex.get(2..).ok_or_else(|| {
                                        de::Error::custom(format!(
                                            "visit_map: indexing slicing failed for \
                                             DateTimeExtended 2..: {hex}"
                                        ))
                                    })?)
                                    .map_err(|e| {
                                        de::Error::custom(format!(
                                            "Invalid value for i64 hex String: {hex} (not a hex \
                                             string). Error: {e}",
                                        ))
                                    })?;
                                    let v = i128::from_be_bytes(
                                        bytes.as_slice().try_into().map_err(|e| {
                                            de::Error::custom(format!(
                                                "Invalid value for i64 hex String: {hex}. Error: \
                                                 {e}",
                                            ))
                                        })?,
                                    );
                                    let dt = OffsetDateTime::from_unix_timestamp_nanos(v * 1000)
                                        .map_err(|e| {
                                            de::Error::custom(format!(
                                                "Invalid value for unix timestamp: {hex}. Error: \
                                                 {e}",
                                            ))
                                        })?;
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

/// Convert a `BigUint` into a `Vec<u32>`.
///
/// Get the `Vec<u8>` representation from the `BigUint`,
/// and chunk it 4-by-4 bytes to create the multiple
/// `u32` bytes needed for `Vec<u32>` representation.
///
/// This conversion is done manually, as `num-bigint-dig`
/// doesn't provide such conversion.
pub fn to_u32_digits(big_int: &BigUint) -> KmipResult<Vec<u32>> {
    // Since the KMS works with big-endian representation of byte arrays, casting
    // a group of 4 bytes in big-endian u32 representation needs revert iter so
    // that if you have a chunk [0, 12, 143, 239] you will do
    // B = 239 + 143*2^8 + 12*2^16 + 0*2^24 which is the correct way to do. On
    // top of that, if the number of bytes in `big_int` is not a multiple of 4,
    // it will behave as if there were leading null bytes which is technically
    // the case.
    // In this case, using this to convert a BigUint to a Vec<u32> will not lose
    // leading null bytes information which might be the case when an EC private
    // key is legally generated with leading null bytes.
    let mut bytes_be = big_int.to_bytes_be();
    bytes_be.reverse();

    let mut result = Vec::new();
    for group_of_4_bytes in bytes_be.chunks(4) {
        let mut acc = 0;
        for (k, elt) in group_of_4_bytes.iter().enumerate() {
            acc += u32::from(*elt) * 2_u32.pow(u32::try_from(k)? * 8);
        }
        result.push(acc);
    }
    Ok(result)
}

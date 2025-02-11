use core::fmt;

use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize,
};
use time::{format_description::well_known::Iso8601, OffsetDateTime};
use tracing::trace;

use super::{kmip_big_int::KmipBigInt, TTLV};
use crate::ttlv::{KmipEnumerationVariant, TTLValue};

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
                                    trace!("visit_map: Enumeration");
                                    let e: KmipEnumerationVariant = map.next_value()?;
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

impl<'de> Deserialize<'de> for KmipEnumerationVariant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct KmipEnumVisitor;

        impl<'de> Visitor<'de> for KmipEnumVisitor {
            type Value = KmipEnumerationVariant;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct TTLV")
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(v.as_str())
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                trace!("visit_str: {}", v);
                if v.starts_with("0x") {
                    let hex_string = v.get(2..).ok_or_else(|| {
                        de::Error::custom("Invalid hex string for enumeration value: {v}")
                    })?;
                    let bytes = hex::decode(hex_string).map_err(|e| {
                        de::Error::custom(format!(
                            "Invalid hex string for enumeration value: {v}. Error: {e}"
                        ))
                    })?;
                    let index = u32::from_be_bytes(bytes.try_into().map_err(|e| {
                        de::Error::custom(format!(
                            "Invalid byte length for enumeration value: {v}. Error: {e:?}"
                        ))
                    })?);
                    Ok(KmipEnumerationVariant {
                        index,
                        name: String::new(),
                    })
                } else {
                    Ok(KmipEnumerationVariant {
                        index: 0,
                        name: v.to_owned(),
                    })
                }
            }

            // all signed integers are converted to i64 by default
            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                trace!("visit_i64: {}", v);
                Ok(KmipEnumerationVariant {
                    index: u32::try_from(v).map_err(|e| {
                        de::Error::custom(format!(
                            "Invalid i64 value for enumeration index: {v}. Error: {e:?}"
                        ))
                    })?,
                    name: String::new(),
                })
            }

            // all unsigned integers are converted to u64 by default
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                trace!("visit_u64: {}", v);
                Ok(KmipEnumerationVariant {
                    index: u32::try_from(v).map_err(|e| {
                        de::Error::custom(format!(
                            "Invalid u64 value for enumeration index: {v}. Error: {e:?}"
                        ))
                    })?,
                    name: String::new(),
                })
            }

            // all floating point numbers are converted to f64 by default
            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                trace!("visit_f64: {}", v);
                Err(de::Error::custom(format!(
                    "Invalid f64 value for enumeration index: {v}"
                )))
            }
        }

        deserializer.deserialize_any(KmipEnumVisitor)
    }
}

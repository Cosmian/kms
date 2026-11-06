//! The KMIP `Interval` primitive type.
//!
//! KMIP defines `Interval` as a distinct TTLV primitive (type `0x0A`, a 32-bit
//! unsigned number of seconds) which is *not* interchangeable with `Integer`
//! (type `0x02`). Strictly typed KMIP clients reject an `Integer` where the
//! specification mandates an `Interval`.
//!
//! Fields the specification types as `Interval`:
//!
//! | Field | KMIP 1.4 | KMIP 2.1 |
//! |-------|----------|----------|
//! | `Lease Time` | §3.20 Table 99 | §4.29 Table 88 |
//! | `Protection Period` | — | §4.42 |
//! | `Rotate Interval` / `Rotate Offset` | — | §4.51 |
//!
//! Rust's serde data model has no `Interval`, so a plain `u32` field would be
//! emitted as a TTLV `Integer`. Wrapping the value in [`Interval`] makes the
//! serializer emit the correct primitive: the newtype is serialized through
//! `serialize_newtype_struct` under the reserved name [`INTERVAL_NEWTYPE`],
//! which the TTLV serializer recognises.

use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Visitor};

/// Reserved `serialize_newtype_struct` name used to signal to the TTLV
/// serializer that the wrapped `u32` must be emitted as a TTLV `Interval`
/// rather than an `Integer`.
pub const INTERVAL_NEWTYPE: &str = "$KmipInterval";

/// A KMIP `Interval`: a period of time expressed as a count of seconds.
///
/// Serializes to the TTLV `Interval` primitive (`0x0A`) instead of the
/// `Integer` primitive (`0x02`) that a bare `u32` would produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Interval(pub u32);

impl Interval {
    /// Returns the interval as a number of seconds.
    #[must_use]
    pub const fn as_secs(self) -> u32 {
        self.0
    }
}

impl From<u32> for Interval {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Interval> for u32 {
    fn from(value: Interval) -> Self {
        value.0
    }
}

impl Display for Interval {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}s", self.0)
    }
}

impl Serialize for Interval {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct(INTERVAL_NEWTYPE, &self.0)
    }
}

impl<'de> Deserialize<'de> for Interval {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IntervalVisitor;

        impl<'de> Visitor<'de> for IntervalVisitor {
            type Value = Interval;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("a KMIP Interval (seconds)")
            }

            fn visit_u32<E: serde::de::Error>(self, v: u32) -> Result<Self::Value, E> {
                Ok(Interval(v))
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(Interval(u32::try_from(v).unwrap_or(u32::MAX)))
            }

            fn visit_i32<E: serde::de::Error>(self, v: i32) -> Result<Self::Value, E> {
                Ok(Interval(u32::try_from(v).unwrap_or(0)))
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(Interval(u32::try_from(v).unwrap_or(0)))
            }

            fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_u32(Self)
            }
        }

        deserializer.deserialize_newtype_struct(INTERVAL_NEWTYPE, IntervalVisitor)
    }
}

/// Serialize an `Option<i64>` number of seconds as a TTLV `Interval`, for fields the
/// specification types as `Interval` but whose public Rust type is `i64` (Re-key,
/// Re-key Key Pair and Re-certify `Offset`). Deserialization of `i64` already accepts
/// an `Interval`, as well as the `LongInteger` previously emitted.
///
/// # Errors
/// Fails when the value does not fit the unsigned 32-bit `Interval`.
pub fn serialize_option_secs<S>(value: &Option<i64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(secs) => {
            let secs = u32::try_from(*secs).map_err(|_e| {
                serde::ser::Error::custom(format!(
                    "an Interval must be between 0 and {} seconds, got {secs}",
                    u32::MAX
                ))
            })?;
            serializer.serialize_some(&Interval(secs))
        }
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::Interval;
    use crate::ttlv::{TTLValue, to_ttlv};

    #[test]
    fn test_option_secs_serializes_as_interval() {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct S {
            #[serde(serialize_with = "super::serialize_option_secs")]
            offset: Option<i64>,
        }
        let ttlv = to_ttlv(&S { offset: Some(60) }).ok();
        assert!(
            matches!(ttlv.as_ref().map(|t| &t.value), Some(TTLValue::Structure(children))
                if children.first().map(|c| &c.value) == Some(&TTLValue::Interval(60))),
            "unexpected TTLV: {ttlv:?}"
        );
    }

    #[test]
    fn test_interval_conversions() {
        let i = Interval::from(3600_u32);
        assert_eq!(i.as_secs(), 3600);
        assert_eq!(u32::from(i), 3600);
        assert_eq!(i.to_string(), "3600s");
    }
}

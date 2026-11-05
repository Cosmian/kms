use serde::{
    Serialize,
    ser::{self, SerializeStruct, Serializer},
};
use time::{UtcOffset, format_description::well_known::Rfc3339};

use super::{KmipEnumerationVariant, ttlv_struct::TTLV};
use crate::ttlv::ttlv_struct::TTLValue;

/// Upper-case hex view of a byte slice; `serde_json` streams it via `collect_str` without a heap `String`.
struct UpperHex<'a>(&'a [u8]);

impl core::fmt::Display for UpperHex<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = [0_u8; 128];
        for chunk in self.0.chunks(64) {
            let out = buf.get_mut(..chunk.len() * 2).ok_or(core::fmt::Error)?;
            hex::encode_to_slice(chunk, out).map_err(|_e| core::fmt::Error)?;
            out.make_ascii_uppercase();
            f.write_str(core::str::from_utf8(out).map_err(|_e| core::fmt::Error)?)?;
        }
        Ok(())
    }
}

impl Serialize for UpperHex<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Serialize TTLV structure to the Serde Data Model
///
/// Serialization if performed by calling methods on the Serializer object.
/// In this particular case, we are serializing a TTLV structure to a Serde Data Model
/// structure.
impl Serialize for TTLV {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        /// Serialize a TTLV structure to a Serde Data Model Structure
        fn serialize_struct_<S, T>(
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
            if typ != "Structure" {
                ttlv.serialize_field("type", typ)?;
            }
            ttlv.serialize_field("value", value)?;
            ttlv.end()
        }

        match &self.value {
            TTLValue::Structure(v) => serialize_struct_(serializer, &self.tag, "Structure", v),
            TTLValue::Integer(v) => serialize_struct_(serializer, &self.tag, "Integer", v),
            TTLValue::LongInteger(v) => serialize_struct_(
                serializer,
                &self.tag,
                "LongInteger",
                &("0x".to_owned() + &hex::encode_upper(v.to_be_bytes())),
            ),
            TTLValue::BigInteger(v) => {
                // TODO Note that Big Integers must be sign extended to
                // TODO  contain a multiple of 8 bytes, and as per LongInteger, JS numbers only
                // support a limited range of values.
                serialize_struct_(
                    serializer,
                    &self.tag,
                    "BigInteger",
                    v, //&("0x".to_owned() + &hex::encode_upper(v.to_bytes_be())),
                )
            }
            TTLValue::Enumeration(v) => serialize_struct_(serializer, &self.tag, "Enumeration", v),
            TTLValue::Boolean(v) => serialize_struct_(serializer, &self.tag, "Boolean", v),
            TTLValue::TextString(v) => serialize_struct_(serializer, &self.tag, "TextString", v),
            TTLValue::ByteString(v) => {
                serialize_struct_(serializer, &self.tag, "ByteString", &UpperHex(v))
            }
            // A KMIP Date-Time is POSIX time in seconds, as in the binary and XML encodings
            TTLValue::DateTime(v) => serialize_struct_(
                serializer,
                &self.tag,
                "DateTime",
                &v.to_offset(UtcOffset::UTC)
                    .replace_nanosecond(0)
                    .map_err(ser::Error::custom)?
                    .format(&Rfc3339)
                    .map_err(|err| {
                        ser::Error::custom(format!(
                            "Cannot format DateTime {v} into ISO8601: {err}"
                        ))
                    })?,
            ),
            TTLValue::Interval(v) => serialize_struct_(serializer, &self.tag, "Interval", v),
            TTLValue::DateTimeExtended(v) => {
                // truncate to 64 bits
                let u_64 = u64::try_from(*v).map_err(|err| {
                    ser::Error::custom(format!("Cannot convert DateTimeExtended {v} to u64: {err}"))
                })?;
                serialize_struct_(
                    serializer,
                    &self.tag,
                    "DateTimeExtended",
                    &("0x".to_owned() + &hex::encode_upper(u_64.to_be_bytes())),
                )
            }
        }
    }
}

impl Serialize for KmipEnumerationVariant {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.name.is_empty() {
            let bytes = self.value.to_be_bytes().to_vec();
            let hex_string = "0x".to_owned() + &hex::encode_upper(&bytes);
            serializer.serialize_str(&hex_string)
        } else {
            serializer.serialize_str(&self.name)
        }
    }
}

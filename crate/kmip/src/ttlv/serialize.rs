use serde::{
    ser::{self, SerializeStruct, Serializer},
    Serialize,
};
use time::format_description::well_known::Iso8601;

use super::ttlv_struct::{TTLVEnumeration, TTLV};
use crate::ttlv::ttlv_struct::TTLValue;

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

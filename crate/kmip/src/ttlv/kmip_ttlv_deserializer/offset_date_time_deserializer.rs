use cosmian_logger::trace;
use serde::de::{self, DeserializeSeed, SeqAccess};
use time::OffsetDateTime;
use tracing::instrument;

use super::Result;
use crate::ttlv::TtlvError;

/// Serde `Deserializer` that feeds a `time::OffsetDateTime` to the `time` crate's tuple visitor.
///
/// The visitor expects `visit_seq` with fields in this order:
/// year, ordinal, hour, minute, second, nanosecond, `offset_hours`, `offset_minutes`, `offset_seconds`.
/// See <https://github.com/time-rs/time/blob/main/time/src/serde/visitor.rs#L80>.
pub(super) struct OffsetDateTimeDeserializer {
    // The tag of the array
    tag: String,
    // all the elements of the containing struct
    dt: OffsetDateTime,
    // index of the element called by the visitor
    // they will be called in this order:
    // year, ordinal, hour, minute, second, nanosecond, `offset_hours`, `offset_minutes`, `offset_seconds`
    index: usize,
}

impl OffsetDateTimeDeserializer {
    pub(super) fn new(tag: &str, dt: OffsetDateTime) -> Self {
        Self {
            tag: tag.to_owned(),
            dt,
            index: 0,
        }
    }
}

impl<'de> de::Deserializer<'de> for &mut OffsetDateTimeDeserializer {
    type Error = TtlvError;

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        // forward the call to deserialize_i32
        self.deserialize_i32(visitor)
    }

    fn deserialize_any<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_bool<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_i8<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        // forward the call to deserialize_i32
        self.deserialize_i32(visitor)
    }

    fn deserialize_i16<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        // forward the call to deserialize_i32
        self.deserialize_i32(visitor)
    }

    fn deserialize_i32<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        if self.index == 0 {
            visitor.visit_i32(self.dt.year())
        } else if self.index == 1 {
            visitor.visit_u16(self.dt.ordinal())
        } else if self.index == 2 {
            visitor.visit_u8(self.dt.hour())
        } else if self.index == 3 {
            visitor.visit_u8(self.dt.minute())
        } else if self.index == 4 {
            visitor.visit_u8(self.dt.second())
        } else if self.index == 5 {
            visitor.visit_u32(self.dt.nanosecond())
        } else if self.index == 6 {
            visitor.visit_i8(self.dt.offset().whole_hours())
        } else if self.index == 7 {
            visitor.visit_i16(self.dt.offset().whole_minutes() % 60)
        } else if self.index == 8 {
            visitor.visit_i32(self.dt.offset().whole_seconds() % 60)
        } else {
            unimplemented!("should not be called by OffsetDateTime deserializer")
        }
    }

    fn deserialize_i64<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_u16<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        // forward the call to deserialize_i32
        self.deserialize_i32(visitor)
    }

    fn deserialize_u32<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        // forward the call to deserialize_i32
        self.deserialize_i32(visitor)
    }

    fn deserialize_u64<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_f32<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_f64<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_char<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_str<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_string<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_bytes<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_byte_buf<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_option<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_unit<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        _visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        _visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_seq<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_tuple<V>(
        self,
        _len: usize,
        _visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_map<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        _visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_identifier<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }

    fn deserialize_ignored_any<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by OffsetDateTime deserializer")
    }
}

impl<'de> SeqAccess<'de> for OffsetDateTimeDeserializer {
    type Error = TtlvError;

    #[instrument(level = "trace", skip(self, seed))]
    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        trace!(
            "deserializing OffsetDateTime at tag: {}, value: {}, index: {}",
            self.tag, self.dt, self.index
        );

        if self.index >= 9 {
            return Ok(None);
        }

        let res = seed.deserialize(&mut *self).map(Some);
        self.index += 1;
        res
    }
}

#[cfg(test)]
#[path = "offset_date_time_deserializer_characterization_tests.rs"]
mod characterization_tests;

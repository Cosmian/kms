use serde::de::{self, DeserializeSeed, SeqAccess};
use tracing::{instrument, trace};

use super::Result;
use crate::ttlv::TtlvError;

// The `ByteStringDeserializer` is used to deserialize a ByteString
/// It is called by the main deserializer when receiving Visitor requests to `deserialize_seq`
pub(super) struct ByteStringDeserializer<'a> {
    // The tag of the array
    tag: String,
    // all the elements of the containing struct
    byte_string: &'a [u8],
    // position in the ByteString
    index: usize,
}

impl<'a> ByteStringDeserializer<'a> {
    pub(super) fn new(tag: &str, byte_string: &'a [u8]) -> Self {
        ByteStringDeserializer {
            tag: tag.to_owned(),
            byte_string,
            index: 0,
        }
    }
}
impl<'a, 'de: 'a> de::Deserializer<'de> for &mut ByteStringDeserializer<'a> {
    type Error = TtlvError;

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        let byte = self.byte_string.get(self.index).copied().ok_or_else(|| {
            TtlvError::from("Deserializing a ByteString: expected u8 value in ByteString")
        })?;
        self.index += 1;
        visitor.visit_u8(byte)
    }

    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_any<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        self.deserialize_u8(visitor)
    }

    fn deserialize_bool<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_bool: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_i8<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_i8: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_i16<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_i16: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_i32<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_i32: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_i64<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_i64: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_u16<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_u16: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_u32<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_u32: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_u64<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_u64: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_f32<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_f32: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_f64<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_f64: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_char<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_char: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_str<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_str: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_string<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_string: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_bytes<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_bytes: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_byte_buf<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_byte_buf: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_option<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_option: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_unit<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_unit: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        _visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_unit_struct: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        _visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_newtype_struct: should not be called by ByteString deserializer"
                .to_owned(),
        ))
    }

    fn deserialize_seq<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_seq: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_tuple<V>(
        self,
        _len: usize,
        _visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_tuple: should not be called by ByteString deserializer".to_owned(),
        ))
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
        Err(de::Error::custom(
            "deserialize_tuple_struct: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_map<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_map: should not be called by ByteString deserializer".to_owned(),
        ))
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
        Err(de::Error::custom(
            "deserialize_struct: should not be called by ByteString deserializer".to_owned(),
        ))
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
        Err(de::Error::custom(
            "deserialize_enum: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_identifier<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_identifier: should not be called by ByteString deserializer".to_owned(),
        ))
    }

    fn deserialize_ignored_any<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        Err(de::Error::custom(
            "deserialize_ignored_any: should not be called by ByteString deserializer".to_owned(),
        ))
    }
}

impl<'a, 'de: 'a> SeqAccess<'de> for ByteStringDeserializer<'a> {
    type Error = TtlvError;

    #[instrument(level = "trace", skip(self, seed))]
    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        trace!(
            "deserializing bytes string at tag: {}, of len: {}",
            self.tag,
            self.byte_string.len()
        );

        if self.index >= self.byte_string.len() {
            return Ok(None);
        }

        seed.deserialize(&mut *self).map(Some)
    }
}

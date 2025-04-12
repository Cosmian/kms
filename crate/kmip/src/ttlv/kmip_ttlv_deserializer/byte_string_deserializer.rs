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

#[allow(unused_variables)]
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

    #[instrument(skip(self, visitor))]
    fn deserialize_any<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        self.deserialize_u8(visitor)
    }

    fn deserialize_bool<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_i8<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_i16<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_i32<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_i64<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_u16<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_u32<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_u64<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_f32<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_f64<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_char<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_str<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_string<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_bytes<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_option<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_unit<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_unit_struct<V>(
        self,
        name: &'static str,
        visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_newtype_struct<V>(
        self,
        name: &'static str,
        visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_seq<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_tuple<V>(
        self,
        len: usize,
        visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_tuple_struct<V>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_map<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_struct<V>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_enum<V>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_identifier<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        unimplemented!("should not be called by ByteString deserializer")
    }
}

impl<'a, 'de: 'a> SeqAccess<'de> for ByteStringDeserializer<'a> {
    type Error = TtlvError;

    #[instrument(skip(self, seed))]
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

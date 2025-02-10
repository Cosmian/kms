#![allow(dead_code)]
use std::collections::VecDeque;

use serde::de::{self, DeserializeSeed, SeqAccess, Visitor};
use tracing::trace;

use super::{error::TtlvError, KmipBigInt};

type Result<T> = std::result::Result<T, TtlvError>;

#[derive(Debug)]
pub struct KmipBigIntDeserializer {
    sign: i8,
    u32_be: VecDeque<u32>,
}

impl KmipBigIntDeserializer {
    pub fn instantiate(kmip_big_int: &KmipBigInt) -> Result<Self> {
        Ok(Self {
            sign: kmip_big_int.sign(),
            u32_be: VecDeque::from(kmip_big_int.to_u32_digits()?),
        })
    }
}

impl<'de> de::Deserializer<'de> for &mut KmipBigIntDeserializer {
    type Error = TtlvError;

    fn deserialize_any<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_bool<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_i8<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i8(self.sign)
    }

    fn deserialize_i16<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_i32<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_i64<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_u8<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_u16<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_u32<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let next = self.u32_be.pop_front();
        next.map_or_else(
            || Err(TtlvError::from("No more elements in BigInt")),
            |v| visitor.visit_u32(v),
        )
    }

    fn deserialize_u64<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_f32<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_f64<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_char<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_str<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_string<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_bytes<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_byte_buf<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_option<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_unit<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        _visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        _visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_seq<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_seq: state:  {:?}", self);
        visitor.visit_seq(self)
    }

    fn deserialize_tuple<V>(
        self,
        _len: usize,
        visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_tuple: state:  {:?}", self);
        visitor.visit_seq(self)
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_map<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        _visitor: V,
    ) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_identifier<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_ignored_any<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "Unsupported deserialization for KmipBigInt",
        ))
    }
}

// `SeqAccess` is provided to the `Visitor` to give it the ability to iterate
// through elements of the sequence.
impl<'de> SeqAccess<'de> for KmipBigIntDeserializer {
    type Error = TtlvError;

    // #[instrument(skip(self, seed))]
    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        trace!("seq_access: next_element_seed: state:  {:?}", self);
        // this is called when deserializing the Biguint part of the BigInt
        // which is built from a sequence of u32
        // make sure we are not out of bounds
        if self.u32_be.is_empty() {
            return Ok(None);
        }
        // go ahead, deserialize the next i8 (sign) or u32
        seed.deserialize(self).map(Some)
    }
}

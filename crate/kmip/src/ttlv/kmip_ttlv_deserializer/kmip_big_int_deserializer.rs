//! A deserializer implementation for KMIP `BigInt` values.
//!
//! This module provides functionality to deserialize KMIP `BigInt` values into Rust types,
//! primarily focusing on `BigInt` values that are represented as a sequence of big-endian u32 values.
//! The deserializer supports converting The KMIP `BigInt` into its constituent parts:
//! - A sign value (i8)
//! - A sequence of big-endian u32 values
//!
//! # Implementation Details
//!
//! The deserializer primarily supports:
//! - Deserializing the sign as an `i8`
//! - Deserializing individual `u32` values from the big-endian representation
//! - Sequence deserialization for handling the full number
//! - Tuple deserialization for composite number representation
//!
//! Most other deserialization types (like bool, string, map, etc.) are intentionally
//! unsupported and will return an error.
//!
//! # Example Usage
//! ```ignore
//! let kmip_big_int = KmipBigInt::new();  // Your BigInt value
//! let deserializer = KmipBigIntDeserializer::instantiate(&kmip_big_int)?;
//! let value = MyType::deserialize(deserializer)?;
//! ```
//!
//! The deserializer maintains internal state using a `VecDeque<u32>` to process
//! the big-endian u32 digits and tracks the sign of the number.

use std::collections::VecDeque;

use serde::de::{self, DeserializeSeed, SeqAccess, Visitor};
use tracing::{instrument, trace};

use crate::ttlv::{KmipBigInt, TtlvError};

type Result<T> = std::result::Result<T, TtlvError>;

/// A deserializer for KMIP `BigInt` values that implements Serde's Deserializer trait.
///
/// # Fields
///
/// * `sign` - The sign of the `BigInt` value (-1, 0, or 1)
/// * `u32_be` - A double-ended queue containing the big-endian u32 digits of the number
///
/// This struct provides methods to deserialize a KMIP `BigInt` into its component parts,
/// primarily focusing on extracting the sign and sequence of u32 values.
#[derive(Debug)]
pub struct KmipBigIntDeserializer {
    sign: i8,
    u32_be: VecDeque<u32>,
}

impl KmipBigIntDeserializer {
    pub fn instantiate(kmip_big_int: &KmipBigInt) -> Result<Self> {
        Ok(Self {
            sign: kmip_big_int.sign(),
            u32_be: VecDeque::from(kmip_big_int.to_u32_digits()?.1),
        })
    }
}

impl<'de> de::Deserializer<'de> for &mut KmipBigIntDeserializer {
    type Error = TtlvError;

    fn deserialize_any<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_any: state:  {:?}", self);
        // Check if the sign was visited already
        if self.sign != i8::MAX {
            // deserialize the sign
            let res = visitor.visit_i8(self.sign);
            // mark the sign as visited
            self.sign = i8::MAX;
            // return res;
            return res;
        }
        // if the sign was already visited, deserialize the next u32
        let next = self.u32_be.pop_front();
        next.map_or_else(
            || Err(TtlvError::from("No more elements in BigInt")),
            |v| visitor.visit_u32(v),
        )
    }

    fn deserialize_bool<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "deserialize_bool: Unsupported deserialization for KmipBigInt",
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
            "deserialize_i16: Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_i32<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "deserialize_i32: Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_i64<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "deserialize_i64: Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_u8<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "deserialize_u8: Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_u16<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "deserialize_u16: Unsupported deserialization for KmipBigInt",
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
            "deserialize_u64: Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_f32<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "deserialize_f32: Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_f64<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "deserialize_f64: Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_char<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "deserialize_char: Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_str<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "deserialize_str: Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_string<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "deserialize_string: Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_bytes<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "deserialize_bytes: Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_byte_buf<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "deserialize_bytes_buf: Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_option<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "deserialize_option: Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_unit<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "deserialize_unit: Unsupported deserialization for KmipBigInt",
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
            "deserialize_unit_struct: Unsupported deserialization for KmipBigInt",
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
            "deserialize_newtype_struct: Unsupported deserialization for KmipBigInt",
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
            "deserialize_tuple_struct: Unsupported deserialization for KmipBigInt",
        ))
    }

    fn deserialize_map<V>(self, _visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::from(
            "deserialize_map: Unsupported deserialization for KmipBigInt",
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
            "deserialize_struct: Unsupported deserialization for KmipBigInt",
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

// `SeqAccess` is provided to the `Visitor` to allow it to iterate
// through elements of the sequence.
// From the BigInt Deserialize point of view, the KMIP BigInt is a sequence of
// - a sign encoded as an i8
// - a sequence of u32 in big endian order representing the absolute value of the BigInt
impl<'de> SeqAccess<'de> for KmipBigIntDeserializer {
    type Error = TtlvError;

    #[instrument(skip(self, seed))]
    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        trace!("seq_access: next_element_seed: state:  {:?}", self);
        // this is called when deserializing the Biguint part of the BigInt
        // which is built from a sequence of u32. The deserializer will
        // empty the u32 sequence. We return None to signal the end of the sequence
        if self.u32_be.is_empty() {
            return Ok(None);
        }
        // go ahead, deserialize the next i8 (sign) or u32
        seed.deserialize(self).map(Some)
    }
}

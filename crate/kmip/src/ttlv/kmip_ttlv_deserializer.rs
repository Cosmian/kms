#![allow(dead_code)]
use serde::{
    de::{self, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor},
    Deserialize,
};
use strum::VariantNames;
use tracing::{instrument, trace};

use super::{error::TtlvError, TTLV};
use crate::{
    kmip_1_4, kmip_2_1,
    ttlv::{kmip_big_int_deserializer::KmipBigIntDeserializer, TTLValue},
};

type Result<T> = std::result::Result<T, TtlvError>;

/// Parse a KMIP structure from its TTLV value.
///
/// Note: `Objects` are untagged enums, so it is impossible to know the type of the Object
/// unless the root value being deserialized is an object, in which case,
/// the tag is the name of the variant.
///
/// #see `Object::post_fix()`
pub fn from_ttlv<'a, T>(s: TTLV) -> Result<T>
where
    T: Deserialize<'a>,
{
    trace!("from_ttlv: {s:?}");
    let mut deserializer = TtlvDeserializer::from_ttlv(s);
    T::deserialize(&mut deserializer)
}

// WHen deserializing a map, the deserializer needs to know if it is deserializing the key or the value
// This is handled in MapAccess::next_key_seed and MapAccess::next_value_seed
#[derive(Debug, PartialEq, Eq)]
enum MapAccessState {
    // Not in a Map Axxess
    None,
    Key,
    Value,
}

#[derive(Debug)]
pub struct TtlvDeserializer {
    /// The current TTLV being deserialized
    current: TTLV,
    /// The current child index in a structure being deserialized.
    /// Arrays in TTLV are represented as structures with children holding the array values
    /// The child index is also used in Enums deserialization to differentiate between the tag and the variant
    /// when deserializing an identifier (0; tag, 1; variant)
    child_index: usize,
    /// The state of the deserializer when deserializing a map.
    /// The deserializer needs to know if it is deserializing the key or the value.
    /// This is handled in `MapAccess::next_key_seed` and `MapAccess::next_value_seed`.
    /// The deserializer starts with the key state
    /// When the key is deserialized, the state is changed to Value
    map_state: MapAccessState,
    /// The secondary index is used to track a position in a value
    /// such as the byte index in a `ByteString`
    value_index: usize,
}

impl TtlvDeserializer {
    #[must_use]
    pub const fn from_ttlv(root: TTLV) -> Self {
        Self {
            current: root,
            child_index: 0,
            value_index: 0,
            map_state: MapAccessState::None,
        }
    }

    // When the current value is a structure, we want to look at the child
    // at the current child index. If the current value is not a structure,
    // we want to look at the current value.
    fn fetch_element(&self) -> Result<&TTLV> {
        //unwrap the structure if within a structure and get the child
        match &self.current.value {
            TTLValue::Structure(children) => {
                // get the child at the child index
                let child = children.get(self.child_index).ok_or_else(|| {
                    TtlvError::from(format!(
                        "Index out of bounds when accessing child array: {}",
                        self.child_index
                    ))
                })?;
                Ok(child)
            }
            _ => Ok(&self.current),
        }
    }

    /// Creates a deserializer for the next child TTLV and deserializes it using the provided seed.
    /// Used for struct and map deserialization, where each child represents a field.
    /// Returns None when there are no more children to process.
    ///
    /// The function maintains an internal index to track the current child position.
    ///
    /// # Type Parameters
    /// * `K` - The type of seed that will be used to deserialize the child
    ///
    /// # Returns
    /// * `Ok(Some(Value))` - Successfully deserialized child value
    /// * `Ok(None)` - No more children to process
    /// * `Err` - Deserialization error
    #[instrument(skip(self, seed))]
    fn get_child_deserializer<'de, K>(
        &mut self,
        seed: K,
        map_state: MapAccessState,
    ) -> Result<Option<<K as DeserializeSeed<'de>>::Value>>
    where
        K: DeserializeSeed<'de>,
    {
        let TTLValue::Structure(children) = &self.current.value else {
            return Err(TtlvError::from("Expected Structure or Array value in TTLV"));
        };
        if self.child_index >= children.len() {
            // if the child index is out of bounds, we are done with this child
            // reset the child index to 0
            trace!(
                "get_child_deserializer: map access state: {:?}, index: {}, no more children",
                self.map_state,
                self.child_index
            );
            self.child_index = 0;
            return Ok(None);
        }
        let child = children
            .get(self.child_index)
            .ok_or_else(|| TtlvError::from("Index out of bounds when accessing child array"))?;
        trace!(
            "get_child_deserializer: map access state: {:?}, index: {}, child: {:?}",
            self.map_state,
            self.child_index,
            child
        );
        let mut deserializer = Self {
            current: child.clone(),
            child_index: 0,
            value_index: 0,
            map_state,
        };
        let v = seed.deserialize(&mut deserializer).map(Some)?;
        Ok(v)
    }
}

impl<'de> de::Deserializer<'de> for &mut TtlvDeserializer {
    type Error = TtlvError;

    // Look at the input data to decide what Serde data model type to
    // deserialize as. Not all data formats are able to support this operation.
    // Formats that support `deserialize_any` are known as self-describing.
    //
    // When the deserializer is deserializing an untagged enum, almost all calls to deserialize
    // the child keys and values are done in the `deserialize_any` method.
    #[instrument(skip(self, visitor))]
    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_any: map access state: {:?}, index: {}, current: {:?}",
            self.map_state,
            self.child_index,
            self.current
        );
        if self.map_state == MapAccessState::Key {
            // if the deserializer is deserializing the key of a map, the tag is the key
            trace!(
                "deserialize_any: map access state: key, tag: {}",
                self.current.tag
            );
            return visitor.visit_str(&self.current.tag);
        }

        // if self.map_state == MapAccessState::None
        //     && matches!(self.current.value, TTLValue::Structure(_))
        // {
        //     self.current = TTLV {
        //         tag: "ROOT".to_owned(),
        //         value: TTLValue::Structure(vec![self.current.clone()]),
        //     };
        //     return visitor.visit_map(self);
        // }

        // we are not in a map accessing a seed key but either:
        // - deserializing a value in a map
        // - or not in a map at all, and we are also interested in the value

        match &self.fetch_element()?.value {
            TTLValue::BigInteger(bi) => {
                // if the TTLV value is a BigInt, the deserializer is attempting to deserialize the value
                // by converting the BigInt to u32
                trace!("deserialize_any value of BigInt: {:?}", bi);
                let seq_access = KmipBigIntDeserializer::instantiate(bi)?;
                visitor.visit_seq(seq_access)
            }
            TTLValue::Structure(child_array) => {
                trace!("deserialize_any value of Structure: {:?}", child_array);
                // if the TTLV value is a Structure, we will deserialize it using the StructureWalker
                // which will iterate over the children of the structure as it were a map of properties to values
                visitor.visit_map(StructureWalker::new(self))
            }
            TTLValue::Integer(i) => {
                // if the TTLV value is an Integer, the deserializer is attempting to deserialize the value
                // by converting the integer to i32
                visitor.visit_i32(*i)
            }
            TTLValue::LongInteger(i) => {
                // if the TTLV value is a LongInteger, the deserializer is attempting to deserialize the value
                // by converting the integer to i64
                visitor.visit_i64(*i)
            }
            TTLValue::TextString(s) => {
                // if the TTLV value is a TextString, the deserializer is attempting to deserialize the value
                visitor.visit_str(s)
            }
            TTLValue::Boolean(b) => {
                // if the TTLV value is a Boolean, the deserializer is attempting to deserialize the value
                visitor.visit_bool(*b)
            }
            TTLValue::ByteString(b) => {
                // if the TTLV value is a ByteString, the deserializer is attempting to deserialize the value
                visitor.visit_bytes(b)
            }
            TTLValue::DateTime(dt) => {
                // if the TTLV value is a DateTime, the deserializer is attempting to deserialize the value
                visitor.visit_i64(dt.unix_timestamp())
            }
            TTLValue::Interval(i) => {
                // if the TTLV value is an Interval, the deserializer is attempting to deserialize the value
                visitor.visit_u32(*i)
            }
            TTLValue::DateTimeExtended(dt) => {
                // if the TTLV value is a DateTimeExtended, the deserializer is attempting to deserialize the value
                visitor.visit_i128(dt.unix_timestamp_nanos() / 1000)
            }
            TTLValue::Enumeration(e) => {
                // Choose the variant name over the value if it is available
                if e.name.is_empty() {
                    trace!("deserialize_any of enum variant: value: {}", e.value);
                    visitor.visit_u32(e.value)
                } else {
                    trace!("deserialize_any of enum variant: name: {}", e.name);
                    visitor.visit_str(&e.name)
                }
            }
        }
    }

    #[instrument(skip(self, visitor))]
    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_bool: state:  {:?}", self.current);
        let value = match &self.fetch_element()?.value {
            TTLValue::Boolean(b) => *b,
            _ => return Err(TtlvError::from("Expected Boolean value in TTLV")),
        };
        visitor.visit_bool(value)
    }

    #[instrument(skip(self, visitor))]
    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        match &self.fetch_element()?.value {
            TTLValue::BigInteger(bi) => {
                // if the TTLV value is a BigInt, the deserializer is attempting to deserialize the sign
                visitor.visit_i8(bi.sign())
            }
            TTLValue::Integer(i) => {
                // if the TTLV value is an Integer, the deserializer is attempting to deserialize the value
                // by converting the integer to i8
                let value: i8 = (*i)
                    .try_into()
                    .map_err(|e| TtlvError::from(format!("Integer conversion error{e}")))?;
                visitor.visit_i8(value)
            }
            _ => Err(TtlvError::from("Expected BigInt or Integer value in TTLV")),
        }
    }

    #[instrument(skip(self, visitor))]
    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_i16 state:  {:?}", self.current);
        if let TTLValue::Integer(i) = &self.fetch_element()?.value {
            let value: i16 = (*i)
                .try_into()
                .map_err(|e| TtlvError::from(format!("Integer conversion error{e}")))?;
            visitor.visit_i16(value)
        } else {
            Err(TtlvError::from("Expected Integer value in TTLV"))
        }
    }

    #[instrument(skip(self, visitor))]
    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_i32: child index: {},  current:  {:?}",
            self.child_index,
            self.current
        );
        if let TTLValue::Integer(i) = &self.fetch_element()?.value {
            visitor.visit_i32(*i)
        } else {
            Err(TtlvError::from("Expected Integer value in TTLV"))
        }
    }

    #[instrument(skip(self, visitor))]
    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_i64: state:  {:?}", self.current);
        if let TTLValue::LongInteger(i) = &self.fetch_element()?.value {
            visitor.visit_i64(*i)
        } else {
            Err(TtlvError::from("Expected Integer value in TTLV"))
        }
    }

    #[instrument(skip(self, visitor))]
    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_u8: state: {:?}, index: {}",
            self.current,
            self.child_index
        );
        match &self.fetch_element()?.value {
            TTLValue::ByteString(_bs) => {
                Err(TtlvError::from(
                    "ByteString: deserialize from u8: how does this work ?",
                ))
                // if let Some(byte) = bs.get(self.value_index).cloned() {
                //     self.value_index += 1;
                //     visitor.visit_u8(byte)
                // } else {
                //     self.value_index = 0;
                //     Err(TtlvError::from(
                //         "Index out of bounds when accessing ByteString",
                //     ))
                // }
            }
            TTLValue::Integer(i) => {
                if *i < 0 {
                    return Err(TtlvError::from("Cannot convert negative integer to u8"));
                }
                let value: u8 = (*i)
                    .try_into()
                    .map_err(|e| TtlvError::from(format!("Integer conversion error{e}")))?;
                visitor.visit_u8(value)
            }
            _ => Err(TtlvError::from(
                "Expected ByteString or Integer value in TTLV",
            )),
        }
    }

    #[instrument(skip(self, visitor))]
    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_u16: state:  {:?}", self.current);
        if let TTLValue::Integer(i) = &self.fetch_element()?.value {
            if *i < 0 {
                return Err(TtlvError::from("Cannot convert negative integer to u16"));
            }
            let value: u16 = (*i)
                .try_into()
                .map_err(|e| TtlvError::from(format!("Integer conversion error{e}")))?;
            visitor.visit_u16(value)
        } else {
            Err(TtlvError::from("Expected Integer value in TTLV"))
        }
    }

    #[instrument(skip(self, visitor))]
    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_u32: state:  {:?}", self.current);
        match &self.fetch_element()?.value {
            TTLValue::BigInteger(bi) => {
                // if the TTLV value is a BigInt, the deserializer is attempting to deserialize the value
                // by converting the BigInt to u32
                bi.to_u32_digits()?
                    .get(self.child_index)
                    .ok_or_else(|| TtlvError::from("BigInt conversion error"))
                    .and_then(|v| {
                        self.child_index += 1;
                        visitor.visit_u32(*v)
                    })
            }
            TTLValue::Integer(i) => {
                if *i < 0 {
                    return Err(TtlvError::from("Cannot convert negative integer to u32"));
                }
                let value: u32 = u32::try_from(*i)
                    .map_err(|e| TtlvError::from(format!("Integer conversion error{e}")))?;
                visitor.visit_u32(value)
            }
            _ => Err(TtlvError::from(
                "Expected Integer ro BigInteger value in TTLV",
            )),
        }
    }

    #[instrument(skip(self, visitor))]
    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_u64: state:  {:?}", self.current);
        if let TTLValue::LongInteger(i) = &self.fetch_element()?.value {
            if *i < 0 {
                return Err(TtlvError::from("Cannot convert negative integer to u64"));
            }
            let value: u64 = (*i)
                .try_into()
                .map_err(|e| TtlvError::from(format!("Integer conversion error{e}")))?;
            visitor.visit_u64(value)
        } else {
            Err(TtlvError::from("Expected Integer value in TTLV"))
        }
    }

    #[instrument(skip(self, _visitor))]
    fn deserialize_f32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_f32: state:  {:?}", self.current);
        // there is no support for f32 in KMIP
        Err(TtlvError::from("f32 is not supported in KMIP"))
    }

    #[instrument(skip(self, _visitor))]
    fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_f64: state:  {:?}", self.current);
        // there is no support for f64 in KMIP
        Err(TtlvError::from("f64 is not supported in KMIP"))
    }

    #[instrument(skip(self, _visitor))]
    fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_char: state:  {:?}", self.current);
        unimplemented!("deserialize_char");
    }

    // Refer to the "Understanding deserializer lifetimes" page for information
    // about the three deserialization flavors of strings in Serde.
    #[instrument(skip(self, visitor))]
    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_str: map state: {:?}, index: {}, current:  {:?}",
            self.map_state,
            self.child_index,
            self.current
        );
        if self.map_state == MapAccessState::Key {
            // if the deserializer is deserializing the key of a map, the tag is the key
            return visitor.visit_str(&self.current.tag);
        }
        if let TTLValue::TextString(s) = &self.fetch_element()?.value {
            visitor.visit_str(s)
        } else {
            Err(TtlvError::from("Expected TextString value in TTLV"))
        }
    }

    #[instrument(skip(self, visitor))]
    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_string: state:  {:?}", self.current);
        self.deserialize_str(visitor)
    }

    #[instrument(skip(self, _visitor))]
    fn deserialize_bytes<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_bytes: state:  {:?}", self.current);
        unimplemented!("deserialize_bytes");
    }

    #[instrument(skip(self, _visitor))]
    fn deserialize_byte_buf<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_bytes_buff: state:  {:?}", self.current);
        unimplemented!("deserialize_byte_buf");
    }

    #[instrument(skip(self, visitor))]
    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_option: state:  {:?}", self.current);
        // No none in KMIP
        visitor.visit_some(self)
    }

    // In Serde, unit means an anonymous value containing no data.
    #[instrument(skip(self, _visitor))]
    fn deserialize_unit<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_unit: state:  {:?}", self.current);
        unimplemented!("deserialize_unit");
    }

    // Unit struct means a named value containing no data.
    #[instrument(skip(self, _visitor))]
    fn deserialize_unit_struct<V>(self, name: &'static str, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_unit_struct with name: {name}, state:  {:?}",
            self
        );
        unimplemented!("deserialize_unit_struct");
    }

    // As is done here, serializers are encouraged to treat newtype structs as
    // insignificant wrappers around the data they contain. That means not
    // parsing anything other than the contained value.
    #[instrument(skip(self, visitor))]
    fn deserialize_newtype_struct<V>(self, name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_new_type_struct with name: {name}, state:  {:?}",
            self.current
        );
        visitor.visit_newtype_struct(self)
    }

    // Deserialization of compound types like sequences and maps happens by
    // passing the visitor an "Access" object that gives it the ability to
    // iterate through the data contained in the sequence.
    #[instrument(skip(self, visitor))]
    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_seq: child index: {}, current :  {:?}",
            self.child_index,
            self.current
        );
        // There are 3 reasons why this method may be called:
        // 1. The deserializer is deserializing a sequence of TTLVs to reconstruct a flattened array
        // 2. The deserializer is deserializing the u32 array of a `BigUint`
        // 3. The deserializer is deserializing the bytes of a ByteString
        //
        // If the TTLV pointed at child_index is a BigInteger ==> deserialize a BigInt
        // If the TTLV pointed at child_index is a ByteString ==> deserialize a ByteString
        //
        // This strategy prevents deserializing flattened arrays with BigInts or ByteStrings,
        // but it is hard to do better than this, although we could inspect the next element to see if it
        // has the same tag.

        match &self.fetch_element()?.value {
            TTLValue::BigInteger(bi) => {
                // if the TTLV value is a BigInt, the deserializer is attempting to deserialize the value
                // by converting the BigInt to u32
                let seq_access = KmipBigIntDeserializer::instantiate(bi)?;
                visitor.visit_seq(seq_access)
            }
            TTLValue::ByteString(_) => {
                // if the TTLV value is a Structure, ByteString or Array, the deserializer is attempting to deserialize the children
                // by iterating over the children which hold the values of the sequence/array.
                // Reset the child index to 0 to start from the beginning
                self.child_index = 0;
                visitor.visit_seq(self)
            }
            _ => match self.current.value.clone() {
                TTLValue::Structure(children) => {
                    // Tag of the array to deserialize
                    let tag = &children
                        .get(self.child_index)
                        .ok_or_else(|| {
                            TtlvError::from(format!(
                                "Index out of bounds when accessing child array: {}",
                                self.child_index
                            ))
                        })?
                        .tag;
                    trace!("   ... finding seq with tag: {tag}");
                    // Deserialize an array using the ArrayDeserializer
                    let seq_access = ArrayDeserializer::new(self, tag, &children);
                    visitor.visit_seq(seq_access)
                }

                x => Err(TtlvError::from(format!("unexpected {x:?} value in TTLV"))),
            },
        }
    }

    // Tuples look just like sequences
    #[instrument(skip(self, visitor, _len))]
    fn deserialize_tuple<V>(self, _len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_tuple: child index: {}, current :  {:?}",
            self.child_index,
            self.current
        );
        // The only reason this is called is to deserialize BigInt
        match &self.fetch_element()?.value {
            // if the TTLV value is a BigInt, the deserializer is attempting to deserialize the value
            // by converting the BigInt to u32
            TTLValue::BigInteger(bi) => {
                let seq_access = KmipBigIntDeserializer::instantiate(bi)?;
                visitor.visit_seq(seq_access)
            }
            _ => Err(TtlvError::from("Expected a BigInteger value in TTLV")),
        }
    }

    // Tuple structs look just like sequences
    #[instrument(skip(self, _visitor))]
    fn deserialize_tuple_struct<V>(
        self,
        name: &'static str,
        len: usize,
        _visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_tuple_struct: name: {name}, len: {len},  state:  {:?}",
            self.current
        );
        unimplemented!("deserialize_tuple_struct");
    }

    /// There is no such thing as the concept of a Map in KMIP.
    /// KMIP structures are actually deserialized as `maps`, but
    /// the deserializer will call `deserialize_struct` to allow the deserializer,
    /// and the visitor will iterate over the children of the structure
    /// using logic in the `StructureWalker`.
    ///
    /// This method is actually called by the custom `Deserialize` implementations
    /// of untagged enums in KMIP, such as `Object`. The reason here is that the TTLV
    /// actually contains the name of the enum Variant, and recovering as a map key and passing
    /// it to the `Deserialize` `Visitor` implementation helps it to determine what variant
    /// it should use.
    ///
    /// For example, given this untagged enum:
    /// ```Rust
    /// #[serde(untagged)]
    /// pub enum Object {
    ///     /// A Managed Cryptographic Object that is the private portion of an asymmetric key pair.
    ///     PrivateKey {
    ///         #[serde(rename = "KeyBlock")]
    ///         key_block: KeyBlock,
    ///     },
    ///     /// A Managed Cryptographic Object that is the public portion of an asymmetric key pair.
    ///     /// This is only a public key, not a certificate.
    ///     PublicKey {
    ///         #[serde(rename = "KeyBlock")]
    ///         key_block: KeyBlock,
    ///     },
    ///     /// A Managed Cryptographic Object that is a symmetric key.
    ///     SymmetricKey {
    ///         #[serde(rename = "KeyBlock")]
    ///         key_block: KeyBlock,
    ///     },
    /// ```
    ///
    /// The TTLV for a SymmetricKey object would look like this:
    /// ```Rust
    /// TTLV {
    ///    tag: "SymmetricKey",
    ///    value: Structure([
    ///      TTLV {
    ///        tag: "KeyBlock",
    ///       value: Structure([...])
    ///     }
    ///  ])
    /// }
    /// ```
    /// Recovering the tag "SymmetricKey" and passing it to the visitor helps the visitor to determine
    /// that it should use the `Object::SymmetricKey` variant, since all variants have the same structure.
    #[instrument(skip(self, visitor))]
    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_map: state:  {:?}", self.current);
        visitor.visit_map(UntaggedEnumWalker::new(self))
    }

    /// Deserializing a struct.
    ///
    /// # Arguments
    /// * `name` - The name of the target struct
    /// * `fields` - The fields of the target struct
    /// * `visitor` - The visitor
    /// # Returns
    /// The result of the visitor
    ///
    // Notice the `fields` parameter - a "struct" in the Serde data model means
    // that the `Deserialize` implementation is required to know what the fields
    // are before even looking at the input data. Any key-value pairing in which
    // the fields cannot be known ahead of time is probably a map.
    #[instrument(skip(self, visitor))]
    fn deserialize_struct<V>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_struct: name {name}, fields: {fields:?} : state:  {:?}",
            self.current
        );
        // we are going to iterate over the children of the current TTLV by calling visit_map
        // set the child index to 0
        self.child_index = 0;
        visitor.visit_map(StructureWalker::new(self))
    }

    #[instrument(skip(self, visitor))]
    fn deserialize_enum<V>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_enum: name {name}, variants: {variants:?}, state:  {:?}",
            self
        );
        visitor.visit_enum(EnumWalker::new(self))
    }

    // An identifier in Serde is the type that identifies a field of a struct or
    // the variant of an enum. In TTLV, struct fields and enum variants are
    // represented as strings
    //
    // This method is typically called after a next_key_seed method call on a
    // MapAccess implementation, in order to deserialize the key of the field
    // for instance ÀnInt`` in
    // ```
    // TTLV { tag: "AnInt", value: Integer(1) }
    // ```
    #[instrument(skip(self, visitor))]
    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_identifier: current:  {:?}", self.current);

        match &self.fetch_element()?.value {
            TTLValue::Enumeration(e) => {
                //if the current item is an enumeration,
                // and the child index is 0 => deserialize the tag
                // else deserialize the variant
                if self.child_index == 0 {
                    trace!("... enum: tag: {}", self.current.tag);
                    visitor.visit_str(&self.current.tag)
                } else if e.name.is_empty() {
                    trace!("... enum: index: {}", e.value);
                    visitor.visit_u32(e.value)
                } else {
                    trace!("... enum: name: {}", e.name);
                    visitor.visit_str(&e.name)
                }
            }
            TTLValue::Structure(_) => {
                trace!("... structure: tag: {}", self.current.tag);
                // if the current item is a structure, it may be a KMIP Object
                // KMIP objects are always present in KMIP structures with "Object" as the property name.
                // So the deserializer is expecting "Object" as the identifier, not the tag/Object Name
                if kmip_2_1::kmip_objects::Object::VARIANTS.contains(&self.current.tag.as_str()) {
                    trace!("... structure: Object");
                    return visitor.visit_str("Object");
                }
                if kmip_1_4::kmip_objects::Object::VARIANTS.contains(&self.current.tag.as_str()) {
                    trace!("... structure: Object");
                    return visitor.visit_str("Object");
                }
                trace!("... structure: tag: {}", self.current.tag);
                visitor.visit_str(&self.current.tag)
            }
            // all other cases, we want the tag
            _ => {
                trace!("... tag: {}", self.current.tag);
                visitor.visit_str(&self.current.tag)
            }
        }
    }

    // Like `deserialize_any` but indicates to the `Deserializer` that it makes
    // no difference which `Visitor` method is called because the data is
    // ignored.
    //
    // Some deserializers are able to implement this more efficiently than
    // `deserialize_any`, for example, by rapidly skipping over matched
    // delimiters without paying close attention to the data in between.
    //
    // Some formats are not able to implement this at all. Formats that can
    // implement `deserialize_any` and `deserialize_ignored_any` are known as
    // self-describing.
    #[instrument(skip(self, visitor))]
    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_ignored_any: state:  {:?}", self.current);
        self.deserialize_any(visitor)
    }
}

impl<'de> SeqAccess<'de> for TtlvDeserializer {
    type Error = TtlvError;

    #[instrument(skip(self, seed))]
    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        trace!(
            "seq_access: next_element_seed: index: {}, current:  {:?}",
            self.child_index,
            self.current
        );

        match &self.current.value {
            TTLValue::Structure(child_array) => {
                // if the TTLV value is a Structure or Array, the deserializer is attempting to deserialize the children
                // by iterating over the children which hold the values of the sequence/array
                if self.child_index >= child_array.len() {
                    self.child_index = 0;
                    return Ok(None);
                }
                let child = child_array.get(self.child_index).ok_or_else(|| {
                    TtlvError::from("Index out of bounds when accessing child array")
                })?;
                let mut deserializer = Self::from_ttlv(child.clone());
                self.child_index += 1;
                seed.deserialize(&mut deserializer).map(Some)
            }
            TTLValue::ByteString(byte_array) => {
                if self.child_index >= byte_array.len() {
                    self.child_index = 0;
                    return Ok(None);
                }
                seed.deserialize(self).map(Some)
            }
            _ => Err(TtlvError::from(
                "Expected Structure, Array or ByteString value in TTLV",
            )),
        }
    }
}

// The `ArrayDeserializer` is used to deserialize an array from struct elements
/// It is called by the main deserializer when receiving Visitor requests to `deserialize_seq`
struct ArrayDeserializer<'a> {
    de: &'a mut TtlvDeserializer,
    // The tag of the array
    tag: String,
    // all the elements of the containing struct
    struct_elements: &'a [TTLV],
}

impl<'a> ArrayDeserializer<'a> {
    fn new(de: &'a mut TtlvDeserializer, tag: &str, struct_elements: &'a [TTLV]) -> Self {
        ArrayDeserializer {
            de,
            tag: tag.to_owned(),
            struct_elements,
        }
    }
}

impl<'a, 'de: 'a> SeqAccess<'de> for ArrayDeserializer<'a> {
    type Error = TtlvError;

    #[instrument(skip(self, seed))]
    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        trace!(
            "array_access: next_element_seed in seq: {}, current index: {}, structure elems:  {:?}",
            self.tag,
            self.de.child_index,
            self.struct_elements
        );
        // recover the current element
        // if the current index is out of bounds, we are done with this child
        let Some(current_element) = self.struct_elements.get(self.de.child_index) else {
            return Ok(None);
        };

        // if the tag of the current element is different from the tag of the array,
        // we are done with this child
        if current_element.tag != self.tag {
            // backtrack one on the index, because the index should point to the current element
            // in the struct. The index is incremented in the `next_value_seed` method of the Struct Walker
            self.de.child_index -= 1;
            return Ok(None);
        }

        // deserialize the current element
        let mut deserializer = TtlvDeserializer::from_ttlv(current_element.clone());
        // increment the current index
        self.de.child_index += 1;
        // deserialize the element
        let v = seed.deserialize(&mut deserializer).map(Some)?;
        Ok(v)
    }
}

/// The `StructureWalker` is used to deserialize a struct as a map of property -> values
/// It is called by the main deserializer when receiving Visitor requests to `deserialize_struct`
struct StructureWalker<'a> {
    de: &'a mut TtlvDeserializer,
}

impl<'a> StructureWalker<'a> {
    fn new(de: &'a mut TtlvDeserializer) -> Self {
        StructureWalker { de }
    }
}

// MapAccess is called when deserializing a struct because deserialize_struct called visit_map
// The current input is the top structure holding an array of TTLVs which are the fields of the struct/map.
// The calls to `next_value` are driven by the visitor,
// and it is up to this Access to synchronize and advance its counter
// over the struct fields (`self.index`) in this case
impl<'a, 'de: 'a> MapAccess<'de> for StructureWalker<'a> {
    type Error = TtlvError;

    #[instrument(skip(self, seed))]
    fn next_key_seed<K>(&mut self, seed: K) -> std::result::Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        trace!(
            "map access: next_key_seed: index: {}, current: {:?}",
            self.de.child_index,
            self.de.current
        );
        self.de.map_state = MapAccessState::Key;
        // get the child deserializer for a child at the current index
        let v = self.de.get_child_deserializer(seed, MapAccessState::Key)?;
        Ok(v)
    }

    #[instrument(skip(self, seed))]
    fn next_value_seed<V>(&mut self, seed: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        trace!(
            "next_value_seed:index: {}, current: {:?}",
            self.de.child_index,
            self.de.current
        );
        self.de.map_state = MapAccessState::Value;
        let res = seed.deserialize(&mut *self.de);
        self.de.child_index += 1;
        res
    }

    #[inline]
    fn size_hint(&self) -> Option<usize> {
        let TTLValue::Structure(child_array) = &self.de.current.value else {
            return Some(0_usize)
        };
        Some(child_array.len())
    }
}

/// The `UntaggedEnumWalker` is used to deserialize a struct as a map of property -> values
/// It is called by the main deserializer when receiving Visitor requests to `deserialize_struct`
struct UntaggedEnumWalker<'a> {
    de: &'a mut TtlvDeserializer,
    completed: bool,
}

impl<'a> UntaggedEnumWalker<'a> {
    fn new(de: &'a mut TtlvDeserializer) -> Self {
        UntaggedEnumWalker {
            de,
            completed: false,
        }
    }
}

impl<'a, 'de: 'a> MapAccess<'de> for UntaggedEnumWalker<'a> {
    type Error = TtlvError;

    fn next_key_seed<K>(&mut self, seed: K) -> std::result::Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        trace!(
            "Untagged Enum map: next_key_seed: completed?: {}, index: {}, current: {:?}",
            self.completed,
            self.de.child_index,
            self.de.current
        );
        if self.completed {
            return Ok(None);
        }
        // we want to recover the tag of the TTLV and pass it back to the visitor
        self.de.map_state = MapAccessState::Key;
        seed.deserialize(&mut *self.de).map(Some)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        trace!(
            "Untagged Enum map: next_value_seed: current:  {:?}",
            self.de.current
        );
        self.de.map_state = MapAccessState::Value;
        let res = seed.deserialize(&mut *self.de)?;
        self.completed = true;
        Ok(res)
    }

    #[inline]
    fn size_hint(&self) -> Option<usize> {
        let TTLValue::Structure(child_array) = &self.de.current.value else {
            return Some(0_usize)
        };
        Some(child_array.len())
    }
}

struct EnumWalker<'a> {
    de: &'a mut TtlvDeserializer,
}

impl<'a> EnumWalker<'a> {
    fn new(de: &'a mut TtlvDeserializer) -> Self {
        EnumWalker { de }
    }
}

// `EnumAccess` is provided to the `Visitor` to give it the ability to determine
// which variant of the enum is supposed to be deserialized.
//
// Note that all enum deserialization methods in Serde refer exclusively to the
// "externally tagged" enum representation.
impl<'de> EnumAccess<'de> for EnumWalker<'_> {
    type Error = TtlvError;
    type Variant = Self;

    #[instrument(skip(self, seed))]
    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant)>
    where
        V: DeserializeSeed<'de>,
    {
        trace!("variant_seed: state:  {:?}", self.de.current);
        // by setting the child index to 1, we are telling the deserializer
        // to deserialize the variant name and not the tag of the TTLV holding the variant
        self.de.child_index = 1;
        let val = seed.deserialize(&mut *self.de)?;
        self.de.child_index = 0;
        Ok((val, self))
    }
}

// `VariantAccess` is provided to the `Visitor` to give it the ability to see
// the content of the single variant that it decided to deserialize.
impl<'de> VariantAccess<'de> for EnumWalker<'_> {
    type Error = TtlvError;

    // If the `Visitor` expected this variant to be a unit variant, the input
    // should have been the plain string case handled in `deserialize_enum`.
    #[instrument(skip(self))]
    fn unit_variant(self) -> Result<()> {
        trace!("unit_variant: state:  {:?}", self.de.current);
        let TTLValue::Enumeration(_e) = &self.de.current.value else {
            return Err(TtlvError::from("Expected Enumeration value in TTLV"))
        };
        Ok(())
    }

    /// `variant` is called to identify which variant to deserialize.
    #[instrument(skip(self, _seed))]
    fn newtype_variant_seed<T>(self, _seed: T) -> Result<T::Value>
    where
        T: DeserializeSeed<'de>,
    {
        trace!("newtype_variant_seed: state:  {:?}", self.de.current);
        unimplemented!("newtype_variant_seed");
    }

    // Tuple variants are not in KMIP but, if any,
    // deserialize as a sequence of data here.
    #[instrument(skip(self, _visitor))]
    fn tuple_variant<V>(self, len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("tuple_variant of len: {len}, state:  {:?}", self.de.current);
        unimplemented!("tuple_variant");
    }

    // Struct variants are represented in JSON as `{ NAME: { K: V, ... } }` so
    // deserialize the inner map here.
    #[instrument(skip(self, _visitor))]
    fn struct_variant<V>(self, fields: &'static [&'static str], _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "struct_variant with fields: {fields:?}: state:  {:?}",
            self.de.current
        );
        unimplemented!("struct_variant");
    }
}

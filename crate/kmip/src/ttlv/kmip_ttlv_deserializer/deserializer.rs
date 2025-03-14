#![allow(dead_code)]
use serde::{
    de::{self, Visitor},
    Deserialize,
};
use strum::VariantNames;
use tracing::{instrument, trace};

use super::{array_deserializer::ArrayDeserializer, structure_walker::StructureWalker, Result};
use crate::{
    kmip_1_4, kmip_2_1,
    ttlv::{
        kmip_big_int_deserializer::KmipBigIntDeserializer,
        kmip_ttlv_deserializer::{
            byte_string_deserializer::ByteStringDeserializer, enum_walker::EnumWalker,
            untagged_enum_walker::UntaggedEnumWalker,
        },
        TTLValue, TtlvError, TTLV,
    },
};

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
pub(super) enum MapAccessState {
    // Not in a Map Axxess
    None,
    Key,
    Value,
}

#[derive(Debug)]
pub struct TtlvDeserializer {
    /// The current TTLV being deserialized
    pub(super) current: TTLV,
    /// The current child index in a structure being deserialized.
    /// Arrays in TTLV are represented as structures with children holding the array values
    /// The child index is also used in Enums deserialization to differentiate between the tag and the variant
    /// when deserializing an identifier (0; tag, 1; variant)
    pub(super) child_index: usize,
    /// The state of the deserializer when deserializing a map.
    /// The deserializer needs to know if it is deserializing the key or the value.
    /// This is handled in `MapAccess::next_key_seed` and `MapAccess::next_value_seed`.
    /// The deserializer starts with the key state
    /// When the key is deserialized, the state is changed to Value
    pub(super) map_state: MapAccessState,
    /// Determines whether the deserializer is at the root of the TTLV
    /// This is used to determine if the deserializer should deserialize the current TTLV as a structure
    /// or if it should deserialize the child pointed at by the child index
    at_root: bool,
}

impl TtlvDeserializer {
    #[must_use]
    pub const fn from_ttlv(root: TTLV) -> Self {
        Self {
            current: root,
            child_index: 0,
            map_state: MapAccessState::None,
            at_root: true,
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

    //
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
        // fetch the element
        let element = self.fetch_element()?;

        // if the self.map_state is Key, the deserializer is deserializing the key of a map
        // which is the tag of the TTLV
        if self.map_state == MapAccessState::Key {
            // if the deserializer is deserializing the key of a map, the tag is the key
            trace!(
                "deserialize_any: map access state: key, tag: {}",
                element.tag
            );
            return visitor.visit_str(&element.tag);
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

        match &element.value {
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
                visitor.visit_map(StructureWalker::new(&mut TtlvDeserializer {
                    current: element.clone(),
                    child_index: 0,
                    map_state: MapAccessState::None,
                    at_root: false,
                }))
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

        let element = self.fetch_element()?;
        match &element.value {
            TTLValue::BigInteger(bi) => {
                // if the TTLV value is a BigInt, assuming the deserializer is attempting to deserialize the value
                // by converting the BigInt to u32
                trace!("   ... assuming deserialization of BigInteger: {:?}", bi);
                let seq_access = KmipBigIntDeserializer::instantiate(bi)?;
                visitor.visit_seq(seq_access)
            }
            TTLValue::ByteString(bs) => {
                // if the TTLV value is a Structure, ByteString or Array, the deserializer is attempting to deserialize the children
                // by iterating over the children which hold the values of the sequence/array.
                // Reset the child index to 0 to start from the beginning
                trace!("   ... assuming deserialization of ByteString: {:?}", bs);
                let deserializer = ByteStringDeserializer::new(&element.tag, bs);
                visitor.visit_seq(deserializer)
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
                    trace!("   ... deserializing transparent seq with tag: {tag}");
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
        if self.at_root {
            // we are going to iterate over the children of the current TTLV by calling visit_map
            // set the child index to 0
            self.child_index = 0;
            // we are going to walk the element at the root of the TTLV
            // so we are not at the root anymore
            self.at_root = false;
            visitor.visit_map(StructureWalker::new(self))
        } else {
            let element = self.fetch_element()?;
            if let TTLValue::Structure(_) = &element.value {
                // if the TTLV value is a Structure, we will deserialize it using the StructureWalker
                // which will iterate over the children of the structure as it were a map of properties to values
                visitor.visit_map(StructureWalker::new(&mut TtlvDeserializer {
                    current: element.clone(),
                    child_index: 0,
                    map_state: MapAccessState::None,
                    at_root: false,
                }))
            } else {
                Err(TtlvError::from("Expected Structure value in TTLV"))
            }
        }
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
        trace!(
            "deserialize_identifier: child_index :{}, current:  {:?}",
            self.child_index,
            self.current
        );

        let element = self.fetch_element()?;

        if self.map_state == MapAccessState::Key {
            // if the deserializer is deserializing the key of a map, the tag is the key
            return visitor.visit_str(&element.tag);
        }

        match &element.value {
            TTLValue::Enumeration(e) => {
                //if the current item is an enumeration,
                // and the child index is 0 => deserialize the tag
                // else deserialize the variant
                if e.name.is_empty() {
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

// impl<'de> SeqAccess<'de> for TtlvDeserializer {
//     type Error = TtlvError;

//     #[instrument(skip(self, seed))]
//     fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
//     where
//         T: DeserializeSeed<'de>,
//     {
//         trace!(
//             "seq_access: next_element_seed: index: {}, current:  {:?}",
//             self.child_index,
//             self.current
//         );

//         match &self.current.value {
//             TTLValue::Structure(child_array) => {
//                 // if the TTLV value is a Structure or Array, the deserializer is attempting to deserialize the children
//                 // by iterating over the children which hold the values of the sequence/array
//                 if self.child_index >= child_array.len() {
//                     self.child_index = 0;
//                     return Ok(None);
//                 }
//                 let child = child_array.get(self.child_index).ok_or_else(|| {
//                     TtlvError::from("Index out of bounds when accessing child array")
//                 })?;
//                 let mut deserializer = Self::from_ttlv(child.clone());
//                 self.child_index += 1;
//                 seed.deserialize(&mut deserializer).map(Some)
//             }
//             TTLValue::ByteString(byte_array) => {
//                 if self.child_index >= byte_array.len() {
//                     self.child_index = 0;
//                     return Ok(None);
//                 }
//                 seed.deserialize(self).map(Some)
//             }
//             _ => Err(TtlvError::from(
//                 "Expected Structure, Array or ByteString value in TTLV",
//             )),
//         }
//     }
// }

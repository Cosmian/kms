use std::sync::RwLock;

use cosmian_logger::trace;
use serde::{
    Deserialize,
    de::{self, Visitor},
};
use strum::VariantNames;
use tracing::instrument;

use super::{Result, array_deserializer::ArrayDeserializer, structure_walker::StructureWalker};
use crate::{
    KmipResultHelper, kmip_1_4, kmip_2_1,
    ttlv::{
        TTLV, TTLValue, TtlvError,
        kmip_ttlv_deserializer::{
            adjacently_tagged_structure::AdjacentlyTaggedStructure,
            byte_string_deserializer::ByteStringDeserializer, enum_walker::EnumWalker,
            kmip_big_int_deserializer::KmipBigIntDeserializer,
            offset_date_time_deserializer::OffsetDateTimeDeserializer, peek_structure_child,
            untagged_enum_walker::UntaggedEnumWalker,
        },
        tags::BYTE_LIKE_TAGS,
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
    // Not in a Map Access
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
    pub(super) at_root: RwLock<bool>,
}

impl TtlvDeserializer {
    #[must_use]
    pub const fn from_ttlv(root: TTLV) -> Self {
        Self {
            current: root,
            child_index: 0,
            map_state: MapAccessState::None,
            at_root: RwLock::new(true),
        }
    }

    /// Peek the element that will be fetched next
    pub(super) fn peek_element(&self) -> Result<&TTLV> {
        // if we are at root, we want to look at the current value
        if *self.at_root.read().context("Failed to lock at_root")? {
            return Ok(&self.current);
        }
        // unwrap the structure if within a structure and get the child
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

    /// Fetch the element that will be deserialized next
    /// Updates the `at_root` status if the deserializer is at the root
    fn fetch_element(&self) -> Result<&TTLV> {
        let element = self.peek_element()?;
        // When we have fetched the value of en element at root,
        // we need to set the at_root status to false
        if *self.at_root.read().context("Failed to lock at_root")? {
            // if deserializing a Map key, leave the at root status set so that
            // the deserializer can deserialize the value while being at root
            if self.map_state != MapAccessState::Key {
                let mut at_root = self.at_root.write().context("Failed to lock at_root")?;
                *at_root = false;
            }
        }
        Ok(element)
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
    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_any: map access state: {:?}, index: {}, child: {:?}",
            self.map_state,
            self.child_index,
            peek_structure_child(&self.current, self.child_index)
        );
        // fetch the element
        // If the deserializer is at the root, the current TTLV is the root TTLV
        // If the deserializer is not at the root, the current TTLV is the child at the current child index
        // `deserialize_any` may be called from the root when deserializing an untagged enum for instance
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
                    at_root: RwLock::new(false),
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
                visitor.visit_seq(&mut ByteStringDeserializer::new(&self.current.tag, b))
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
                visitor.visit_i128(*dt)
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

    #[instrument(level = "trace", skip(self, visitor))]
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

    #[instrument(level = "trace", skip(self, visitor))]
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

    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_i16 state:  {:?}", self.current);
        match &self.fetch_element()?.value {
            TTLValue::Integer(i) => {
                let value: i16 = (*i)
                    .try_into()
                    .map_err(|e| TtlvError::from(format!("Integer conversion error{e}")))?;
                visitor.visit_i16(value)
            }
            TTLValue::BigInteger(bi) => {
                // Fallback: treat sign as i16 when deserializing part of BigInteger
                visitor.visit_i16(i16::from(bi.sign()))
            }
            TTLValue::LongInteger(i) => {
                let value: i16 = (*i)
                    .try_into()
                    .map_err(|e| TtlvError::from(format!("Integer conversion error{e}")))?;
                visitor.visit_i16(value)
            }
            _ => Err(TtlvError::from("Expected Integer value in TTLV for i16")),
        }
    }

    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_u8: state:  {:?}", self.current);
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
            TTLValue::LongInteger(i) => {
                if *i < 0 {
                    return Err(TtlvError::from(
                        "Cannot convert negative long integer to u8",
                    ));
                }
                let value: u8 = (*i)
                    .try_into()
                    .map_err(|e| TtlvError::from(format!("LongInteger conversion error{e}")))?;
                visitor.visit_u8(value)
            }
            TTLValue::Enumeration(e) => {
                // Some small numeric fields may have been encoded as Enumeration; accept if within range
                if e.value > u32::from(u8::MAX) {
                    return Err(TtlvError::from(format!(
                        "Enumeration value {} too large for u8",
                        e.value
                    )));
                }
                let value = u8::try_from(e.value).map_err(|_e| {
                    TtlvError::from("Enumeration value conversion to u8 failed".to_owned())
                })?;
                visitor.visit_u8(value)
            }
            x => Err(TtlvError::from(format!(
                "Expected Integer/LongInteger/Enumeration value in TTLV for u8, got: {x:?}"
            ))),
        }
    }

    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_u16: state:  {:?}", self.current);
        match &self.fetch_element()?.value {
            TTLValue::Integer(i) => {
                if *i < 0 {
                    return Err(TtlvError::from("Cannot convert negative integer to u16"));
                }
                let value: u16 = (*i)
                    .try_into()
                    .map_err(|e| TtlvError::from(format!("Integer conversion error{e}")))?;
                visitor.visit_u16(value)
            }
            _ => Err(TtlvError::from("Expected Integer value in TTLV for u16")),
        }
    }

    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_u32: state: {}: {:?}",
            self.child_index,
            peek_structure_child(&self.current, self.child_index)
        );
        match &self.fetch_element()?.value {
            TTLValue::BigInteger(bi) => {
                // Deserialize digits of a BigInteger as a sequence of u32 values
                bi.to_u32_digits()?
                    .1
                    .get(self.child_index)
                    .ok_or_else(|| TtlvError::from("BigInt conversion error"))
                    .and_then(|v| {
                        self.child_index += 1;
                        visitor.visit_u32(*v)
                    })
            }
            TTLValue::Interval(i) => visitor.visit_u32(*i),
            // This is for masks
            TTLValue::Integer(i) => {
                if *i < 0 {
                    return Err(TtlvError::from("Cannot convert negative integer to u32"));
                }
                let value: u32 = (*i)
                    .try_into()
                    .map_err(|e| TtlvError::from(format!("Integer conversion error{e}")))?;
                visitor.visit_u32(value)
            }
            v => Err(TtlvError::from(format!(
                "Expected BigInteger, Interval, Integer (for masks) value in TTLV for an u32, got \
                 : {v:?}"
            ))),
        }
    }

    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_i32: state:  {:?}", self.current);
        match &self.fetch_element()?.value {
            TTLValue::Integer(i) => visitor.visit_i32(*i),
            TTLValue::Interval(i) => {
                // KMIP Interval is encoded as an unsigned 32-bit value; accept it for i32 fields
                let v: i32 = (*i)
                    .try_into()
                    .map_err(|e| TtlvError::from(format!("Interval conversion error{e}")))?;
                visitor.visit_i32(v)
            }
            _ => Err(TtlvError::from("Expected Integer value in TTLV for i32")),
        }
    }

    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_i64: state:  {:?}", self.current);
        match &self.fetch_element()?.value {
            TTLValue::LongInteger(i) => visitor.visit_i64(*i),
            TTLValue::Integer(i) => {
                // KMIP Integer is 32-bit; widen to 64-bit when the target expects a LongInteger/i64.
                // This situation arises in some test vectors where XML supplies an <Integer> but
                // the model expects a LongInteger. Accept as a lossless widening.
                let widened: i64 = i64::from(*i);
                visitor.visit_i64(widened)
            }
            TTLValue::Interval(i) => {
                // KMIP 1.4 LeaseTime uses Interval (u32). This widening is for other i64 fields that accept Interval.
                visitor.visit_i64(i64::from(*i))
            }
            other => Err(TtlvError::from(format!(
                "Expected LongInteger (or Integer for widening) value in TTLV for i64, got: {other:?}"
            ))),
        }
    }

    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_u64: state:  {}: {:?}",
            self.child_index,
            peek_structure_child(&self.current, self.child_index)
        );
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

    #[instrument(level = "trace", skip(self, _visitor))]
    fn deserialize_f32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_f32: state:  {:?}", self.current);
        // there is no support for f32 in KMIP
        Err(TtlvError::from("f32 is not supported in KMIP"))
    }

    #[instrument(level = "trace", skip(self, _visitor))]
    fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_f64: state:  {:?}", self.current);
        // there is no support for f64 in KMIP
        Err(TtlvError::from("f64 is not supported in KMIP"))
    }

    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_i128<V>(self, visitor: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        // This is called when deserializing a DateTimeExtended
        // The value is a 128-bit integer
        let element = self.fetch_element()?;
        trace!("deserialize_i128: element: {:?}", element);
        if let TTLValue::DateTimeExtended(dt) = &element.value {
            visitor.visit_i128(*dt)
        } else {
            Err(TtlvError::from("Expected DateTimeExtended value in TTLV"))
        }
    }

    #[instrument(level = "trace", skip(self, _visitor))]
    fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_char: state:  {:?}", self.current);
        unimplemented!("deserialize_char");
    }

    // Refer to the "Understanding deserializer lifetimes" page for information
    // about the three deserialization flavors of strings in Serde.
    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let element = self.fetch_element()?;
        trace!(
            "deserialize_str: map state: {:?}, element tag: {}",
            self.map_state, element.tag
        );
        if self.map_state == MapAccessState::Key {
            // if the deserializer is deserializing the key of a map, the tag is the key
            trace!("... str: key: {}", element.tag);
            return visitor.visit_str(&element.tag);
        }
        if let TTLValue::TextString(s) = &element.value {
            trace!("... text string: value: {}", s);
            visitor.visit_str(s)
        } else if let TTLValue::ByteString(bytes) = &element.value {
            // Some KMIP 2.1 interop vectors encode ShortUniqueIdentifier as a ByteString even though
            // the internal representation in our model is a String. Coerce by hex encoding.
            if element.tag == "ShortUniqueIdentifier" {
                let hexed = hex::encode(bytes);
                trace!(
                    "... coerced ShortUniqueIdentifier ByteString -> hex string: {}",
                    hexed
                );
                visitor.visit_string(hexed)
            } else {
                let actual = "ByteString";
                Err(TtlvError::from(format!(
                    "deserialize_str: expected a TextString value in TTLV; tag='{}' actual={}",
                    element.tag, actual
                )))
            }
        } else {
            let actual = match &element.value {
                TTLValue::Integer(_) => "Integer",
                TTLValue::LongInteger(_) => "LongInteger",
                TTLValue::BigInteger(_) => "BigInteger",
                TTLValue::Enumeration(e) => {
                    if e.name.is_empty() {
                        "Enumeration(code)"
                    } else {
                        "Enumeration(name)"
                    }
                }
                TTLValue::Boolean(_) => "Boolean",
                TTLValue::ByteString(_) => "ByteString",
                TTLValue::DateTime(_) => "DateTime",
                TTLValue::DateTimeExtended(_) => "DateTimeExtended",
                TTLValue::Interval(_) => "Interval",
                TTLValue::Structure(_) => "Structure",
                TTLValue::TextString(_) => "TextString",
            };
            Err(TtlvError::from(format!(
                "deserialize_str: expected a TextString value in TTLV; tag='{}' actual={}",
                element.tag, actual
            )))
        }
    }

    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // trace!("deserialize_string: state:  {:?}", self.current);
        self.deserialize_str(visitor)
    }

    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // This is never called; all bytes deserialization goes via seq.
        // One reason for this is that JSON deserialization always goes via seq
        trace!("deserialize_bytes: state:  {:?}", self.current);
        let element = self.fetch_element()?;
        let TTLValue::ByteString(bytes) = &element.value else {
            return Err(TtlvError::from(
                "deserialize_bytes: expected a ByteString value in TTLV",
            ));
        };
        visitor.visit_bytes(bytes)
    }

    #[instrument(level = "trace", skip(self, _visitor))]
    fn deserialize_byte_buf<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_bytes_buff: state:  {:?}", self.current);
        unimplemented!("deserialize_byte_buf");
    }

    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_option: state:  {:?}", self.current);
        // No none in KMIP
        visitor.visit_some(self)
    }

    // In Serde, unit means an anonymous value containing no data.
    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_unit: state:  {:?}", self.current);
        // KMIP does not have an explicit Unit representation; when a unit is expected,
        // just signal an empty value to the visitor.
        visitor.visit_unit()
    }

    // Unit struct means a named value containing no data.
    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_unit_struct<V>(self, name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_unit_struct with name: {name}, state:  {:?}",
            self
        );
        // Treat unit structs as units; the name is only informational.
        visitor.visit_unit()
    }

    // As is done here, serializers are encouraged to treat newtype structs as
    // insignificant wrappers around the data they contain. That means not
    // parsing anything other than the contained value.
    #[instrument(level = "trace", skip(self, visitor))]
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
    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_seq: child index: {}: {:?}",
            self.child_index,
            peek_structure_child(&self.current, self.child_index)
        );
        let element = self.fetch_element()?.clone();
        if let TTLValue::BigInteger(bi) = &element.value {
            trace!("   ... assuming deserialization of BigInteger: {:?}", bi);
            let seq_access = KmipBigIntDeserializer::instantiate(bi)?;
            return visitor.visit_seq(seq_access);
        }
        if let TTLValue::ByteString(bs) = &element.value {
            trace!("   ... assuming deserialization of ByteString: {:?}", bs);
            let deserializer = ByteStringDeserializer::new(&element.tag, bs);
            return visitor.visit_seq(deserializer);
        }

        // Conservative structure-as-ByteString fallback for a whitelist of byte-vector tags
        if let TTLValue::Structure(children) = &element.value {
            fn collect_bytes(node: &TTLV, out: &mut Vec<u8>) -> bool {
                match &node.value {
                    TTLValue::ByteString(bs) => {
                        out.extend_from_slice(bs);
                        true
                    }
                    TTLValue::Integer(v) => u8::try_from(*v).is_ok_and(|b| {
                        out.push(b);
                        true
                    }),
                    TTLValue::Structure(inner) => {
                        for ch in inner {
                            if !collect_bytes(ch, out) {
                                return false;
                            }
                        }
                        true
                    }
                    _ => false,
                }
            }
            if BYTE_LIKE_TAGS.contains(&element.tag.as_str()) {
                let mut buf: Vec<u8> = Vec::new();
                let all_byte_like = children.iter().all(|ch| collect_bytes(ch, &mut buf));
                if all_byte_like {
                    trace!(
                        "   ... structure recognized as byte-like; concatenated len={} for tag {}",
                        buf.len(),
                        element.tag
                    );
                    let deserializer = ByteStringDeserializer::new(&element.tag, &buf);
                    return visitor.visit_seq(deserializer);
                }
            }
        }

        // Default: array deserialization using the parent structure context
        match self.current.value.clone() {
            TTLValue::Structure(children) => {
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
                let seq_access = ArrayDeserializer::new(self, tag, &children);
                visitor.visit_seq(seq_access)
            }
            x => Err(TtlvError::from(format!("unexpected {x:?} value in TTLV"))),
        }
    }

    // Tuples look just like sequences
    #[instrument(level = "trace", skip(self, visitor, _len))]
    fn deserialize_tuple<V>(self, _len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_tuple: child index: {}, current :  {:?}",
            self.child_index, self.current
        );
        // The only reason this is called is to deserialize BigInt
        match &self.fetch_element()?.value {
            // if the TTLV value is a BigInt, the deserializer is attempting to deserialize the value
            // by converting the BigInt to u32
            TTLValue::BigInteger(bi) => {
                let seq_access = KmipBigIntDeserializer::instantiate(bi)?;
                visitor.visit_seq(seq_access)
            }
            TTLValue::DateTime(dt) => {
                // if human_readable is not on the deserializer and the `time` crate (feature serde-human-readable),
                // `deserialize_tuple` will be called on the deserializer
                // see <https://github.com/time-rs/time/blob/main/time/src/serde/mod.rs#L320>
                // The `OffsetDateTime` visitor expects calls to `visit_seq` passing all the elements
                // og the tuple in order (year, day of year, hour, etc..)
                // see <https://github.com/time-rs/time/blob/main/time/src/serde/visitor.rs#L80>

                let seq_access = OffsetDateTimeDeserializer::new(&self.current.tag, *dt);
                visitor.visit_seq(seq_access)
            }
            _ => Err(TtlvError::from("Expected a BigInteger value in TTLV")),
        }
    }

    // Tuple structs look just like sequences
    #[instrument(level = "trace", skip(self, _visitor))]
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
    /// The TTLV for a `SymmetricKey` object would look like this:
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
    /// Recovering the tag "`SymmetricKey`" and passing it to the visitor helps the visitor to determine
    /// that it should use the `Object::SymmetricKey` variant, since all variants have the same structure.
    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // When directly deserializing an Object (e.g. Object::SymmetricKey),
        // `deserialize_map` is the entry point of the deserializer, so we are at root
        // and we need to deserialize the top/current element
        let element = self.fetch_element()?;
        trace!(
            "deserialize_map: calling Untagged Enum deserializer for: {:?}",
            element
        );
        visitor.visit_map(UntaggedEnumWalker::new(&mut TtlvDeserializer {
            current: element.clone(),
            child_index: 0,
            map_state: MapAccessState::None,
            at_root: RwLock::new(true),
        }))
    }

    /// Deserializing a struct.
    ///
    /// # Arguments
    /// * `name` - The name of the target struct
    /// * `fields` - The fields of the target struct
    /// * `visitor` - The visitor
    /// # Returns
    /// The result of the visitor
    // Notice the `fields` parameter - a "struct" in the Serde data model means
    // that the `Deserialize` implementation is required to know what the fields
    // are before even looking at the input data. Any key-value pairing in which
    // the fields cannot be known ahead of time is probably a map.
    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_struct<V>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let element = self.fetch_element()?;
        trace!(
            "deserialize_struct: name {name}, fields: {fields:?}, element: {:?}",
            element
        );

        if fields == ["_t", "_c"] {
            // This is a special case for the KMIP 2.1 Object, which has a _t and _c field
            // that are not part of the structure, but are used to identify the type of object
            // being deserialized.
            // The deserializer will skip these fields and deserialize the rest of the structure
            trace!("... deserializing an adjacently tagged structure");
            return visitor.visit_map(AdjacentlyTaggedStructure::new(&TtlvDeserializer {
                current: element.clone(),
                child_index: 0,
                map_state: MapAccessState::None,
                at_root: RwLock::new(false),
            }));
        }

        if let TTLValue::Structure(_) = &element.value {
            // if the TTLV value is a Structure, we will deserialize it using the StructureWalker
            // which will iterate over the children of the structure as it were a map of properties to values
            visitor.visit_map(StructureWalker::new(&mut TtlvDeserializer {
                current: element.clone(),
                child_index: 0,
                map_state: MapAccessState::None,
                at_root: RwLock::new(false),
            }))
        } else {
            Err(TtlvError::from(format!(
                "Expected Structure value in TTLV while deserializing struct '{name}' (tag='{}', actual={:?})",
                element.tag, element.value
            )))
        }
    }

    #[instrument(level = "trace", skip(self, visitor))]
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
            "deserialize_enum: name {name}, element: {:?}",
            self.peek_element()?
        );
        if *self.at_root.read().context("Failed to lock at_root")? {
            // The enum is the current structure
            trace!("... deserializing enum at root");
            visitor.visit_enum(EnumWalker::new(self))
        } else {
            // The enumeration the deserializer is deserializing is the only child of the current structure
            // This is typically the case of a property with an `Attribute`
            // ```Rust
            // struct A {
            //   new_attribute: Attribute // enum to deserialize
            // }
            // ```
            trace!("... deserializing enum that is the only child of the current element",);
            let element = self.fetch_element()?;

            match &element.value {
                // if the TTLV value is an Enumeration, we will deserialize it using the EnumWalker
                TTLValue::Enumeration(_) => visitor.visit_enum(EnumWalker::new(self)),
                // if the TTLV value is a Structure, we will deserialize the single child
                // using the EnumWalker
                TTLValue::Structure(children) => {
                    // Special case: KMIP 2.1 Vendor Attribute structure encoded directly as:
                    // <Attribute><VendorIdentification/><AttributeName/><AttributeValue/></Attribute>
                    // This has 3 children and should deserialize to the enum variant
                    // Attribute::VendorAttribute(VendorAttribute { .. }). Our strict single-child
                    // logic would normally reject this, so detect this pattern explicitly.
                    if element.tag == "Attribute" {
                        let mut has_vendor_id = false;
                        let mut has_attr_name = false;
                        let mut has_attr_value = false;
                        for c in children {
                            match c.tag.as_str() {
                                "VendorIdentification" => has_vendor_id = true,
                                "AttributeName" => has_attr_name = true,
                                "AttributeValue" => has_attr_value = true,
                                _ => {}
                            }
                        }
                        if has_vendor_id && has_attr_name && has_attr_value {
                            trace!(
                                "... detected VendorAttribute triple children; deserializing element itself as enum variant"
                            );
                            return visitor.visit_enum(EnumWalker::new(&mut TtlvDeserializer {
                                current: element.clone(),
                                child_index: 0,
                                map_state: MapAccessState::None,
                                at_root: RwLock::new(true),
                            }));
                        }
                    }
                    if children.len() != 1 {
                        // KMIP Attribute structures in some vectors may encode as:
                        // Attribute -> AttributeName + <ActualAttributeValueStructure>
                        // and may include an optional AttributeIndex.
                        // Prefer AttributeValue if present; otherwise fall back to the single
                        // non-AttributeName child.
                        let mut attribute_value_child: Option<TTLV> = None;
                        let mut non_name_candidate: Option<TTLV> = None;
                        for c in children {
                            if c.tag == "AttributeValue" {
                                attribute_value_child = Some(c.clone());
                            } else if c.tag != "AttributeName" {
                                if non_name_candidate.is_some() && attribute_value_child.is_none() {
                                    return Err(TtlvError::from(format!(
                                        "Deserializing an enum of tag: {}: unexpected multiple non-AttributeName children",
                                        element.tag
                                    )));
                                }
                                non_name_candidate = Some(c.clone());
                            }
                        }
                        let selected = attribute_value_child
                            .or(non_name_candidate)
                            .ok_or_else(|| {
                                TtlvError::from(format!(
                                    "Deserializing an enum of tag: {}: could not locate attribute value child",
                                    element.tag
                                ))
                            })?;
                        return visitor.visit_enum(EnumWalker::new(&mut TtlvDeserializer {
                            current: selected,
                            child_index: 0,
                            map_state: MapAccessState::None,
                            at_root: RwLock::new(true),
                        }));
                    }
                    visitor.visit_enum(EnumWalker::new(&mut TtlvDeserializer {
                        current: children
                            .first()
                            .ok_or_else(|| {
                                TtlvError::from(format!(
                                    "Deserializing an enum of tag: {}: expected a child structure",
                                    element.tag
                                ))
                            })?
                            .clone(),
                        child_index: 0,
                        map_state: MapAccessState::None,
                        at_root: RwLock::new(true),
                    }))
                }
                // if the TTLV value is a Structure, we will deserialize it using the StructureWalker
                // which will iterate over the children of the structure as it were a map of properties to values
                x => Err(TtlvError::from(format!(
                    "Deserializing an enum of tag: {}: expected a an Enumeration or a Structure \
                     as a value, got: {x:?}",
                    element.tag
                ))),
            }
        }
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
    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let element = self.fetch_element()?;
        trace!(
            "deserialize_identifier: map state: {:?}, element: {:?}",
            self.map_state, element
        );

        if self.map_state == MapAccessState::Key {
            // if the deserializer is deserializing the key of a map, the tag is the key
            // except for the corner case of Objects inside another structure, where the key is always "Object"
            if kmip_2_1::kmip_objects::Object::VARIANTS.contains(&element.tag.as_str())
                || kmip_1_4::kmip_objects::Object::VARIANTS.contains(&element.tag.as_str())
            {
                trace!("... => This is an Object => identifier: key: Object");
                return visitor.visit_str("Object");
            }
            trace!("... identifier: key: {}", element.tag);
            return visitor.visit_str(&element.tag);
        }

        match &element.value {
            TTLValue::Enumeration(e) => {
                // if the current item is an enumeration,
                // and the child index is 0 => deserialize the tag
                // else deserialize the variant
                if e.name.is_empty() {
                    trace!("... enum: index: {:#x}", e.value);
                    visitor.visit_u32(e.value)
                } else {
                    trace!("... enum: name: {}", e.name);
                    visitor.visit_str(&e.name)
                }
            }
            TTLValue::Structure(_) => {
                // if the current item is a structure, it may be a KMIP Object
                // KMIP objects are always present in KMIP structures with "Object" as the property name.
                // So the deserializer is expecting "Object" as the identifier, not the tag/Object Name
                if kmip_2_1::kmip_objects::Object::VARIANTS.contains(&element.tag.as_str()) {
                    trace!("... structure: 2.1 Object");
                    return visitor.visit_str("Object");
                }
                if kmip_1_4::kmip_objects::Object::VARIANTS.contains(&element.tag.as_str()) {
                    trace!("... structure: 1.4 Object");
                    return visitor.visit_str("Object");
                }
                trace!("... structure: tag: {}", element.tag);
                visitor.visit_str(&element.tag)
            }
            // all other cases, we want the tag
            _ => {
                trace!("... tag: {}", element.tag);
                visitor.visit_str(&element.tag)
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
    #[instrument(level = "trace", skip(self, visitor))]
    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_ignored_any: state:  {:?}", self.current);
        self.deserialize_any(visitor)
    }
}

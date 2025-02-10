#![allow(dead_code)]
use serde::{
    de::{self, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor},
    Deserialize,
};
use tracing::trace;

use super::{error::TtlvError, TTLV};
use crate::{
    // kmip_1_4::kmip_objects::{Object as Object14, ObjectType as ObjectType14},
    kmip_2_1::kmip_objects::{Object as Object21, ObjectType as ObjectType21},
    ttlv::TTLValue,
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
    // postfix the TTLV if it is a root object
    trait PostFix
    where
        Self: Sized,
    {
        fn post_fix(self, tag: &str) -> Result<Self>;
    }
    impl<T> PostFix for T {
        default fn post_fix(self, _tag: &str) -> Result<Self> {
            Ok(self)
        }
    }
    // impl PostFix for Object14 {
    //     fn post_fix(self, tag: &str) -> Result<Self> {
    //         let object_type = ObjectType14::try_from(tag)?;
    //         Ok(Self::post_fix(object_type, self))
    //     }
    // }
    impl PostFix for Object21 {
        fn post_fix(self, tag: &str) -> Result<Self> {
            let object_type = ObjectType21::try_from(tag)?;
            Ok(Self::post_fix(object_type, self))
        }
    }

    trace!("from_ttlv: {s:?}");
    // Recover the tag for postfixing
    let tag = s.tag.clone();
    // Deserialize the value
    // and postfix the value if it is a root object
    let mut deserializer = TtlvDeserializer::from_ttlv(s);
    let value = T::deserialize(&mut deserializer)?;

    value.post_fix(&tag)
}

#[derive(Debug)]
pub struct TtlvDeserializer {
    current: TTLV,
    child_index: usize,
}

impl TtlvDeserializer {
    #[must_use]
    pub const fn from_ttlv(root: TTLV) -> Self {
        Self {
            current: root,
            child_index: 0,
        }
    }
}

impl<'de> de::Deserializer<'de> for &mut TtlvDeserializer {
    type Error = TtlvError;

    // Look at the input data to decide what Serde data model type to
    // deserialize as. Not all data formats are able to support this operation.
    // Formats that support `deserialize_any` are known as self-describing.
    // #[instrument(skip(self, visitor))]
    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_any: state  {:?}", self.current);
        unimplemented!("deserialize_any");
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_bool<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_bool: state:  {:?}", self.current);
        unimplemented!("deserialize_bool");
    }

    // #[instrument(skip(self, _visitor))]
    fn deserialize_i8<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_i8: state: {:?}", self.current);
        unimplemented!("deserialize_i8");
    }

    // #[instrument(skip(self, _visitor))]
    fn deserialize_i16<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_i16 state:  {:?}", self.current);
        unimplemented!("deserialize_i16");
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_i32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_i32: state:  {:?}", self.current);
        unimplemented!("deserialize_i32");
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_i64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_i64: state:  {:?}", self.current);
        unimplemented!("deserialize_i64");
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_u8<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_u8: state:  {:?}", self.current);
        unimplemented!("deserialize_u8");
    }

    // #[instrument(skip(self, _visitor))]
    fn deserialize_u16<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_u16: state:  {:?}", self.current);
        unimplemented!("deserialize_u16");
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_u32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_u32: state:  {:?}", self.current);
        unimplemented!("deserialize_u32");
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_u64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_u64: state:  {:?}", self.current);
        unimplemented!("deserialize_u64");
    }

    // #[instrument(skip(self, _visitor))]
    fn deserialize_f32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_f32: state:  {:?}", self.current);
        unimplemented!("deserialize_f32");
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_f64: state:  {:?}", self.current);
        unimplemented!("deserialize_f64");
    }

    // #[instrument(skip(self, _visitor))]
    fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_char: state:  {:?}", self.current);
        unimplemented!("deserialize_char");
    }

    // Refer to the "Understanding deserializer lifetimes" page for information
    // about the three deserialization flavors of strings in Serde.
    // #[instrument(skip(self, visitor))]
    fn deserialize_str<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_str: state:  {:?}", self.current);
        unimplemented!("deserialize_str");
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_string<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_string: state:  {:?}", self.current);
        unimplemented!("deserialize_string");
    }

    // #[instrument(skip(self, _visitor))]
    fn deserialize_bytes<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_bytes: state:  {:?}", self.current);
        unimplemented!("deserialize_bytes");
    }

    // #[instrument(skip(self, _visitor))]
    fn deserialize_byte_buf<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_bytes_buff: state:  {:?}", self.current);
        unimplemented!("deserialize_byte_buf");
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_option<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_option: state:  {:?}", self.current);
        unimplemented!("deserialize_option");
    }

    // In Serde, unit means an anonymous value containing no data.
    // #[instrument(skip(self, _visitor))]
    fn deserialize_unit<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_unit: state:  {:?}", self.current);
        unimplemented!("deserialize_unit");
    }

    // Unit struct means a named value containing no data.
    // #[instrument(skip(self, _visitor))]
    fn deserialize_unit_struct<V>(self, _name: &'static str, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_unit_struct state:  {:?}", self.current);
        unimplemented!("deserialize_unit_struct");
    }

    // As is done here, serializers are encouraged to treat newtype structs as
    // insignificant wrappers around the data they contain. That means not
    // parsing anything other than the contained value.
    // #[instrument(skip(self, visitor))]
    fn deserialize_newtype_struct<V>(self, _name: &'static str, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_new_type_struct: state:  {:?}", self.current);
        unimplemented!("deserialize_newtype_struct");
    }

    // Deserialization of compound types like sequences and maps happens by
    // passing the visitor an "Access" object that gives it the ability to
    // iterate through the data contained in the sequence.
    // #[instrument(skip(self, visitor))]
    fn deserialize_seq<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_seq: state:  {:?}", self.current);
        unimplemented!("deserialize_seq");
    }

    // Tuples look just like sequences
    // #[instrument(skip(self, visitor))]
    fn deserialize_tuple<V>(self, len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_tuple, len: {len}, state:  {:?}", self.current);
        unimplemented!("deserialize_tuple");
    }

    // Tuple structs look just like sequences
    // #[instrument(skip(self, visitor))]
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

    // #[instrument(skip(self, visitor))]
    fn deserialize_map<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_map: state:  {:?}", self.current);
        unimplemented!("deserialize_map");
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
    // #[instrument(skip(self, visitor))]
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
        visitor.visit_map(self)
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_enum<V>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_enum: name {name}, variants: {variants:?}, state:  {:?}",
            self
        );
        unimplemented!("deserialize_enum");
    }

    // An identifier in Serde is the type that identifies a field of a struct or
    // the variant of an enum. In TTLV, struct fields and enum variants are
    // represented as strings
    // #[instrument(skip(self, visitor))]
    fn deserialize_identifier<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_identifier: state:  {:?}", self.current);
        unimplemented!("deserialize_identifier");
    }

    // Like `deserialize_any` but indicates to the `Deserializer` that it makes
    // no difference which `Visitor` method is called because the data is
    // ignored.
    //
    // Some deserializers are able to implement this more efficiently than
    // `deserialize_any`, for example by rapidly skipping over matched
    // delimiters without paying close attention to the data in between.
    //
    // Some formats are not able to implement this at all. Formats that can
    // implement `deserialize_any` and `deserialize_ignored_any` are known as
    // self-describing.
    // #[instrument(skip(self, visitor))]
    fn deserialize_ignored_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("deserialize_ignored_any: state:  {:?}", self.current);
        unimplemented!("deserialize_ignored_any");
    }
}

// MapAccess is called when deserializing a struct because deserialize_struct called visit_map
// The current input is the top structure holding an array of TTLVs which are the fields of the struct/map.
//
// The calls to `next_value` are driven by the visitor
// and it is up to this Access to synchronize and advance its counter
// over the struct fields (`self.index`) in this case
impl<'de> MapAccess<'de> for TtlvDeserializer {
    type Error = TtlvError;

    // #[instrument(skip(self, seed))]
    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: DeserializeSeed<'de>,
    {
        trace!("next_key_seed: state:  {:?}", self.current);
        // recover the next child
        let TTLValue::Structure(child_array) = &self.current.value else {
            return Ok(None)
        };
        if self.child_index >= child_array.len() {
            self.child_index = 0;
            return Ok(None);
        }
        let child = child_array
            .get(self.child_index)
            .ok_or_else(|| TtlvError::from("Index out of bounds when accessing child array"))?;
        let mut deserializer = Self::from_ttlv(child.clone());
        let v = seed.deserialize(&mut deserializer).map(Some)?;
        Ok(v)
    }

    // #[instrument(skip(self, seed))]
    fn next_value_seed<V>(&mut self, _seed: V) -> Result<V::Value>
    where
        V: DeserializeSeed<'de>,
    {
        trace!("next_value_seed: state:  {:?}", self.current);
        unimplemented!("next_value_seed");
    }
}

// `SeqAccess` is provided to the `Visitor` to give it the ability to iterate
// through elements of the sequence.
impl<'de> SeqAccess<'de> for TtlvDeserializer {
    type Error = TtlvError;

    // #[instrument(skip(self, seed))]
    fn next_element_seed<T>(&mut self, _seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        trace!("next_element_seed: state:  {:?}", self.current);
        unimplemented!("next_element_seed");
    }
}

struct EnumWalker<'a> {
    de: &'a mut TtlvDeserializer,
}

impl<'a> EnumWalker<'a> {
    // #[instrument(skip(de))]
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

    // #[instrument(skip(self, seed))]
    fn variant_seed<V>(self, _seed: V) -> Result<(V::Value, Self::Variant)>
    where
        V: DeserializeSeed<'de>,
    {
        trace!("variant_seed: state:  {:?}", self.de.current);
        unimplemented!("variant_seed");
    }
}

// `VariantAccess` is provided to the `Visitor` to give it the ability to see
// the content of the single variant that it decided to deserialize.
impl<'de> VariantAccess<'de> for EnumWalker<'_> {
    type Error = TtlvError;

    // If the `Visitor` expected this variant to be a unit variant, the input
    // should have been the plain string case handled in `deserialize_enum`.
    // #[instrument(skip(self))]
    fn unit_variant(self) -> Result<()> {
        trace!("unit_variant: state:  {:?}", self.de.current);
        unimplemented!("unit_variant");
    }

    /// `variant` is called to identify which variant to deserialize.
    // #[instrument(skip(self, seed))]
    fn newtype_variant_seed<T>(self, _seed: T) -> Result<T::Value>
    where
        T: DeserializeSeed<'de>,
    {
        trace!("newtype_variant_seed: state:  {:?}", self.de.current);
        unimplemented!("newtype_variant_seed");
    }

    // Tuple variants are not in KMIP but, if any,
    // deserialize as a sequence of data here.
    // #[instrument(skip(self, visitor))]
    fn tuple_variant<V>(self, _len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("tuple_variant: state:  {:?}", self.de.current);
        unimplemented!("tuple_variant");
    }

    // Struct variants are represented in JSON as `{ NAME: { K: V, ... } }` so
    // deserialize the inner map here.
    // #[instrument(skip(self, visitor))]
    fn struct_variant<V>(self, _fields: &'static [&'static str], _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!("struct_variant: state:  {:?}", self.de.current);
        unimplemented!("struct_variant");
    }
}

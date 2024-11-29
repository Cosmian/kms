#![allow(clippy::indexing_slicing)]
use serde::{
    de::{self, DeserializeSeed, EnumAccess, Error, MapAccess, SeqAccess, VariantAccess, Visitor},
    Deserialize,
};
use time::format_description::well_known::Rfc3339;
use tracing::trace;

use crate::kmip::{
    kmip_objects::{Object, ObjectType},
    ttlv::{error::TtlvError, to_u32_digits, TTLVEnumeration, TTLValue, TTLV},
};

type Result<T> = std::result::Result<T, TtlvError>;

/// The current input being deserialized
#[derive(Debug, PartialEq)]
enum Deserializing {
    StructureTag,
    StructureValue,
    ByteString,
    BigInt,
}

#[derive(Debug)]
enum Inputs<'de> {
    Structure(Vec<&'de TTLV>),
    Bytes(&'de [u8]),
    BigInt(Vec<u32>),
}

#[derive(Debug)]
pub struct TtlvDeserializer<'de> {
    /// whether a tag or a value is being deserialized with this serializer
    deserializing: Deserializing,
    /// the index+1 of the TTLV being processed
    /// 0 is reserved so that visitors can increase then process
    index: usize,
    /// the inputs being deserialized, index gives the current input
    inputs: Inputs<'de>,
}

impl<'de> TtlvDeserializer<'de> {
    #[must_use]
    pub fn from_ttlv(root: &'de TTLV) -> Self {
        TtlvDeserializer {
            deserializing: Deserializing::StructureValue,
            inputs: Inputs::Structure(vec![root]),
            index: 1,
        }
    }

    fn get_structure(&self) -> Result<&[&'de TTLV]> {
        match &self.inputs {
            Inputs::Structure(children) => Ok(children),
            _ => Err(TtlvError::custom(format!(
                "Unable to get TTLV Structure children. Currently deserializing {:#?}",
                &self.deserializing
            ))),
        }
    }

    fn get_bytes(&self) -> Result<&'de [u8]> {
        match &self.inputs {
            Inputs::Bytes(bytes) => Ok(*bytes),
            _ => Err(TtlvError::custom(format!(
                "Unable to get ByteString bytes. Currently deserializing {:#?}",
                &self.deserializing
            ))),
        }
    }

    fn get_bigint(&self) -> Result<&[u32]> {
        match &self.inputs {
            Inputs::BigInt(array) => Ok(array),
            _ => Err(TtlvError::custom(format!(
                "Unable to get BigInt array. Currently deserializing {:#?}",
                &self.deserializing
            ))),
        }
    }
}

/// Parse a KMIP structure from its TTLV value.
///
/// Note: `Objects` are untagged enums, so it is impossible to know the type of the Object
/// unless the root value being deserialized is an object, in which case,
/// the tag is the name of the variant.
///
/// #see `Object::post_fix()`
pub fn from_ttlv<'a, T>(s: &'a TTLV) -> Result<T>
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
    impl PostFix for Object {
        fn post_fix(self, tag: &str) -> Result<Self> {
            let object_type = ObjectType::try_from(tag)?;
            Ok(Self::post_fix(object_type, self))
        }
    }

    let mut deserializer = TtlvDeserializer::from_ttlv(s);
    let value = T::deserialize(&mut deserializer)?;

    value.post_fix(s.tag.as_str())
}

impl<'de> de::Deserializer<'de> for &mut TtlvDeserializer<'de> {
    type Error = TtlvError;

    // Look at the input data to decide what Serde data model type to
    // deserialize as. Not all data formats are able to support this operation.
    // Formats that support `deserialize_any` are known as self-describing.
    // #[instrument(skip(self, visitor))]
    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "deserialize_any  {:?}:  {:?} -> {:?}",
            self.deserializing,
            self.index,
            self.inputs
        );
        if self.deserializing == Deserializing::ByteString {
            return visitor.visit_u8(self.get_bytes()?[self.index - 1])
        }
        if self.deserializing == Deserializing::BigInt {
            return visitor.visit_u32(self.get_bigint()?[self.index - 1])
        }
        if self.deserializing == Deserializing::StructureTag {
            return visitor.visit_borrowed_str(&self.get_structure()?[self.index - 1].tag)
        }
        // deserializing the value of the child of a Structure
        let child = &self.get_structure()?[self.index - 1];
        let child_tag = &child.tag;
        let child_value = &child.value;
        trace!("deserialize_any child value {child_value:?}");
        match child_value {
            TTLValue::Structure(elements) => {
                trace!("deserialize_any self {self:?}");
                let ttlv_de = TtlvDeserializer {
                    deserializing: Deserializing::StructureValue,
                    inputs: Inputs::Structure(elements.iter().collect::<Vec<&TTLV>>()), // can probably do better
                    // start at 0 because the Visit Map is going to increment first
                    index: 0,
                };
                if elements.is_empty() || child_tag == &elements[0].tag {
                    // in TTLV when the elements tags are identical to the parent tag,
                    // it is a sequence
                    visitor.visit_seq(ttlv_de)
                } else {
                    visitor.visit_map(ttlv_de)
                }
            }
            TTLValue::Integer(i) => visitor.visit_i32(*i),
            TTLValue::BitMask(e) => visitor.visit_u32(*e),
            TTLValue::LongInteger(li) => visitor.visit_i64(*li),
            TTLValue::Enumeration(e) => match e {
                TTLVEnumeration::Integer(i) => visitor.visit_i32(*i),
                TTLVEnumeration::Name(n) => visitor.visit_str(n),
            },
            TTLValue::ByteString(b) => visitor.visit_seq(TtlvDeserializer {
                deserializing: Deserializing::ByteString,
                inputs: Inputs::Bytes(b),
                // start at 0 because the Visit Map is going to increment first
                index: 0,
            }),
            TTLValue::BigInteger(e) => visitor.visit_seq(TtlvDeserializer {
                deserializing: Deserializing::BigInt,
                inputs: Inputs::BigInt(to_u32_digits(e)?),
                // start at 0 because the Visit Map is going to increment first
                index: 0,
            }),
            TTLValue::TextString(s) => visitor.visit_str(s),
            TTLValue::Boolean(b) => visitor.visit_bool(*b),
            TTLValue::DateTime(dt) => visitor.visit_str(&dt.format(&Rfc3339).map_err(|err| {
                TtlvError::custom(format!("Cannot format DateTime {dt} into RFC3339: {err}"))
            })?),
            TTLValue::Interval(i) => visitor.visit_u32(*i),
            TTLValue::DateTimeExtended(dte) => {
                visitor.visit_str(&dte.format(&Rfc3339).map_err(|err| {
                    TtlvError::custom(format!(
                        "Cannot format DateTimeExtended {dte} into RFC3339: {err}"
                    ))
                })?)
            }
        }
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // this can only happen for `Deserializing::Value`
        let child = &self.get_structure()?[self.index - 1].value;
        visitor.visit_bool(match child {
            TTLValue::Boolean(b) => *b,
            x => return Err(TtlvError::custom(format!("Invalid type for bool: {x:?}"))),
        })
    }

    // #[instrument(skip(self, _visitor))]
    fn deserialize_i8<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::custom(
            "Unable to deserialize an i8 value. Not supported in KMIP:".to_owned(),
        ))
    }

    // #[instrument(skip(self, _visitor))]
    fn deserialize_i16<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::custom(
            "Unable to deserialize an i16 value. Not supported in KMIP:".to_owned(),
        ))
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // this can only happen for `Deserializing::Value`
        let child = &self.get_structure()?[self.index - 1].value;
        visitor.visit_i32(match child {
            TTLValue::Integer(v) => *v,
            x => return Err(TtlvError::custom(format!("Invalid type for i32: {x:?}"))),
        })
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // this can only happen for `Deserializing::Value`
        let child = &self.get_structure()?[self.index - 1].value;
        visitor.visit_i64(match child {
            TTLValue::LongInteger(v) => *v,
            x => return Err(TtlvError::custom(format!("Invalid type for i64: {x:?}"))),
        })
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        match &self.deserializing {
            Deserializing::ByteString => {
                let u = &self.get_bytes()?[self.index - 1];
                visitor.visit_u8(*u)
            }
            Deserializing::StructureValue => {
                let child = &self.get_structure()?[self.index - 1];
                trace!("deserialize_u8 child {child:?}");
                match &child.value {
                    TTLValue::Integer(i) => visitor.visit_i32(*i),
                    x => Err(TtlvError::custom(format!(
                        "deserialize_u8. Invalid type for value: {x:?}"
                    ))),
                }
            }
            x => Err(TtlvError::custom(format!(
                "deserialize_u8. Unexpected {x:?}"
            ))),
        }
    }

    // #[instrument(skip(self, _visitor))]
    fn deserialize_u16<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::custom(
            "Unable to deserialize a u16 value. Not supported in KMIP:".to_owned(),
        ))
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        match &self.deserializing {
            Deserializing::BigInt => {
                let u = &self.get_bigint()?[self.index - 1];
                visitor.visit_u32(*u)
            }
            Deserializing::StructureValue => {
                let child = &self.get_structure()?[self.index - 1].value;
                visitor.visit_u32(match child {
                    TTLValue::Integer(v) => (*v)
                        .try_into()
                        .map_err(|_e| TtlvError::custom(format!("Invalid type for u32: {v:?}")))?,
                    TTLValue::BitMask(v) => *v,
                    x => return Err(TtlvError::custom(format!("Invalid type for u32: {x:?}"))),
                })
            }
            x => Err(TtlvError::custom(format!(
                "deserialize_str. Unexpected {x:?}"
            ))),
        }
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // this can only happen for `Deserializing::Value`
        let child = &self.get_structure()?[self.index - 1].value;
        visitor.visit_u64(match child {
            TTLValue::LongInteger(v) => (*v)
                .try_into()
                .map_err(|_e| TtlvError::custom(format!("Invalid type for u64: {v:?}")))?,
            x => return Err(TtlvError::custom(format!("Invalid type for u64: {x:?}"))),
        })
    }

    // #[instrument(skip(self, _visitor))]
    fn deserialize_f32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::custom(
            "Unable to deserialize a f32 value. Not supported in KMIP:".to_owned(),
        ))
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // this can only happen for `Deserializing::Value`
        let child = &self.get_structure()?[self.index - 1].value;
        visitor.visit_f64(match child {
            TTLValue::Integer(v) => f64::from(*v),
            x => return Err(TtlvError::custom(format!("Invalid type for f64: {x:?}"))),
        })
    }

    // #[instrument(skip(self, _visitor))]
    fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::custom(
            "Unable to deserialize a char value. Not supported in KMIP:".to_owned(),
        ))
    }

    // Refer to the "Understanding deserializer lifetimes" page for information
    // about the three deserialization flavors of strings in Serde.
    // #[instrument(skip(self, visitor))]
    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        match &self.deserializing {
            Deserializing::StructureTag => {
                let tag = &self.get_structure()?[self.index - 1].tag;
                visitor.visit_borrowed_str(tag)
            }
            Deserializing::StructureValue => {
                let value = &self.get_structure()?[self.index - 1].value;
                match value {
                    TTLValue::TextString(v) => visitor.visit_borrowed_str(v),
                    TTLValue::Enumeration(v) => match v {
                        TTLVEnumeration::Integer(i) => Err(TtlvError::custom(format!(
                            "deserialize_str. Unexpected integer in enumeration: {i:?}"
                        ))),
                        TTLVEnumeration::Name(n) => visitor.visit_borrowed_str(n),
                    },
                    x => Err(TtlvError::custom(format!(
                        "deserialize_str. Invalid type for string: {x:?}"
                    ))),
                }
            }
            x => Err(TtlvError::custom(format!(
                "deserialize_str. Unexpected {x:?}"
            ))),
        }
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    // #[instrument(skip(self, _visitor))]
    fn deserialize_bytes<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::custom(
            "Unable to deserialize a byte array (not in a ByteString). Not supported in KMIP:"
                .to_owned(),
        ))
    }

    // #[instrument(skip(self, _visitor))]
    fn deserialize_byte_buf<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::custom(
            "Unable to deserialize a byte array (not in a ByteString). Not supported in KMIP:"
                .to_owned(),
        ))
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        // No none in KMIP
        visitor.visit_some(self)
    }

    // In Serde, unit means an anonymous value containing no data.
    // #[instrument(skip(self, _visitor))]
    fn deserialize_unit<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::custom(
            "Unable to deserialize unit. Not supported in KMIP:".to_owned(),
        ))
    }

    // Unit struct means a named value containing no data.
    // #[instrument(skip(self, _visitor))]
    fn deserialize_unit_struct<V>(self, _name: &'static str, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(TtlvError::custom(
            "Unable to deserialize unit struct. Not supported in KMIP:".to_owned(),
        ))
    }

    // As is done here, serializers are encouraged to treat newtype structs as
    // insignificant wrappers around the data they contain. That means not
    // parsing anything other than the contained value.
    // #[instrument(skip(self, visitor))]
    fn deserialize_newtype_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    // Deserialization of compound types like sequences and maps happens by
    // passing the visitor an "Access" object that gives it the ability to
    // iterate through the data contained in the sequence.
    // #[instrument(skip(self, visitor))]
    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        match self.deserializing {
            Deserializing::StructureTag => Err(TtlvError::custom(
                "deserialize_seq. A seq should not be deserialized when deserializing a tag"
                    .to_owned(),
            )),
            Deserializing::StructureValue => {
                let value = &self.get_structure()?[self.index - 1].value;
                match value {
                    TTLValue::ByteString(array) =>
                    // go down one level by deserializing the inner structure
                    {
                        visitor.visit_seq(TtlvDeserializer {
                            deserializing: Deserializing::ByteString,
                            inputs: Inputs::Bytes(array),
                            // start at 0 because the Visit Map is going to increment first
                            index: 0,
                        })
                    }
                    TTLValue::BigInteger(big_int) =>
                    // go down one level by deserializing the inner structure
                    {
                        visitor.visit_seq(TtlvDeserializer {
                            deserializing: Deserializing::BigInt,
                            inputs: Inputs::BigInt(to_u32_digits(big_int)?),
                            index: 0,
                        })
                    }
                    TTLValue::Structure(array) => {
                        // go down one level by deserializing the inner structure
                        visitor.visit_seq(TtlvDeserializer {
                            deserializing: Deserializing::StructureValue,
                            inputs: Inputs::Structure(array.iter().collect::<Vec<&TTLV>>()), // can probably do better
                            // start at 0 because the Visit Map is going to increment first
                            index: 0,
                        })
                    }
                    x => Err(TtlvError::custom(format!(
                        "deserialize_seq. Invalid type for value: {x:?}"
                    ))),
                }
            }
            Deserializing::ByteString => {
                // already at the ByteString level, visit it
                visitor.visit_seq(self)
            }
            Deserializing::BigInt => {
                // already at the BigInt level, visit it
                visitor.visit_seq(self)
            }
        }
    }

    // Tuples look just like sequences
    // #[instrument(skip(self, visitor))]
    fn deserialize_tuple<V>(self, _len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    // Tuple structs look just like sequences
    // #[instrument(skip(self, visitor))]
    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        match &self.deserializing {
            Deserializing::StructureValue => {
                let value = &self.get_structure()?[self.index - 1].value;
                match value {
                    TTLValue::Structure(array) => {
                        // go down one level by deserializing the inner structure
                        visitor.visit_map(TtlvDeserializer {
                            deserializing: Deserializing::StructureValue,
                            inputs: Inputs::Structure(array.iter().collect::<Vec<&TTLV>>()), // can probably do better
                            // start at 0 because the Visit Map is going to increment first
                            index: 0,
                        })
                    }
                    x => Err(TtlvError::custom(format!(
                        "deserialize_map. Invalid type for value: {x:?}"
                    ))),
                }
            }
            x => Err(TtlvError::custom(format!(
                "deserialize_map. A map should not be deserialized when deserializing a {x:?}"
            ))),
        }
    }

    // Structs look just like maps in KMIP.
    //
    // Notice the `fields` parameter - a "struct" in the Serde data model means
    // that the `Deserialize` implementation is required to know what the fields
    // are before even looking at the input data. Any key-value pairing in which
    // the fields cannot be known ahead of time is probably a map.
    // #[instrument(skip(self, visitor))]
    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_map(visitor)
    }

    // #[instrument(skip(self, visitor))]
    fn deserialize_enum<V>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        match &self.deserializing {
            Deserializing::StructureTag => Err(TtlvError::custom(
                "deserialize_enum. An enum should not be deserialized when deserializing a tag"
                    .to_owned(),
            )),
            Deserializing::StructureValue => {
                let value = &self.get_structure()?[self.index - 1].value;
                trace!(
                    "\ndeserialize_enum {}: {:?}, \n[{}]: {:#?}\n",
                    name,
                    variants,
                    &self.index - 1,
                    &value
                );
                match value {
                    TTLValue::Enumeration(_e) => visitor.visit_enum(EnumWalker::new(self)),
                    // TTLValue::Structure(_s) => visitor.visit_enum(EnumWalker::new(self)),
                    x => Err(TtlvError::custom(format!(
                        "deserialize_enum. Invalid type for value: {x:?}"
                    ))),
                }
            }
            x => Err(TtlvError::custom(format!(
                "deserialize_enum. An enum should not be deserialized when deserializing a {x:?}"
            ))),
        }
    }

    // An identifier in Serde is the type that identifies a field of a struct or
    // the variant of an enum. In TTLV, struct fields and enum variants are
    // represented as strings
    // #[instrument(skip(self, visitor))]
    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        match &self.deserializing {
            Deserializing::StructureTag => {
                //go ahead deserialize the tag
                self.deserialize_str(visitor)
            }
            Deserializing::StructureValue => {
                let value = &self.get_structure()?[self.index - 1].value;
                match value {
                    TTLValue::Enumeration(v) => match v {
                        TTLVEnumeration::Integer(_i) => self.deserialize_i32(visitor),
                        TTLVEnumeration::Name(_n) => self.deserialize_str(visitor),
                    },
                    x => Err(TtlvError::custom(format!(
                        "deserialize_identifier. Invalid type for value: {x:?}"
                    ))),
                }
            }
            x => Err(TtlvError::custom(format!(
                "deserialize_identifier. An identifier should not be deserialized when \
                 deserializing a {x:?}"
            ))),
        }
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
    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_any(visitor)
    }
}

// MapAccess is called when deserializing a struct
// The calls to `next_value` are driven by the visitor
// and it is up to this Access to synchronize and advance its counter
// over the struct fields (`self.index`) in this case
impl<'de> MapAccess<'de> for TtlvDeserializer<'de> {
    type Error = TtlvError;

    // #[instrument(skip(self, seed))]
    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: DeserializeSeed<'de>,
    {
        match &self.deserializing {
            Deserializing::StructureTag => Err(TtlvError::custom(
                "next_key_seed. An next key seed should not be deserialized when deserializing a \
                 Tag"
                .to_owned(),
            )),
            Deserializing::StructureValue => {
                // Check if there are no more elements.
                self.index += 1;
                let children = &self.get_structure()?;
                if self.index > children.len() {
                    return Ok(None)
                }

                trace!(
                    "next_key_seed : {:#?}",
                    &self.get_structure()?[self.index - 1].tag
                );

                // tell the deserializer that it is now going
                // to deserialize the `tag` value of the next key
                self.deserializing = Deserializing::StructureTag;

                // Deserialize a map key.
                // This will trigger a call `deserialize_identifier()`
                // on the injected Deserializer (`self` in this case)
                seed.deserialize(self).map(Some)
            }
            x => Err(TtlvError::custom(format!(
                "next_key_seed. An next key seed should not be deserialized when deserializing a \
                 {x:?}"
            ))),
        }
    }

    // #[instrument(skip(self, seed))]
    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: DeserializeSeed<'de>,
    {
        match &self.deserializing {
            Deserializing::StructureTag => {
                // go ahead deserialize the value (index was advanced by a call to
                // next_key_seed) ). This will trigger a call to the
                // corresponding `deserialize_xxx()` method on the injected
                // Deserializer (`self` in this case)
                self.deserializing = Deserializing::StructureValue;
                seed.deserialize(self)
            }
            Deserializing::StructureValue => Err(TtlvError::custom(
                "next_value_seed. A next value seed should not be deserialized when already \
                 deserializing a Value"
                    .to_owned(),
            )),
            x => Err(TtlvError::custom(format!(
                "next_value_seed. A next value seed should not be deserialized when deserializing \
                 a {x:?}"
            ))),
        }
    }
}

// `SeqAccess` is provided to the `Visitor` to give it the ability to iterate
// through elements of the sequence.
impl<'de> SeqAccess<'de> for TtlvDeserializer<'de> {
    type Error = TtlvError;

    // #[instrument(skip(self, seed))]
    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        match &self.deserializing {
            Deserializing::StructureValue => {
                // Check if there are no more elements.
                self.index += 1;
                let children = &self.get_structure()?;
                if self.index > children.len() {
                    return Ok(None)
                }
                // tell the deserializer that it is going to deserialize the value
                self.deserializing = Deserializing::StructureValue;

                // go ahead deserialize it (index was advanced by a call to next_key_seed) ).
                // This will trigger a call to the corresponding `deserialize_xxx()`
                // method on the injected Deserializer (`self` in this case)
                seed.deserialize(self).map(Some)
            }
            Deserializing::ByteString => {
                // Check if there are no more elements.
                self.index += 1;
                let children = &self.get_bytes()?;
                if self.index > children.len() {
                    return Ok(None)
                }
                // tell the deserializer that it is going to deserialize the bytes
                self.deserializing = Deserializing::ByteString;

                // go ahead deserialize it (index was advanced by a call to next_key_seed) ).
                // This will trigger a call to the corresponding `deserialize_xxx()`
                // method on the injected Deserializer (`self` in this case)
                seed.deserialize(self).map(Some)
            }
            Deserializing::BigInt => {
                // Check if there are no more elements.
                self.index += 1;
                let children = self.get_bigint()?;
                if self.index > children.len() {
                    return Ok(None)
                }
                // tell the deserializer that it is going to deserialize the bytes
                self.deserializing = Deserializing::BigInt;

                // go ahead deserialize it (index was advanced by a call to next_key_seed) ).
                // This will trigger a call to the corresponding `deserialize_xxx()`
                // method on the injected Deserializer (`self` in this case)
                seed.deserialize(self).map(Some)
            }
            x @ Deserializing::StructureTag => Err(TtlvError::custom(format!(
                "next_element_seed. A next element seed should not be deserialized when \
                 deserializing a {x:?}"
            ))),
        }
    }
}

struct EnumWalker<'a, 'de: 'a> {
    de: &'a mut TtlvDeserializer<'de>,
}

impl<'a, 'de> EnumWalker<'a, 'de> {
    // #[instrument(skip(de))]
    fn new(de: &'a mut TtlvDeserializer<'de>) -> Self {
        EnumWalker { de }
    }
}

// `EnumAccess` is provided to the `Visitor` to give it the ability to determine
// which variant of the enum is supposed to be deserialized.
//
// Note that all enum deserialization methods in Serde refer exclusively to the
// "externally tagged" enum representation.
impl<'de> EnumAccess<'de> for EnumWalker<'_, 'de> {
    type Error = TtlvError;
    type Variant = Self;

    // #[instrument(skip(self, seed))]
    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant)>
    where
        V: DeserializeSeed<'de>,
    {
        self.de.deserializing = Deserializing::StructureValue;
        let val = seed.deserialize(&mut *self.de)?;
        Ok((val, self))
    }
}

// `VariantAccess` is provided to the `Visitor` to give it the ability to see
// the content of the single variant that it decided to deserialize.
impl<'de> VariantAccess<'de> for EnumWalker<'_, 'de> {
    type Error = TtlvError;

    // If the `Visitor` expected this variant to be a unit variant, the input
    // should have been the plain string case handled in `deserialize_enum`.
    // #[instrument(skip(self))]
    fn unit_variant(self) -> Result<()> {
        Ok(())
    }

    /// `variant` is called to identify which variant to deserialize.
    // #[instrument(skip(self, seed))]
    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value>
    where
        T: DeserializeSeed<'de>,
    {
        seed.deserialize(self.de)
    }

    // Tuple variants are not in KMIP but, if any,
    // deserialize as a sequence of data here.
    // #[instrument(skip(self, visitor))]
    fn tuple_variant<V>(self, _len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        de::Deserializer::deserialize_seq(self.de, visitor)
    }

    // Struct variants are represented in JSON as `{ NAME: { K: V, ... } }` so
    // deserialize the inner map here.
    // #[instrument(skip(self, visitor))]
    fn struct_variant<V>(self, _fields: &'static [&'static str], visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        de::Deserializer::deserialize_map(self.de, visitor)
    }
}

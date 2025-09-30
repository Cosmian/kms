use std::fmt::Debug;

use cosmian_logger::trace;
use serde::{
    Serialize,
    ser::{
        self, Error, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant,
        SerializeTuple, SerializeTupleVariant,
    },
};
use tracing::instrument;

use super::{collapse_adjacently_tagged_structure, normalize_ttlv};
use crate::ttlv::{
    TtlvError,
    ttlv_struct::{KmipEnumerationVariant, TTLV, TTLValue},
};

type Result<T> = std::result::Result<T, TtlvError>;

#[derive(Debug)]
struct Stack<T>
where
    T: Debug,
{
    elements: Vec<T>,
}

impl<T> Stack<T>
where
    T: Debug,
{
    pub(crate) const fn new() -> Self {
        Self {
            elements: Vec::new(),
        }
    }

    fn push(&mut self, v: T) {
        self.elements.push(v);
    }

    fn pop(&mut self) -> Option<T> {
        self.elements.pop()
    }

    fn peek(&self) -> Option<&T> {
        self.elements.last()
    }

    fn peek_mut(&mut self) -> Option<&mut T> {
        self.elements.last_mut()
    }
}

#[derive(Debug)]
pub struct TtlvSerializer {
    stack: Stack<TTLV>,
}

impl TtlvSerializer {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stack: Stack::new(),
        }
    }

    /// Get the current TTLV element
    /// which is the last element on the stack
    fn current_mut(&mut self) -> Result<&mut TTLV> {
        self.stack
            .peek_mut()
            .ok_or_else(|| TtlvError::custom("no TTLV found".to_owned()))
    }

    /// Get the current TTLV element
    /// which is the last element on the stack
    fn current_mut_structure(&mut self) -> Result<&mut Vec<TTLV>> {
        match &mut self.current_mut()?.value {
            TTLValue::Structure(v) => Ok(v),
            _ => Err(TtlvError::custom(
                "current TTLV is not a structure".to_owned(),
            )),
        }
    }

    /// Get the current tag
    fn current_tag(&self) -> String {
        self.stack
            .peek()
            .map_or_else(|| "[ROOT]".to_owned(), |p| p.tag.clone())
    }
}

impl Default for TtlvSerializer {
    fn default() -> Self {
        Self::new()
    }
}

/// The public API of the TTLV Serde serializer
/// Serialize an Object to TTLV
///
/// The way this works is as follows: say we are starting with a Source object
/// 1. The Serialize implementation of the Source object will map the object to Serde Data Model
/// 2. The TTLV Serializer will then serialize the Serde Data Model to TTLV
///
/// KMIP objects use the default Serde serialization.
///
///  However, `Object` is an untagged enum; it is the serialized object,
/// the root tag is replaced with the object type.
/// This is only applied when serializing a root `Object`, not an embedded one in a
/// KMIP Operation such as `Import`
#[instrument(skip(value), level = "trace")]
pub fn to_ttlv<T>(value: &T) -> Result<TTLV>
where
    T: ?Sized + Serialize,
{
    let mut ser = TtlvSerializer::new();
    value.serialize(&mut ser)?;
    let mut root = ser
        .stack
        .pop()
        .ok_or_else(|| TtlvError::custom("no TTLV produced".to_owned()))?;
    normalize_ttlv(&mut root);
    Ok(root)
}

impl<'a> ser::Serializer for &'a mut TtlvSerializer {
    type Error = TtlvError;
    type Ok = ();
    type SerializeMap = &'a mut TtlvSerializer;
    type SerializeSeq = &'a mut TtlvSerializer;
    type SerializeStruct = &'a mut TtlvSerializer;
    type SerializeStructVariant = &'a mut TtlvSerializer;
    type SerializeTuple = &'a mut TtlvSerializer;
    type SerializeTupleStruct = &'a mut TtlvSerializer;
    type SerializeTupleVariant = &'a mut TtlvSerializer;

    #[instrument(level = "trace", skip(self))]
    fn serialize_bool(self, v: bool) -> Result<Self::Ok> {
        self.current_mut()?.value = TTLValue::Boolean(v);
        Ok(())
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_i8(self, v: i8) -> Result<Self::Ok> {
        self.serialize_i32(i32::from(v))
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_i16(self, v: i16) -> Result<Self::Ok> {
        self.serialize_i32(i32::from(v))
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_i32(self, v: i32) -> Result<Self::Ok> {
        self.current_mut()?.value = TTLValue::Integer(v);
        Ok(())
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_i64(self, v: i64) -> Result<Self::Ok> {
        self.current_mut()?.value = TTLValue::LongInteger(v);
        Ok(())
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_u8(self, v: u8) -> Result<Self::Ok> {
        self.serialize_i32(i32::from(v))
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_u16(self, v: u16) -> Result<Self::Ok> {
        self.serialize_i32(i32::from(v))
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_u32(self, v: u32) -> Result<Self::Ok> {
        match i32::try_from(v) {
            Ok(v32) => self.serialize_i32(v32),
            Err(_) => self.serialize_i64(i64::from(v)),
        }
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_u64(self, v: u64) -> Result<Self::Ok> {
        self.serialize_i64(v.try_into().map_err(|_e| {
            TtlvError::custom(format!(
                "Unexpected value: {v}, expected a 64 bit integer fitting in i64"
            ))
        })?)
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_i128(self, v: i128) -> Result<Self::Ok> {
        i64::try_from(v)
            .map_err(|_e| TtlvError::custom("i128 is not supported".to_owned()))
            .and_then(|v64| self.serialize_i64(v64))
    }

    #[instrument(level = "trace", skip(self, _v))]
    fn serialize_f32(self, _v: f32) -> Result<Self::Ok> {
        Err(TtlvError::custom(
            "'value f32' is unsupported in TTLV".to_owned(),
        ))
    }

    #[instrument(level = "trace", skip(self, _v))]
    fn serialize_f64(self, _v: f64) -> Result<Self::Ok> {
        Err(TtlvError::custom(
            "'value f64' is unsupported in TTLV".to_owned(),
        ))
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_char(self, v: char) -> Result<Self::Ok> {
        self.current_mut()?.value = TTLValue::TextString(format!("{v}"));
        Ok(())
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_str(self, v: &str) -> Result<Self::Ok> {
        self.current_mut()?.value = TTLValue::TextString(v.to_owned());
        Ok(())
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok> {
        if let Ok(current) = self.current_mut() {
            current.value = TTLValue::ByteString(v.to_owned());
        } else {
            let tag = "[BYTE_STRING]".to_owned();
            self.stack.push(TTLV {
                tag,
                value: TTLValue::ByteString(v.to_owned()),
            });
        }
        Ok(())
    }

    /// Copied from `https://github.com/NLnetLabs/kmip-ttlv/blob/main/src/ser.rs`
    /// Serializing `None` values, e.g. `Option::TypeName::None`, is not
    /// supported.
    ///
    /// TTLV doesn't support the notion of a serialized value that indicates the
    /// absence of a value.
    ///
    /// ### Using Serde to "skip" a missing value
    ///
    /// The correct way to omit None values is to not attempt to serialize them
    /// at all, e.g. using the `#[serde(skip_serializing_if =
    /// "Option::is_none")]` Serde derive field attribute. Note that at the time
    /// of writing it seems that Serde derive only handles this attribute
    /// correctly when used on Rust brace struct field members (which we do
    /// not support), or on tuple struct fields (i.e. there must be more than
    /// one field). Also, note that not serializing a None struct field
    /// value will still result in the struct itself being serialized as
    /// a TTLV "Structure" unless you also mark the struct as "transparent"
    /// (using the rename attribute like so: `[#serde(rename =
    /// "Transparent:0xAABBCC"))]`. Using the attribute on `newtype` structs still
    /// causes Serde derive to invoke `serialize_none()` which will result
    /// in an unsupported error.
    ///
    /// ### Rationale
    ///
    /// As we have already serialized the item tag to the output by the time we
    /// process the `Option` value, serializing nothing here would still
    /// result in something having been serialized. We could in theory remove
    /// the already serialized bytes from the stream but is not necessarily
    /// safe, e.g. if the already serialized bytes were a TTLV Structure "
    /// header" (i.e. 0xAABBCC 0x00000001 0x00000000) removing the header might
    /// be incorrect if there are other structure items that will be
    /// serialized to the stream after this "none". Removing the Structure
    /// "header" bytes would also break the current logic which at the end
    /// of a structure goes back to the start and replaces the zero length
    /// value in the TTLV Structure "header" with the actual length as the bytes
    /// to replace would no longer exist.
    #[instrument(level = "trace", skip(self))]
    fn serialize_none(self) -> Result<Self::Ok> {
        Err(TtlvError::custom(
            "'Option.None' is unsupported in TTLV".to_owned(),
        ))
    }

    #[instrument(level = "trace", skip(self, value))]
    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_unit(self) -> Result<Self::Ok> {
        Err(TtlvError::custom(
            "'value ()' is unsupported in TTLV".to_owned(),
        ))
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok> {
        Err(TtlvError::custom(format!(
            "cannot map the 'unit struct' {name}, unit_struct is unsupported in TTLV"
        )))
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_unit_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok> {
        trace!("serialize_unit_variant, name: {name}::{variant}; variant_index: {variant_index}");
        self.current_mut()?.value = TTLValue::Enumeration(KmipEnumerationVariant {
            value: variant_index,
            name: variant.into(),
        });
        Ok(())
    }

    #[instrument(level = "trace", skip(self, value))]
    fn serialize_newtype_struct<T>(self, name: &'static str, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        let _ = name;
        value.serialize(self)
    }

    #[instrument(level = "trace", skip(self, value))]
    fn serialize_newtype_variant<T>(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        trace!(
            "serialize_newtype_variant, name: {name}::{variant} (variant index: {variant_index})"
        );
        let has_parent = self.stack.peek().is_some();
        let tag = variant.to_owned();
        self.stack.push(TTLV {
            tag,
            value: TTLValue::Structure(vec![]),
        });
        value.serialize(&mut *self)?;
        if !has_parent {
            return Ok(());
        }
        let current_element = self
            .stack
            .pop()
            .ok_or_else(|| TtlvError::custom("no TTLV found".to_owned()))?;
        let receiving_parent = self.current_mut().map_err(|e| {
            TtlvError::custom(format!(
                "error getting the parent TTLV of the serialized new type variant: {e}"
            ))
        })?;
        receiving_parent.value = TTLValue::Structure(vec![current_element]);
        Ok(())
    }

    /// Serialize a sequence of items.
    /// To do this, we are going to create a special `Array` TTLV to which we add TTLV elements, in the
    /// method `serialize_element`, that will be called for each item in the sequence.
    /// Finally, the method `end` will be called to close the sequence and make the `Array` TTLV the current
    /// element of the serializer.
    #[instrument(level = "trace", skip(self))]
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        if let Some(receiver) = self.stack.peek_mut() {
            receiver.value = TTLValue::Structure(Vec::with_capacity(len.unwrap_or(0)));
            trace!("serialize_seq of len: {len:?} in receiver: {:?}", receiver);
        } else {
            trace!(
                "serialize_seq, no parent found. This is a direct vec![] serialization. Creating \
                 a new one with tag: {}",
                self.current_tag()
            );
            let tag = "[ARRAY]".to_owned();
            self.stack.push(TTLV {
                tag,
                value: TTLValue::Structure(Vec::with_capacity(len.unwrap_or(0))),
            });
        }
        Ok(self)
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
        trace!(
            "serialize_tuple of len {len}. Current: {:?}",
            &self.current_tag()
        );
        self.serialize_seq(Some(len))
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_tuple_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        trace!(
            "serialize_tuple_struct {name} of len {len}. Current: {:?}",
            &self.current_tag()
        );
        self.serialize_seq(Some(len))
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_tuple_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        trace!(
            "serialize_tuple_variant {name}::{variant} (variant index: {variant_index}) of len \
             {len}. Current: {:?}",
            &self.current_tag()
        );
        Err(TtlvError::custom(
            "'tuple variant' is unsupported in TTLV".to_owned(),
        ))
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap> {
        trace!(
            "serialize_map of len: {len:?}. Current: {:?}",
            &self.current_tag()
        );
        Err(TtlvError::custom("'map' is unsupported in TTLV".to_owned()))
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_struct(self, name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
        if let Some(parent) = self.stack.peek_mut() {
            trace!("serialize_struct named: {name} in parent: {:?}", parent);
            parent.value = TTLValue::Structure(Vec::with_capacity(len));
            if parent.tag == "Object" {
                trace!("... replacing  \"Object\" with: {name}");
                name.clone_into(&mut parent.tag);
            }
        } else {
            trace!(
                "serialize_struct, no parent found, creating a new one with tag: {}",
                name
            );
            let tag = name.to_owned();
            self.stack.push(TTLV {
                tag,
                value: TTLValue::Structure(Vec::with_capacity(len)),
            });
        }
        Ok(self)
    }

    #[instrument(level = "trace", skip(self))]
    fn serialize_struct_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        trace!(
            "serialize_struct_variant {name}::{variant} (variant index: {variant_index}) of len \
             {len}. Current: {:?}",
            &self.current_tag()
        );
        self.serialize_struct(name, len)
    }

    #[inline]
    fn is_human_readable(&self) -> bool {
        true
    }
}

impl SerializeSeq for &mut TtlvSerializer {
    type Error = TtlvError;
    type Ok = ();

    #[instrument(level = "trace", skip(self, value))]
    fn serialize_element<T>(&mut self, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        let tag = self.stack.peek().map_or("", |parent| parent.tag.as_str());
        trace!(
            "Seq Element: serializing a seq element with tag {}, stack is: {:?}",
            tag, self.stack
        );
        self.stack.push(TTLV {
            tag: tag.to_owned(),
            value: TTLValue::Boolean(true),
        });
        value.serialize(&mut **self)?;
        let current_element = self
            .stack
            .pop()
            .ok_or_else(|| TtlvError::custom("no TTLV found".to_owned()))?;
        let receiving_parent_vec = self.current_mut_structure().map_err(|e| {
            TtlvError::custom(format!("error getting the current TTLV structure: {e}"))
        })?;
        receiving_parent_vec.push(current_element);
        trace!(
            "... Seq element added, the current parent value is: {:?}",
            receiving_parent_vec,
        );
        Ok(())
    }

    #[instrument(level = "trace", skip(self))]
    fn end(self) -> Result<Self::Ok> {
        trace!(
            "Finished serializing the sequence, the parent is: {:?}",
            self.stack.peek()
        );
        Ok(())
    }
}

impl SerializeTuple for &mut TtlvSerializer {
    type Error = TtlvError;
    type Ok = ();

    #[instrument(level = "trace", skip(self, value))]
    fn serialize_element<T>(&mut self, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        <&mut TtlvSerializer as SerializeSeq>::serialize_element(self, value)
    }

    #[instrument(level = "trace", skip(self))]
    fn end(self) -> Result<Self::Ok> {
        <&mut TtlvSerializer as SerializeSeq>::end(self)
    }
}

impl ser::SerializeTupleStruct for &mut TtlvSerializer {
    type Error = TtlvError;
    type Ok = ();

    #[instrument(level = "trace", skip(self, value))]
    fn serialize_field<T>(&mut self, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        <&mut TtlvSerializer as SerializeSeq>::serialize_element(self, value)
    }

    #[instrument(level = "trace", skip(self))]
    fn end(self) -> Result<Self::Ok> {
        <&mut TtlvSerializer as SerializeSeq>::end(self)
    }
}

impl SerializeTupleVariant for &mut TtlvSerializer {
    type Error = TtlvError;
    type Ok = ();

    #[instrument(level = "trace", skip(self, _value))]
    fn serialize_field<T>(&mut self, _value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        Err(TtlvError::custom(
            "'tuple variant' fields are unsupported in TTLV".to_owned(),
        ))
    }

    #[instrument(level = "trace", skip(self))]
    fn end(self) -> Result<Self::Ok> {
        Err(TtlvError::custom(
            "'tuple variant' is unsupported in TTLV".to_owned(),
        ))
    }
}

impl SerializeMap for &mut TtlvSerializer {
    type Error = TtlvError;
    type Ok = ();

    #[instrument(level = "trace", skip(self, _key))]
    fn serialize_key<T>(&mut self, _key: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        Err(TtlvError::custom(
            "'map' keys are unsupported in TTLV".to_owned(),
        ))
    }

    #[instrument(level = "trace", skip(self, _value))]
    fn serialize_value<T>(&mut self, _value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        Err(TtlvError::custom(
            "'map' values are unsupported in TTLV".to_owned(),
        ))
    }

    #[instrument(level = "trace", skip(self))]
    fn end(self) -> Result<Self::Ok> {
        Ok(())
    }
}

impl SerializeStruct for &mut TtlvSerializer {
    type Error = TtlvError;
    type Ok = ();

    #[instrument(level = "trace", skip(self, value))]
    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        trace!(
            "serializing a struct field with name: {key}, stack: {:?}",
            &self.stack
        );
        let mut current_element = {
            self.stack.push(TTLV {
                tag: key.to_owned(),
                value: TTLValue::Boolean(true),
            });
            value.serialize(&mut **self)?;
            self.stack.pop().ok_or_else(|| {
                TtlvError::custom("unexpected end of struct fields: no parent".to_owned())
            })?
        };
        if key == "Object" {
            if let TTLValue::Structure(ref mut v) = current_element.value {
                if v.len() == 1 {
                    current_element = v.pop().ok_or_else(|| {
                        TtlvError::custom("unexpected end of struct fields: no child".to_owned())
                    })?;
                }
            }
        }
        let struct_elems = self.current_mut_structure()?;
        if let TTLValue::Structure(ref v) = current_element.value {
            let is_array = !v.is_empty() && v.iter().all(|child| child.tag == key);
            if is_array {
                let all_numeric = v.iter().all(|child| {
                    matches!(child.value, TTLValue::Integer(_) | TTLValue::LongInteger(_))
                });
                if all_numeric {
                    struct_elems.push(current_element);
                } else {
                    struct_elems.extend_from_slice(v);
                }
            } else {
                struct_elems.push(current_element);
            }
        } else {
            struct_elems.push(current_element);
        }
        trace!(
            "... added a struct field: {key}, the parent struct is now: {:?}",
            &struct_elems,
        );
        Ok(())
    }

    #[instrument(level = "trace", skip(self))]
    fn end(self) -> Result<Self::Ok> {
        collapse_adjacently_tagged_structure(self.current_mut()?);
        trace!("Structure finalized, stack: {:?} ", self.stack);
        Ok(())
    }
}

impl SerializeStructVariant for &mut TtlvSerializer {
    type Error = TtlvError;
    type Ok = ();

    #[instrument(level = "trace", skip(self, value))]
    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        <&mut TtlvSerializer as SerializeStruct>::serialize_field(self, key, value)
    }

    #[instrument(level = "trace", skip(self))]
    fn end(self) -> Result<Self::Ok> {
        <&mut TtlvSerializer as SerializeStruct>::end(self)
    }
}

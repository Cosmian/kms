use std::fmt::Debug;

use num_bigint_dig::{BigInt, BigUint};
use serde::{
    ser::{
        self, Error, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant,
        SerializeTuple, SerializeTupleVariant,
    },
    Serialize,
};
use time::OffsetDateTime;
// use strum::VariantNames;
use tracing::{debug, instrument, trace};
use zeroize::Zeroizing;

use super::{error::TtlvError, TTLValue, TTLV};
// use crate::{kmip_1_4, kmip_2_1, ttlv::KmipEnumerationVariant};
use crate::ttlv::{KmipBigInt, KmipEnumerationVariant};

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

    pub(crate) fn push(&mut self, value: T) {
        self.elements.push(value);
    }

    pub(crate) fn pop(&mut self) -> Option<T> {
        self.elements.pop()
    }

    pub(crate) fn peek(&self) -> Option<&T> {
        self.elements.last()
    }

    pub(crate) fn peek_mut(&mut self) -> Option<&mut T> {
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

    // Get the current tag
    #[must_use]
    pub fn current_tag(&self) -> &str {
        self.stack.peek().map_or("", |parent| parent.tag.as_str())
    }

    pub fn current_mut(&mut self) -> Result<&mut TTLV> {
        self.stack
            .peek_mut()
            .ok_or_else(|| TtlvError::custom("no TTLV found on stack".to_owned()))
    }

    pub fn current_mut_structure(&mut self) -> Result<&mut Vec<TTLV>> {
        match self.current_mut()?.value {
            TTLValue::Structure(ref mut v) => Ok(v),
            _ => Err(TtlvError::custom(
                "the current element is not a TTLV structure".to_owned(),
            )),
        }
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
/// 1. The Serialize implementation of the Source object will map the objec to Serde Data Model
/// 2. The TTLV Serializer will then serialize the Serde Data Model to TTLV
///
/// KMIP objects use the default Serde serialization.
///
///  However, `Object` is an untagged enum; it is the serialized object,
/// the root tag is replaced with the object type.
/// This is only applied when serializing a root `Object`, not an embedded one in a
/// KMIP Operation such as `Import`
pub fn to_ttlv<T>(value: &T) -> Result<TTLV>
where
    T: Serialize,
{
    let mut serializer = TtlvSerializer::new();
    value.serialize(&mut serializer)?;
    serializer
        .stack
        .peek()
        .cloned()
        .ok_or_else(|| TtlvError::custom("no TTLV value found".to_owned()))
}

impl ser::Serializer for &mut TtlvSerializer {
    // The error type when some error occurs during serialization.
    type Error = TtlvError;
    // The output type produced by this `Serializer` during successful
    // serialization. Most serializers that produce text or binary output should
    // set `Ok = ()` and serialize into an `io::Write` or buffer contained
    // within the `Serializer` instance, as happens here. Serializers that build
    // in-memory data structures may be simplified by using `Ok` to propagate
    // the data structure around.
    type Ok = ();
    type SerializeMap = Self;
    // Associated types for keeping track of additional state while serializing
    // compound data structures like sequences and maps. In this case no
    // additional state is required beyond what is already stored in the
    // Serializer struct.
    type SerializeSeq = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;

    // Here we go with the simple methods. The following 12 methods receive one
    // of the primitive types of the data model and map it to JSON by appending
    // into the output string.
    #[instrument(skip(self))]
    fn serialize_bool(self, v: bool) -> Result<Self::Ok> {
        self.current_mut()?.value = TTLValue::Boolean(v);
        Ok(())
    }

    // TTLV does not distinguish between integers of size < 32,
    // so we serialize all integers as i32
    #[instrument(skip(self))]
    fn serialize_i8(self, v: i8) -> Result<Self::Ok> {
        self.serialize_i32(i32::from(v))
    }

    // TTLV does not distinguish between integers of size < 32,
    // so we serialize all integers as i32
    #[instrument(skip(self))]
    fn serialize_i16(self, v: i16) -> Result<Self::Ok> {
        self.serialize_i32(i32::from(v))
    }

    // TTLV does not distinguish between integers of size < 32,
    // so we serialize all integers as i32
    #[instrument(skip(self))]
    fn serialize_i32(self, v: i32) -> Result<Self::Ok> {
        self.current_mut()?.value = TTLValue::Integer(v);
        Ok(())
    }

    // Serialize a 64-bit signed integer as a TTLV Long Integer
    #[instrument(skip(self))]
    fn serialize_i64(self, v: i64) -> Result<Self::Ok> {
        self.current_mut()?.value = TTLValue::LongInteger(v);
        Ok(())
    }

    // TTLV does not distinguish between integers of size < 32,
    // so we serialize all integers as i32
    #[instrument(skip(self))]
    fn serialize_u8(self, v: u8) -> Result<Self::Ok> {
        self.serialize_i32(i32::from(v))
    }

    // TTLV does not distinguish between integers of size < 32,
    // so we serialize all integers as i32
    #[instrument(skip(self))]
    fn serialize_u16(self, v: u16) -> Result<Self::Ok> {
        self.serialize_i32(i32::from(v))
    }

    // TTLV does not distinguish between integers of size < 32,
    // so we serialize all integers as i32
    // This may overflow if the value is too large, so we need to check
    // the value is within the range of i32
    #[instrument(skip(self))]
    fn serialize_u32(self, v: u32) -> Result<Self::Ok> {
        self.serialize_i32(v.try_into().map_err(|_e| {
            TtlvError::custom(format!(
                "Unexpected value: {v}, expected a 32 bit integer fitting in i32"
            ))
        })?)
    }

    // Serialize a 64-bit unsigned integer as a TTLV Long Integer
    // This may overflow if the value is too large, so we need to check
    // the value is within the range of i64
    #[instrument(skip(self))]
    fn serialize_u64(self, v: u64) -> Result<Self::Ok> {
        self.serialize_i64(v.try_into().map_err(|_e| {
            TtlvError::custom(format!(
                "Unexpected value: {v}, expected a 64 bit integer fitting in i64"
            ))
        })?)
    }

    // TTLV has no support for floating point numbers
    #[instrument(skip(self, _v))]
    fn serialize_f32(self, _v: f32) -> Result<Self::Ok> {
        Err(TtlvError::custom(
            "'value f32' is unsupported in TTLV".to_owned(),
        ))
    }

    // TTLV has no support for floating point numbers
    #[instrument(skip(self, _v))]
    fn serialize_f64(self, _v: f64) -> Result<Self::Ok> {
        Err(TtlvError::custom(
            "'value f64' is unsupported in TTLV".to_owned(),
        ))
    }

    // Serialize a char as a single-character string. Other formats may
    // represent this differently.
    #[instrument(skip(self))]
    fn serialize_char(self, v: char) -> Result<Self::Ok> {
        self.current_mut()?.value = TTLValue::TextString(format!("{v}"));
        Ok(())
    }

    // Serialize a str as a TTLV string
    #[instrument(skip(self))]
    fn serialize_str(self, v: &str) -> Result<Self::Ok> {
        self.current_mut()?.value = TTLValue::TextString(v.to_owned());
        Ok(())
    }

    // Serialize a byte array as a TTLV byte string
    #[instrument(skip(self))]
    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok> {
        self.current_mut()?.value = TTLValue::ByteString(v.to_owned());
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
    #[instrument(skip(self))]
    fn serialize_none(self) -> Result<Self::Ok> {
        Err(TtlvError::custom(
            "'Option.None' is unsupported in TTLV".to_owned(),
        ))
    }

    // A present optional is represented as just the contained value.
    #[instrument(skip(self, value))]
    fn serialize_some<T>(self, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        // to the serializer, a Vec<u8> and a BigUint look
        // like seq. We want to intercept that and make sure they
        // are serialized for what they are

        enum Detected {
            Other,
            ByteString(Vec<u8>),
            BigUint(BigUint),
            BigInt(BigInt),
        }
        trait Detect {
            fn detect(&self) -> Detected;
        }
        impl<T> Detect for T {
            default fn detect(&self) -> Detected {
                Detected::Other
            }
        }
        impl Detect for &Vec<u8> {
            fn detect(&self) -> Detected {
                trace!("handling a byte string");
                Detected::ByteString((*self).clone())
            }
        }
        impl Detect for &Zeroizing<Vec<u8>> {
            fn detect(&self) -> Detected {
                trace!("handling a byte string");
                Detected::ByteString((*self).to_vec())
            }
        }
        // BigUint shoould go and be replace by BigInt everywhere
        impl Detect for &BigUint {
            fn detect(&self) -> Detected {
                debug!("serializing a Big Uint {:?}", self);
                Detected::BigUint(self.to_owned().clone())
            }
        }
        impl Detect for &BigInt {
            fn detect(&self) -> Detected {
                debug!("serializing a Big Uint {:?}", self);
                Detected::BigInt(self.to_owned().clone())
            }
        }

        match value.detect() {
            Detected::Other => value.serialize(self),
            Detected::ByteString(byte_string) => {
                self.stack
                    .peek_mut()
                    .ok_or_else(|| TtlvError::custom("no TTLV found".to_owned()))?
                    .value = TTLValue::ByteString(byte_string);
                Ok(())
            }
            // Map to a KmipBigInt
            Detected::BigUint(big_int) => {
                self.stack
                    .peek_mut()
                    .ok_or_else(|| TtlvError::custom("no TTLV found".to_owned()))?
                    .value = TTLValue::BigInteger(big_int.into());
                Ok(())
            }
            // Map to a KmipBigInt
            Detected::BigInt(big_int) => {
                self.stack
                    .peek_mut()
                    .ok_or_else(|| TtlvError::custom("no TTLV found".to_owned()))?
                    .value = TTLValue::BigInteger(big_int.into());
                Ok(())
            }
        }
    }

    // The type of () in Rust, no such value exists in TTLV
    #[instrument(skip(self))]
    fn serialize_unit(self) -> Result<Self::Ok> {
        Err(TtlvError::custom(
            "'value ()' is unsupported in TTLV".to_owned(),
        ))
    }

    // The type of `()` in Rust, no such value exists in TTLV
    #[instrument(skip(self))]
    fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok> {
        Err(TtlvError::custom(format!(
            "cannot map the 'unit struct' {name}, ujnit_struct is unsupported in TTLV"
        )))
    }

    // For example the `E::A` and `E::B` in `enum E { A, B }`
    // This is where all the KMIP types are serialized
    #[instrument(skip(self))]
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

    // A newtype_struct is for example struct `Millimeters(u8)`
    // We want to intercept Intervals here
    #[instrument(skip(self, value))]
    fn serialize_newtype_struct<T>(self, name: &'static str, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        // requires the specification feature
        trait Detect {
            fn detect_specific_value(&self, name: &'static str) -> Option<TTLValue>;
        }
        impl<T> Detect for T {
            default fn detect_specific_value(&self, _name: &'static str) -> Option<TTLValue> {
                None
            }
        }
        impl Detect for u32 {
            fn detect_specific_value(&self, name: &'static str) -> Option<TTLValue> {
                if name == "Interval" {
                    Some(TTLValue::Interval(*self))
                } else {
                    None
                }
            }
        }
        // Yhis is used by `VendorAttributeValue::Serialize()``
        impl Detect for &BigInt {
            fn detect_specific_value(&self, _name: &'static str) -> Option<TTLValue> {
                debug!("serializing a Big Int {:?}", self);
                Some(TTLValue::BigInteger(KmipBigInt::from(
                    self.to_owned().clone(),
                )))
            }
        }
        // This is used by `VendorAttributeValue::Serialize()`
        impl Detect for &OffsetDateTime {
            fn detect_specific_value(&self, _name: &'static str) -> Option<TTLValue> {
                debug!("serializing a Offset Date Time {:?}", self);
                Some(TTLValue::DateTime(*self.to_owned()))
            }
        }
        if let Some(value) = value.detect_specific_value(name) {
            self.stack
                .peek_mut()
                .ok_or_else(|| TtlvError::custom("no TTLV found".to_owned()))?
                .value = value;
            Ok(())
        } else {
            value.serialize(self)
        }
    }

    // For example the E::N in enum E { N(u8) }.
    // This is typically called when serializing an `Attribute` enumeration
    // The serialized value is inside a TTLV structure that has a tag
    // that is the name of the enum variant
    #[instrument(skip(self, value))]
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

        // First we want to kmow if this variant has a parent. If not the user is
        // trying to serialize a newtype variant directly as root
        let has_parent = self.stack.peek().is_some();

        // create a new structure parent to which we will add the fields of the struct
        let tag = variant.to_owned();
        self.stack.push(TTLV {
            tag,
            value: TTLValue::Structure(vec![]),
        });
        value.serialize(&mut *self)?;
        // We now have the variant serialized in the TTLV structure created above
        // If it has nop parent, we are done, else we need to add the newtype
        // variant to the parent
        if !has_parent {
            return Ok(());
        }

        // We have a parent, so we need to add the newtype variant to it
        let current_element = self
            .stack
            .pop()
            .ok_or_else(|| TtlvError::custom("no TTLV found".to_owned()))?;
        // add the TTLV element to the parent
        let receiving_parent_vec = self.current_mut().map_err(|e| {
            TtlvError::custom(format!(
                "error getting the parent TTLV of the serialized new type variant: {e}"
            ))
        })?;
        receiving_parent_vec.value = TTLValue::Structure(vec![current_element]);
        trace!(
            "... Newtype variant added, the current parent value is: {:?}",
            receiving_parent_vec,
        );
        Ok(())
    }

    /// Serialize a sequence of items.
    /// To do this, we are going to create a special `Array` TTLV to which we add TTLV elements, in the
    /// method `serialize_element`, that will be called for each item in the sequence.
    /// Finally, the method `end` will be called to close the sequence and make the `Array` TTLV the current
    /// element of the serializer.
    #[instrument(skip(self))]
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        // A receiver has been added on the stack, which will be flattened
        // when returned, since TTLV flattens arrays to the parent structure
        if let Some(receiver) = self.stack.peek_mut() {
            receiver.value = TTLValue::Structure(Vec::with_capacity(len.unwrap_or(0)));
            trace!("serialize_seq of len: {len:?} in receiver: {:?}", receiver);
        } else {
            trace!(
                "serialize_seq, no parent found. This is a direct vec![] serialization. Creating \
                 a new one with tag: {}",
                self.current_tag()
            );
            // create a new structure parent to which we will add the fields of the struct
            let tag = "[ARRAY]".to_owned();
            self.stack.push(TTLV {
                tag,
                value: TTLValue::Structure(Vec::with_capacity(len.unwrap_or(0))),
            });
        }
        Ok(self)
    }

    // Tuples look just like sequences in TTLV.
    //
    // Note: Some formats may be able to
    // represent tuples more efficiently by omitting the length, since tuple
    // means that the corresponding `Deserialize implementation will know the
    // length without needing to look at the serialized data.
    #[instrument(skip(self))]
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
        trace!(
            "serialize_tuple of len {len}. Current: {:?}",
            &self.current_tag()
        );
        self.serialize_seq(Some(len))
    }

    // A named tuple, for example struct Rgb(u8, u8, u8)
    #[instrument(skip(self))]
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

    // For example, the E::T in enum E { T(u8, u8) }.
    #[instrument(skip(self))]
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

    // A variably sized heterogeneous key-value pairing,
    // for example, BTreeMap<K, V>. When serializing,
    // the length may or may not be known before iterating through all the entries.
    // When deserializing, the length is determined by looking at the serialized
    // data.
    #[instrument(skip(self))]
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap> {
        trace!(
            "serialize_map of len: {len:?}. Current: {:?}",
            &self.current_tag()
        );
        Err(TtlvError::custom("'map' is unsupported in TTLV".to_owned()))
    }

    // A statically sized heterogeneous key-value pairing
    // in which the keys are compile-time constant strings
    // and will be known at deserialization time
    // without looking at the serialized data,
    // for example, struct S { r: u8, g: u8, b: u8 }.
    #[instrument(skip(self))]
    fn serialize_struct(self, name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
        if let Some(parent) = self.stack.peek_mut() {
            // the children will be handled in SerializeStruct impl
            trace!("serialize_struct named: {name} in parent: {:?}", parent);
            parent.value = TTLValue::Structure(Vec::with_capacity(len));
            // corner case: when the parent has a field named `object`, then the
            // the field name must be replaced the `name`of the struct: example: SymmetricKey
            if parent.tag == "Object" {
                trace!("... replacing  \"Object\" with: {name}");
                name.clone_into(&mut parent.tag);
            }
        } else {
            trace!(
                "serialize_struct, no parent found, creating a new one with tag: {}",
                name
            );
            // top level struct
            let tag = name.to_owned();
            // create a new structure parent to which we will add the fields of the struct
            self.stack.push(TTLV {
                tag,
                value: TTLValue::Structure(Vec::with_capacity(len)),
            });
        }
        Ok(self)
    }

    // For example, the E::S in enum E { S { r: u8, g: u8, b: u8 } }
    // same as Struct
    #[instrument(skip(self))]
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

// The following 7 impls deal with the serialization of compound types like
// sequences and maps. Serialization of such types is begun by a Serializer
// method and followed by zero or more calls to serialize individual elements of
// the compound type and one call to end the compound type.

// This impl is `SerializeSeq` so these methods are called after `serialize_seq`
// is called on the Serializer.
impl SerializeSeq for &mut TtlvSerializer {
    // Must match the `Error` type of the serializer.
    type Error = TtlvError;
    // Must match the `Ok` type of the serializer.
    type Ok = ();

    // Serialize a single element of the sequence.
    #[instrument(skip(self, value))]
    fn serialize_element<T>(&mut self, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        let tag = self.stack.peek().map_or("", |parent| parent.tag.as_str());
        trace!(
            "Seq Element: serializing a seq element with tag {}, stack is: {:?}",
            tag,
            self.stack
        );
        // push a new TTLV element on the stack with the tag
        self.stack.push(TTLV {
            tag: tag.to_owned(),
            value: TTLValue::Boolean(true),
        });
        // generate the value for the new TTLV element
        value.serialize(&mut **self)?;
        // pop the TTLV element from the stack and add it to the parent
        let current_element = self
            .stack
            .pop()
            .ok_or_else(|| TtlvError::custom("no TTLV found".to_owned()))?;
        // add the TTLV element to the parent
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

    // Close the sequence.
    #[instrument(skip(self))]
    fn end(self) -> Result<Self::Ok> {
        trace!(
            "Finished serializing the sequence, the parent is: {:?}",
            self.stack.peek()
        );
        Ok(())
    }
}

// Same thing as seq but for tuples.
impl SerializeTuple for &mut TtlvSerializer {
    type Error = TtlvError;
    type Ok = ();

    #[instrument(skip(self, value))]
    fn serialize_element<T>(&mut self, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        <&mut TtlvSerializer as SerializeSeq>::serialize_element(self, value)
    }

    fn end(self) -> Result<Self::Ok> {
        <&mut TtlvSerializer as SerializeSeq>::end(self)
    }
}

// Same thing but for tuple structs.
impl ser::SerializeTupleStruct for &mut TtlvSerializer {
    type Error = TtlvError;
    type Ok = ();

    //#[instrument(skip(self, value))]
    fn serialize_field<T>(&mut self, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        <&mut TtlvSerializer as SerializeSeq>::serialize_element(self, value)
    }

    fn end(self) -> Result<Self::Ok> {
        <&mut TtlvSerializer as SerializeSeq>::end(self)
    }
}

// For example the E::T in enum E { T(u8, u8) }
// There is no such thing as a tuple variant in TTLV
impl SerializeTupleVariant for &mut TtlvSerializer {
    type Error = TtlvError;
    type Ok = ();

    //#[instrument(skip(_value))]
    fn serialize_field<T>(&mut self, _value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        Err(TtlvError::custom(
            "'tuple variant' fields are unsupported in TTLV".to_owned(),
        ))
    }

    // #[instrument(skip(self))]
    fn end(self) -> Result<Self::Ok> {
        Err(TtlvError::custom(
            "'tuple variant' is unsupported in TTLV".to_owned(),
        ))
    }
}

// A variably sized heterogeneous key-value pairing,
// for example BTreeMap<K, V>. When serializing,
// the length may or may not be known before iterating through all the entries.
// When deserializing, the length is determined by looking at the serialized
// data.
// This is not supported in TTLV
impl SerializeMap for &mut TtlvSerializer {
    type Error = TtlvError;
    type Ok = ();

    //#[instrument(skip(self, _key))]
    fn serialize_key<T>(&mut self, _key: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        Err(TtlvError::custom(
            "'map' keys are unsupported in TTLV".to_owned(),
        ))
    }

    // It doesn't make a difference whether the colon is printed at the end of
    // `serialize_key` or at the beginning of `serialize_value`. In this case
    // the code is a bit simpler having it here.
    //#[instrument(skip(_value))]
    fn serialize_value<T>(&mut self, _value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        Err(TtlvError::custom(
            "'map' values are unsupported in TTLV".to_owned(),
        ))
    }

    // #[instrument(skip(self))]
    fn end(self) -> Result<Self::Ok> {
        Ok(())
    }
}

// Structs are like seqs for their elements
impl SerializeStruct for &mut TtlvSerializer {
    type Error = TtlvError;
    type Ok = ();

    #[instrument(skip(self, value))]
    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        enum Detected {
            Other,
            ByteString(Vec<u8>),
            BigInt(BigInt),
            // BigUint should go
            BigUint(BigUint),
            DateTime(OffsetDateTime),
            DateTimeExtended(i128),
            DateTimeInterval(u32),
        }
        trait Detect {
            fn detect(&self) -> Detected;
        }
        impl<T> Detect for T {
            default fn detect(&self) -> Detected {
                trace!(
                    "... the value has other type {}",
                    std::any::type_name::<T>()
                );
                Detected::Other
            }
        }
        impl Detect for &Vec<u8> {
            fn detect(&self) -> Detected {
                trace!("... the value is a byte string");
                Detected::ByteString((*self).clone())
            }
        }
        impl Detect for &Zeroizing<Vec<u8>> {
            fn detect(&self) -> Detected {
                trace!("... the value is a (zeroized) byte string");
                Detected::ByteString((*self).to_vec())
            }
        }
        impl Detect for &BigInt {
            fn detect(&self) -> Detected {
                trace!("... the value is a BigInt");
                Detected::BigInt(self.to_owned().clone())
            }
        }
        impl Detect for &BigUint {
            fn detect(&self) -> Detected {
                trace!("... the value is a BigUint");
                Detected::BigUint(self.to_owned().clone())
            }
        }
        impl Detect for &OffsetDateTime {
            fn detect(&self) -> Detected {
                trace!("... the value is a OffsetDateTime");
                Detected::DateTime(*self.to_owned())
            }
        }
        impl Detect for &i128 {
            fn detect(&self) -> Detected {
                trace!("... the value is a OffsetDateTime");
                Detected::DateTimeExtended(**self)
            }
        }

        impl Detect for &u32 {
            fn detect(&self) -> Detected {
                trace!("... the value is an Interval");
                Detected::DateTimeInterval(**self)
            }
        }

        trace!(
            "serializing a struct field with name: {key}, stack: {:?}",
            &self.stack,
        );

        // Serialize the value according to its type
        let current_element = match value.detect() {
            Detected::ByteString(byte_string) => TTLV {
                tag: key.to_owned(),
                value: TTLValue::ByteString(byte_string),
            },
            Detected::BigInt(big_int) => TTLV {
                tag: key.to_owned(),
                value: TTLValue::BigInteger(big_int.into()),
            },
            Detected::BigUint(big_uint) => TTLV {
                tag: key.to_owned(),
                value: TTLValue::BigInteger(big_uint.into()),
            },
            Detected::DateTime(date_time) => TTLV {
                tag: key.to_owned(),
                value: TTLValue::DateTime(date_time),
            },
            Detected::DateTimeExtended(offset_date_time) => TTLV {
                tag: key.to_owned(),
                value: TTLValue::DateTimeExtended(offset_date_time),
            },
            Detected::DateTimeInterval(interval) => TTLV {
                tag: key.to_owned(),
                value: TTLValue::Interval(interval),
            },
            Detected::Other => {
                let current_ttlv = TTLV {
                    tag: key.to_owned(),
                    value: TTLValue::Boolean(true),
                };
                self.stack.push(current_ttlv);
                value.serialize(&mut **self)?;
                let mut ttlv = self.stack.pop().ok_or_else(|| {
                    TtlvError::custom("'unexpected end of struct fields: no parent ".to_owned())
                })?;
                // There is a corner case: if the field name is "Object", then we serialize the
                // Object structure directly into the parent structure (no intermediate TTLV with
                // tag "Object")
                if key == "Object" {
                    trace!("... the field name is 'Object', removing the Object layer");
                    // remove the "Object" layer
                    if let TTLValue::Structure(ref mut v) = ttlv.value {
                        if v.len() == 1 {
                            ttlv = v.pop().ok_or_else(|| {
                                TtlvError::custom(
                                    "unexpected end of struct fields: no child".to_owned(),
                                )
                            })?;
                        }
                        // more than one object in the structure? This should not happen
                    }
                }
                ttlv
            }
        };

        // Fetch the structure
        let struct_elems = self.current_mut_structure()?;

        // test if the current element is an array
        if let TTLValue::Structure(ref v) = current_element.value {
            // Arrays have all the same tag, which is the same as the parent element storing them
            // `Attributes` may be an empty structure but is not an array
            let is_array = !v.is_empty() && v.iter().all(|child| child.tag == key);
            if is_array {
                struct_elems.extend_from_slice(v);
            } else {
                struct_elems.push(current_element);
            }
        } else {
            // if the current element is not an array, we need to add it to the parent
            struct_elems.push(current_element);
        }

        trace!(
            "... added a struct field: {key}, the parent struct is now: {:?}",
            &struct_elems,
        );
        Ok(())
    }

    #[instrument(skip(self))]
    fn end(self) -> Result<Self::Ok> {
        trace!("Structure finalized, stack: {:?} ", self.stack);
        Ok(())
    }
}

// For example the `E::S` in `enum E { S { r: u8, g: u8, b: u8 } }`
// same as Struct therefore same as seqs
impl SerializeStructVariant for &mut TtlvSerializer {
    type Error = TtlvError;
    type Ok = ();

    #[instrument(skip(self, value))]
    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        <&mut TtlvSerializer as SerializeStruct>::serialize_field(self, key, value)
    }

    #[instrument(skip(self))]
    fn end(self) -> Result<Self::Ok> {
        <&mut TtlvSerializer as SerializeStruct>::end(self)
    }
}

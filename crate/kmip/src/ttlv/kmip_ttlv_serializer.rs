use num_bigint_dig::{BigInt, BigUint};
use serde::{
    ser::{
        self, Error, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant,
        SerializeTuple, SerializeTupleVariant,
    },
    Serialize,
};
use strum::VariantNames;
use tracing::{debug, instrument, trace};
use zeroize::Zeroizing;

use super::{error::TtlvError, TTLValue, TTLV};
use crate::{kmip_1_4, kmip_2_1, ttlv::KmipEnumerationVariant};

type Result<T> = std::result::Result<T, TtlvError>;

#[derive(Debug)]
pub struct TTLVSerializer {
    // A stack of parents
    parents: Vec<TTLV>,
    // The current element being deserialized
    current_tag: String,
    // In case the current element is an array, we hold the tag and the values
    current_values: Vec<TTLValue>,
}

impl TTLVSerializer {
    fn last_parent_tag(&self) -> &str {
        self.parents
            .last()
            .map_or_else(|| "[NO PARENT]", |p| p.tag.as_str())
    }
}

/// The public API of the TTLV Serde serializer
/// Serialize an Object to TTLV
///
/// The way this works is as follows: say we are starting with a Source object
/// 1. The Serialize implementation of the Source object will map the objecy to Serde Data Model
/// 2. The TTLV Serializer will then serialize the Serde Data Model to TTLV
///
/// KMIP objects use the default Serde serialization.
///
///  However, `Object` is an untagged enum; it is is the serialized object,
/// the root tag is replaced with the object type.
/// This is only applied when serializing a root `Object`, not an embedded one in a
/// KMIP Operation such as `Import`
pub fn to_ttlv<T>(value: &T) -> Result<TTLV>
where
    T: Serialize,
{
    let mut serializer = TTLVSerializer {
        parents: vec![],
        current_tag: String::new(),
        current_values: vec![],
    };
    value.serialize(&mut serializer)?;
    if serializer.current_values.len() == 0 {
        return Err(TtlvError::custom("no TTLV value generated".to_owned()));
    }
    // When serilizing a struct, this is what should happen
    if serializer.current_values.len() == 1 {
        return Ok(TTLV {
            tag: serializer.current_tag,
            value: serializer
                .current_values
                .pop()
                .ok_or_else(|| TtlvError::custom("no TTLV value found".to_owned()))?,
        })
    }
    // Serializing an array of structs: this is non-standard
    // Create a "holding" TTLV struct
    // and add the current values to it
    let tag = &serializer.current_tag;
    let mut array = Vec::with_capacity(serializer.current_values.len());
    // Add the current values to the holding struct
    for value in serializer.current_values {
        array.push(TTLV {
            tag: tag.clone(),
            value,
        });
    }
    Ok(TTLV {
        tag: tag.clone(),
        value: TTLValue::Structure(array),
    })
}

impl ser::Serializer for &mut TTLVSerializer {
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
        self.current_values.push(TTLValue::Boolean(v));
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
        self.current_values.push(TTLValue::Integer(v));
        Ok(())
    }

    // Serialize a 64-bit signed integer as a TTLV Long Integer
    #[instrument(skip(self))]
    fn serialize_i64(self, v: i64) -> Result<Self::Ok> {
        self.current_values.push(TTLValue::LongInteger(v));
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
        self.current_values
            .push(TTLValue::TextString(format!("{v}")));
        Ok(())
    }

    // Serialize a str as a TTLV string
    #[instrument(skip(self))]
    fn serialize_str(self, v: &str) -> Result<Self::Ok> {
        self.current_values.push(TTLValue::TextString(v.to_owned()));
        Ok(())
    }

    // Serialize a byte array as a TTLV byte string
    #[instrument(skip(self))]
    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok> {
        self.current_values.push(TTLValue::ByteString(v.to_owned()));
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
                self.current_values.push(TTLValue::ByteString(byte_string));
                Ok(())
            }
            // Map to a KmipBigInt
            Detected::BigUint(big_int) => {
                self.current_values
                    .push(TTLValue::BigInteger(big_int.into()));
                Ok(())
            }
            // Map to a KmipBigInt
            Detected::BigInt(big_int) => {
                self.current_values
                    .push(TTLValue::BigInteger(big_int.into()));
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
        self.current_values
            .push(TTLValue::Enumeration(KmipEnumerationVariant {
                value: variant_index,
                name: variant.into(),
            }));
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
        if let Some(value) = value.detect_specific_value(name) {
            self.current_values.push(value);
            Ok(())
        } else {
            value.serialize(self)
        }
    }

    // For example the E::N in enum E { N(u8) }.
    // We serialize the newtype variant as the value itself
    // (i.e we collapse the newtype variant)
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
        value.serialize(self)
    }

    /// Serialize a sequence of items.
    /// To do this, we are going to create a special `Array` TTLV to which we add TTLV elements, in the
    /// method `serialize_element`, that will be called for each item in the sequence.
    /// Finally, the method `end` will be called to close the sequence and make the `Array` TTLV the current
    /// element of the serializer.
    #[instrument(skip(self))]
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        trace!(
            "serializing a sequence of tags {}, of len: {len:?}, in parent {:?}",
            &self.current_tag,
            &self.last_parent_tag()
        );
        self.current_values = Vec::with_capacity(len.unwrap_or(0));
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
            &self.current_tag
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
            &self.current_tag
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
            &self.current_tag
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
            &self.current_tag
        );
        Err(TtlvError::custom("'map' is unsupported in TTLV".to_owned()))
    }

    // A statically sized heterogeneous key-value pairing
    // in which the keys are compile-time constant strings
    // and will be known at deserialization time
    // without looking at the serialized data,
    // for example, struct S { r: u8, g: u8, b: u8 }.
    // The strategy is as follows:
    // - create a new parent TTLV structure and push it into `parents`
    // - serialize the fields of the struct, adding them to this new parent
    // - when the struct is done, pop the parent from `parents` and add it to the last parent
    #[instrument(skip(self))]
    fn serialize_struct(self, name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
        let tag = &self.current_tag;
        trace!(
            "Starting to serialize a struct: {name} of len: {len} in parent: {:?}",
            &self.last_parent_tag()
        );
        // Push the struct on the parent's stack, collecting the name
        // There are teo special cases:
        // 1. If the tag is empty, it means it is the root structure, we use the name of the struct
        let tag = if tag.is_empty() {
            trace!("... setting the root tag with name: {}", name);
            name.to_owned()
        // 2. The structure is a KMIP object, we use the name of the object as tag
        } else if kmip_2_1::kmip_objects::Object::VARIANTS.contains(&name)
            || kmip_1_4::kmip_objects::Object::VARIANTS.contains(&name)
        {
            trace!(
                "... replacing the parent tag: {} with KMIP Object name: {}",
                tag,
                name
            );
            name.to_owned()
        } else {
            tag.to_owned()
        };
        // create a new structure parent to which we will add the fields of the struct
        self.parents.push(TTLV {
            tag,
            value: TTLValue::Structure(vec![]),
        });
        Ok(self)
    }

    // For example the E::S in enum E { S { r: u8, g: u8, b: u8 } }
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
            &self.current_tag
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

// This impl is SerializeSeq so these methods are called after `serialize_seq`
// is called on the Serializer.
impl SerializeSeq for &mut TTLVSerializer {
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
        trace!("Serializing a seq element with tag {}", self.current_tag,);

        // this will serialize the element and push it on the stack of current values
        value.serialize(&mut **self)?;

        trace!(
            "... added sequence element, the current sequence is: {:?}",
            self.current_values,
        );
        Ok(())
    }

    // Close the sequence.
    #[instrument(skip(self))]
    fn end(self) -> Result<Self::Ok> {
        trace!("Finished serializing the sequence",);
        Ok(())
    }
}

// Same thing as seq but for tuples.
impl<'a> SerializeTuple for &'a mut TTLVSerializer {
    type Error = TtlvError;
    type Ok = ();

    #[instrument(skip(self, value))]
    fn serialize_element<T>(&mut self, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        <&'a mut TTLVSerializer as SerializeSeq>::serialize_element(self, value)
    }

    fn end(self) -> Result<Self::Ok> {
        <&'a mut TTLVSerializer as SerializeSeq>::end(self)
    }
}

// Same thing but for tuple structs.
impl<'a> ser::SerializeTupleStruct for &'a mut TTLVSerializer {
    type Error = TtlvError;
    type Ok = ();

    //#[instrument(skip(self, value))]
    fn serialize_field<T>(&mut self, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        <&'a mut TTLVSerializer as SerializeSeq>::serialize_element(self, value)
    }

    fn end(self) -> Result<Self::Ok> {
        <&'a mut TTLVSerializer as SerializeSeq>::end(self)
    }
}

// For example the E::T in enum E { T(u8, u8) }
// There is no such thing as a tuple variant in TTLV
impl SerializeTupleVariant for &mut TTLVSerializer {
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
impl SerializeMap for &mut TTLVSerializer {
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
impl SerializeStruct for &mut TTLVSerializer {
    type Error = TtlvError;
    type Ok = ();

    #[instrument(skip(self, value))]
    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        // enum Detected {
        //     Other,
        //     ByteString(Vec<u8>),
        //     BigInt(BigInt),
        //     // BigUint should go
        //     BigUint(BigUint),
        // }
        // trait Detect {
        //     fn detect(&self) -> Detected;
        // }
        // impl<T> Detect for T {
        //     default fn detect(&self) -> Detected {
        //         trace!("... value has other type {}", std::any::type_name::<T>());
        //         Detected::Other
        //     }
        // }
        // impl Detect for &Vec<u8> {
        //     fn detect(&self) -> Detected {
        //         Detected::ByteString((*self).clone())
        //     }
        // }
        // impl Detect for &Zeroizing<Vec<u8>> {
        //     fn detect(&self) -> Detected {
        //         trace!("handling a byte string");
        //         Detected::ByteString((*self).to_vec())
        //     }
        // }
        // impl Detect for &BigInt {
        //     fn detect(&self) -> Detected {
        //         Detected::BigInt(self.to_owned().clone())
        //     }
        // }
        // impl Detect for &BigUint {
        //     fn detect(&self) -> Detected {
        //         Detected::BigUint(self.to_owned().clone())
        //     }
        // }

        self.current_tag = key.to_owned();
        trace!(
            "serializing a struct field with name: {key} in structure {:?}",
            self.parents
                .last()
                .map_or("???", |parent| { parent.tag.as_str() }),
        );

        value.serialize(&mut **self)?;

        // match value.detect() {
        //     Detected::Other => {
        //         trace!("... detected other for {}", &self.current.tag);
        //         value.serialize(&mut **self)?;
        //     }
        //     Detected::ByteString(byte_string) => {
        //         trace!("... detected ByteString for {}", &self.current.tag);
        //         self.current_values.push(TTLValue::ByteString(byte_string);
        //     }
        //     Detected::BigInt(big_int) => {
        //         trace!("... detected BigInteger for {}", &self.current.tag);
        //         self.current_values.push(TTLValue::BigInteger(big_int.into());
        //     }
        //     Detected::BigUint(big_int) => {
        //         trace!("... detected BigUInteger for {}", &self.current.tag);
        //         self.current_values.push(TTLValue::BigInteger(big_int.into());
        //     }
        // }

        // add this new serialized field on the lat parent
        let parent: &mut TTLV = match self.parents.last_mut() {
            Some(p) => p,
            None => return Err(TtlvError::custom("'no parent for the field !".to_owned())),
        };

        match &mut parent.value {
            TTLValue::Structure(v) => {
                // If the child is a TTLV::Array, it means it is a transparent struct
                // so we add its children to the struct directly
                for child in self.current_values.drain(..) {
                    v.push(TTLV {
                        tag: self.current_tag.clone(),
                        value: child,
                    });
                }
            }
            v => {
                return Err(TtlvError::custom(format!(
                    "'unexpected value for struct: {v:?}"
                )))
            }
        }
        trace!(
            "... added a struct field: {key}, the parent struct is now: {:?}",
            &parent,
        );
        Ok(())
    }

    #[instrument(skip(self))]
    fn end(self) -> Result<Self::Ok> {
        trace!(
            "Finalizing the serialization of the struct: {:?}; making it the curent element ",
            self.parents.last()
        );

        //pop the parent
        let Some(struct_root) = self.parents.pop() else {
            return Err(TtlvError::custom(
                "'unexpected end of struct fields: no parent ".to_owned(),
            ))
        };
        self.current_tag = struct_root.tag;
        self.current_values = vec![struct_root.value];
        trace!(
            "... the parents now are: {:?}, the current element: {}:{:?}",
            self.parents,
            self.current_tag,
            self.current_values,
        );
        Ok(())
    }
}

// For example the `E::S` in `enum E { S { r: u8, g: u8, b: u8 } }`
// same as Struct therefore same as seqs
impl<'a> SerializeStructVariant for &'a mut TTLVSerializer {
    type Error = TtlvError;
    type Ok = ();

    //#[instrument(skip(self, value))]
    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        <&'a mut TTLVSerializer as ser::SerializeStruct>::serialize_field(self, key, value)
    }

    // #[instrument(skip(self))]
    fn end(self) -> Result<Self::Ok> {
        <&'a mut TTLVSerializer as ser::SerializeStruct>::end(self)
    }
}

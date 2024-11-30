use num_bigint_dig::BigUint;
use serde::{
    ser::{self, Error, SerializeSeq},
    Serialize,
};
use tracing::{debug, trace};
use zeroize::Zeroizing;

use super::{error::TtlvError, TTLVEnumeration, TTLValue, TTLV};
use crate::kmip::kmip_objects::{Object, ObjectType};

type Result<T> = std::result::Result<T, TtlvError>;

#[derive(Debug)]
pub struct TTLVSerializer {
    parents: Vec<TTLV>,
    current: TTLV,
}

/// The public API of the TTLV Serde serializer
/// Serialize an Object to TTLV
///
/// `Object` is an untagged enum; it is is the serialized object,
/// the root tag is replaced with the object type.
/// This is only applied when serializing a root `Object`, not an embedded one in a
/// KMIP Operation such as `Import`
pub fn to_ttlv<T>(value: &T) -> Result<TTLV>
where
    T: Serialize,
{
    // postfix the TTLV if it is a root object
    trait Detect {
        fn detect(&self) -> Option<ObjectType>;
    }
    impl<T> Detect for T {
        default fn detect(&self) -> Option<ObjectType> {
            None
        }
    }
    impl Detect for Object {
        fn detect(&self) -> Option<ObjectType> {
            Some(self.object_type())
        }
    }

    let mut serializer = TTLVSerializer {
        parents: vec![],
        current: TTLV::default(),
    };
    value.serialize(&mut serializer)?;
    let mut ttlv = serializer.current;

    if let Some(object_type) = value.detect() {
        ttlv.tag = object_type.to_string();
    };

    Ok(ttlv)
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
    //#[instrument(skip(self))]
    fn serialize_bool(self, v: bool) -> Result<Self::Ok> {
        self.current.value = TTLValue::Boolean(v);
        Ok(())
    }

    // TTLV does not distinguish between integers of size < 32
    //#[instrument(skip(self))]
    fn serialize_i8(self, v: i8) -> Result<Self::Ok> {
        self.serialize_i32(i32::from(v))
    }

    //#[instrument(skip(self))]
    fn serialize_i16(self, v: i16) -> Result<Self::Ok> {
        self.serialize_i32(i32::from(v))
    }

    //#[instrument(skip(self))]
    fn serialize_i32(self, v: i32) -> Result<Self::Ok> {
        self.current.value = TTLValue::Integer(v);
        Ok(())
    }

    //#[instrument(skip(self))]
    fn serialize_i64(self, v: i64) -> Result<Self::Ok> {
        self.current.value = TTLValue::LongInteger(v);
        Ok(())
    }

    //#[instrument(skip(self))]
    fn serialize_u8(self, v: u8) -> Result<Self::Ok> {
        self.serialize_i32(i32::from(v))
    }

    //#[instrument(skip(self))]
    fn serialize_u16(self, v: u16) -> Result<Self::Ok> {
        self.serialize_i32(i32::from(v))
    }

    // assume this is an integer
    //#[instrument(skip(self))]
    fn serialize_u32(self, v: u32) -> Result<Self::Ok> {
        self.serialize_i32(v.try_into().map_err(|_e| {
            TtlvError::custom(format!("Unexpected value: {v}, expected a 32 bit integer"))
        })?)
    }

    // assume this is a long integer
    //#[instrument(skip(self))]
    fn serialize_u64(self, v: u64) -> Result<Self::Ok> {
        self.serialize_i64(v.try_into().map_err(|_e| {
            TtlvError::custom(format!("Unexpected value: {v}, expected a 32 bit integer"))
        })?)
    }

    // assume this is an integer
    //#[instrument(skip(self))]
    #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
    fn serialize_f32(self, v: f32) -> Result<Self::Ok> {
        self.serialize_i32(v.round() as i32)
    }

    // assume this is a Long integer
    //#[instrument(skip(self))]
    #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
    fn serialize_f64(self, v: f64) -> Result<Self::Ok> {
        self.serialize_i64(v.round() as i64)
    }

    // Serialize a char as a single-character string. Other formats may
    // represent this differently.
    //#[instrument(skip(self))]
    fn serialize_char(self, _v: char) -> Result<Self::Ok> {
        Err(TtlvError::custom(
            "'char' type is unsupported in TTLV".to_owned(),
        ))
    }

    //#[instrument(skip(self))]
    fn serialize_str(self, v: &str) -> Result<Self::Ok> {
        self.current.value = TTLValue::TextString(v.to_owned());
        Ok(())
    }

    //#[instrument(skip(self))]
    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok> {
        self.current.value = TTLValue::ByteString(v.to_owned());
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
    //#[instrument(skip(self))]
    fn serialize_none(self) -> Result<Self::Ok> {
        Err(TtlvError::custom(
            "'Option.None' is unsupported in TTLV".to_owned(),
        ))
    }

    // A present optional is represented as just the contained value.
    //#[instrument(skip(self, value))]
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
            BigInt(BigUint),
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
        impl Detect for &BigUint {
            fn detect(&self) -> Detected {
                debug!("serializing a Big Uint {:?}", self);
                Detected::BigInt(self.to_owned().clone())
            }
        }

        match value.detect() {
            Detected::Other => value.serialize(self),
            Detected::ByteString(byte_string) => {
                self.current.value = TTLValue::ByteString(byte_string);
                Ok(())
            }
            Detected::BigInt(big_int) => {
                self.current.value = TTLValue::BigInteger(big_int);
                Ok(())
            }
        }
    }

    // The type of () in Rust
    //#[instrument(skip(self))]
    fn serialize_unit(self) -> Result<Self::Ok> {
        Err(TtlvError::custom(
            "'value ()' is unsupported in TTLV".to_owned(),
        ))
    }

    //#[instrument(skip(self))]
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok> {
        Err(TtlvError::custom(
            "'unit struct' is unsupported in TTLV".to_owned(),
        ))
    }

    // For example the `E::A` and `E::B` in `enum E { A, B }`
    //#[instrument(skip(self))]
    fn serialize_unit_variant(
        self,
        name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok> {
        trace!("serialize_unit_variant, name: {name}::{variant}");
        self.current.value = TTLValue::Enumeration(TTLVEnumeration::Name(variant.to_owned()));
        Ok(())
    }

    // For example struct `Millimeters(u8)`
    // Detect Interval(here)
    //#[instrument(skip(self, value))]
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
            self.current.value = value;
            Ok(())
        } else {
            value.serialize(self)
        }
    }

    // For example the E::N in enum E { N(u8) }.
    //#[instrument(skip(self, value))]
    fn serialize_newtype_variant<T>(
        self,
        name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        trace!("serialize_newtype_variant, name: {name}::{variant}");
        value.serialize(self)
    }

    //#[instrument(skip(self))]
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
        trace!("serialize_seq. Value: {:?}", &self.current);

        // Push the struct on the parents stack, collecting the name
        let tag = self.current.tag.clone();
        self.parents.push(TTLV {
            tag,
            value: TTLValue::Structure(vec![]),
        });
        self.current = TTLV::default();
        Ok(self)
    }

    // Tuples look just like sequences in JSON. Some formats may be able to
    // represent tuples more efficiently by omitting the length, since tuple
    // means that the corresponding `Deserialize implementation will know the
    // length without needing to look at the serialized data.
    //#[instrument(skip(self))]
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
        self.serialize_seq(Some(len))
    }

    // A named tuple, for example struct Rgb(u8, u8, u8)
    //#[instrument(skip(self))]
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        self.serialize_seq(Some(len))
    }

    // For example the E::T in enum E { T(u8, u8) }.
    //#[instrument(skip(self))]
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        Err(TtlvError::custom(
            "'tuple variant' is unsupported in TTLV".to_owned(),
        ))
    }

    // A variably sized heterogeneous key-value pairing,
    // for example BTreeMap<K, V>. When serializing,
    // the length may or may not be known before iterating through all the entries.
    // When deserializing, the length is determined by looking at the serialized
    // data.
    //#[instrument(skip(self))]
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        Err(TtlvError::custom("'map' is unsupported in TTLV".to_owned()))
    }

    // A statically sized heterogeneous key-value pairing
    // in which the keys are compile-time constant strings
    // and will be known at deserialization time
    // without looking at the serialized data,
    // for example struct S { r: u8, g: u8, b: u8 }.
    //#[instrument(skip(self))]
    fn serialize_struct(self, name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
        trace!("serialize_struct {name} . Value: {:?}", &self.current);
        // Push the struct on the parents stack, collecting the name
        let tag = if self.current.tag.is_empty() {
            // top level struct => get its name
            name.to_owned()
        } else {
            self.current.tag.clone()
        };
        self.parents.push(TTLV {
            tag,
            value: TTLValue::Structure(vec![]),
        });
        self.current = TTLV::default();
        Ok(self)
    }

    // For example the E::S in enum E { S { r: u8, g: u8, b: u8 } }
    // same as Struct
    //#[instrument(skip(self))]
    fn serialize_struct_variant(
        self,
        name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        self.serialize_struct(name, len)
    }
}

// The following 7 impls deal with the serialization of compound types like
// sequences and maps. Serialization of such types is begun by a Serializer
// method and followed by zero or more calls to serialize individual elements of
// the compound type and one call to end the compound type.

// This impl is SerializeSeq so these methods are called after `serialize_seq`
// is called on the Serializer.
impl ser::SerializeSeq for &mut TTLVSerializer {
    // Must match the `Error` type of the serializer.
    type Error = TtlvError;
    // Must match the `Ok` type of the serializer.
    type Ok = ();

    // Serialize a single element of the sequence.
    //#[instrument(skip(self, value))]
    fn serialize_element<T>(&mut self, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        trace!(
            "Before serialize seq element {:?} #### {:?}",
            self.parents,
            self.current
        );
        value.serialize(&mut **self)?;

        // recover the parent
        let parent: &mut TTLV = self
            .parents
            .last_mut()
            .ok_or_else(|| TtlvError::custom("'no parent for the element !".to_owned()))?;
        // give the same tag as tag of the parent
        self.current.tag.clone_from(&parent.tag);

        // update the parent
        match &mut parent.value {
            TTLValue::Structure(v) => {
                v.push(self.current.clone());
                self.current = TTLV::default();
            }
            v => {
                return Err(TtlvError::custom(format!(
                    "'unexpected value for struct: {v:?}"
                )))
            }
        }
        trace!(
            "After serialize seq element {:?} #### {:?}",
            self.parents,
            self.current
        );
        Ok(())
    }

    // Close the sequence.
    // //#[instrument(skip(self))]
    fn end(self) -> Result<Self::Ok> {
        //pop the parent
        self.current = match self.parents.pop() {
            Some(p) => p,
            None => {
                return Err(TtlvError::custom(
                    "'unexpected end of seq: no parent ".to_owned(),
                ))
            }
        };
        trace!(
            "After serialize seq end {:?} #### {:?}",
            self.parents,
            self.current
        );
        Ok(())
    }
}

// Same thing but for tuples.
impl<'a> ser::SerializeTuple for &'a mut TTLVSerializer {
    type Error = TtlvError;
    type Ok = ();

    //#[instrument(skip(self, value))]
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
impl ser::SerializeTupleVariant for &mut TTLVSerializer {
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
        //value.serialize(&mut **self)
    }

    // //#[instrument(skip(self))]
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
impl ser::SerializeMap for &mut TTLVSerializer {
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

    // //#[instrument(skip(self))]
    fn end(self) -> Result<Self::Ok> {
        Ok(())
        // Err(TtlvError::custom(
        //     "'map' is unsupported in TTLV".to_owned(),
        // ))
    }
}

// Structs are like seqs for their elements
impl ser::SerializeStruct for &mut TTLVSerializer {
    type Error = TtlvError;
    type Ok = ();

    //#[instrument(skip(self, value))]
    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        enum Detected {
            Other,
            ByteString(Vec<u8>),
            BigInt(BigUint),
        }
        trait Detect {
            fn detect(&self) -> Detected;
        }
        impl<T> Detect for T {
            default fn detect(&self) -> Detected {
                trace!("... value has other type {}", std::any::type_name::<T>());
                Detected::Other
            }
        }
        impl Detect for &Vec<u8> {
            fn detect(&self) -> Detected {
                Detected::ByteString((*self).clone())
            }
        }
        impl Detect for &Zeroizing<Vec<u8>> {
            fn detect(&self) -> Detected {
                trace!("handling a byte string");
                Detected::ByteString((*self).to_vec())
            }
        }
        impl Detect for &BigUint {
            fn detect(&self) -> Detected {
                Detected::BigInt(self.to_owned().clone())
            }
        }

        key.clone_into(&mut self.current.tag);
        trace!(
            "Before serialize field {:?} #### {:?}",
            self.parents,
            self.current
        );

        match value.detect() {
            Detected::Other => {
                trace!("... detected other for {}", &self.current.tag);
                value.serialize(&mut **self)?;
            }
            Detected::ByteString(byte_string) => {
                trace!("... detected ByteString for {}", &self.current.tag);
                self.current.value = TTLValue::ByteString(byte_string);
            }
            Detected::BigInt(big_int) => {
                trace!("... detected BigInteger for {}", &self.current.tag);
                self.current.value = TTLValue::BigInteger(big_int);
            }
        }

        let parent: &mut TTLV = match self.parents.last_mut() {
            Some(p) => p,
            None => return Err(TtlvError::custom("'no parent for the field !".to_owned())),
        };

        match &mut parent.value {
            TTLValue::Structure(v) => {
                v.push(self.current.clone());
                self.current = TTLV::default();
            }
            v => {
                return Err(TtlvError::custom(format!(
                    "'unexpected value for struct: {v:?}"
                )))
            }
        };
        trace!(
            "After serialize field {:?} #### {:?}",
            self.parents,
            self.current
        );
        Ok(())
    }

    // //#[instrument(skip(self))]
    fn end(self) -> Result<Self::Ok> {
        //pop the parent
        self.current = match self.parents.pop() {
            Some(p) => p,
            None => {
                return Err(TtlvError::custom(
                    "'unexpected end of struct fields: no parent ".to_owned(),
                ))
            }
        };
        trace!(
            "After serialize struct fields end {:?} #### {:?}",
            self.parents,
            self.current
        );
        Ok(())
    }
}

// For example the `E::S` in `enum E { S { r: u8, g: u8, b: u8 } }`
// same as Struct therefore same as seqs
impl<'a> ser::SerializeStructVariant for &'a mut TTLVSerializer {
    type Error = TtlvError;
    type Ok = ();

    //#[instrument(skip(self, value))]
    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<Self::Ok>
    where
        T: ?Sized + Serialize,
    {
        <&'a mut TTLVSerializer as ser::SerializeStruct>::serialize_field(self, key, value)
    }

    // //#[instrument(skip(self))]
    fn end(self) -> Result<Self::Ok> {
        <&'a mut TTLVSerializer as ser::SerializeStruct>::end(self)
    }
}

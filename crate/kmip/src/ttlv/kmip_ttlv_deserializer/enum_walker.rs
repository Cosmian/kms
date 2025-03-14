use serde::de::{DeserializeSeed, EnumAccess, VariantAccess, Visitor};
use tracing::{instrument, trace};

use super::{Result, TtlvDeserializer};
use crate::ttlv::{kmip_ttlv_deserializer::deserializer::MapAccessState, TtlvError};

pub(super) struct EnumWalker<'a> {
    de: &'a mut TtlvDeserializer,
}

impl<'a> EnumWalker<'a> {
    pub(super) fn new(de: &'a mut TtlvDeserializer) -> Self {
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
        // The map state should already be set to value, but just in case
        // this will tel deserialize_identifier to deserialize the variant of the TT:V, not the tag
        self.de.map_state = MapAccessState::Value;
        let val = seed.deserialize(&mut *self.de)?;
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
        trace!(
            "unit_variant: child index: {}, current: {:?}",
            self.de.child_index,
            self.de.current
        );
        Ok(())
    }

    /// `variant` is called to identify which variant to deserialize.
    #[instrument(skip(self, _seed))]
    fn newtype_variant_seed<T>(self, _seed: T) -> Result<T::Value>
    where
        T: DeserializeSeed<'de>,
    {
        trace!(
            "newtype_variant_seed: child index: {}, current: {:?}",
            self.de.child_index,
            self.de.current
        );
        unimplemented!("newtype_variant_seed");
    }

    // Tuple variants are not in KMIP but, if any,
    // deserialize as a sequence of data here.
    #[instrument(skip(self, _visitor))]
    fn tuple_variant<V>(self, len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "tuple_variant of len: {len}, child index: {}, current: {:?}",
            self.de.child_index,
            self.de.current
        );
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

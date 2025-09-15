use std::sync::RwLock;

use cosmian_logger::trace;
use serde::de::{DeserializeSeed, EnumAccess, VariantAccess, Visitor};
use tracing::instrument;

use super::{Result, TtlvDeserializer};
use crate::{
    KmipResultHelper,
    ttlv::{TtlvError, kmip_ttlv_deserializer::deserializer::MapAccessState},
};

pub(super) struct EnumWalker<'a> {
    de: &'a mut TtlvDeserializer,
}

impl<'a> EnumWalker<'a> {
    pub(super) const fn new(de: &'a mut TtlvDeserializer) -> Self {
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

    #[instrument(level = "trace", skip(self, seed))]
    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant)>
    where
        V: DeserializeSeed<'de>,
    {
        trace!("element:  {:?}", self.de.peek_element()?);
        // // The map state should already be set to value, but just in case
        // // this will tel deserialize_identifier to deserialize the variant of the TTLV, not the tag
        self.de.map_state = MapAccessState::Key;
        // Deserialize the variant identifier
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
    #[instrument(level = "trace", skip(self))]
    fn unit_variant(self) -> Result<()> {
        trace!(
            "unit_variant: child index: {}, current: {:?}",
            self.de.child_index, self.de.current
        );
        Ok(())
    }

    /// `variant` is called to identify which variant to deserialize.
    /// This is typically call for the Attribute enumeration
    /// Tell the derializwr to deserialize the content of the next struct as the variant value
    #[instrument(level = "trace", skip(self, seed))]
    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value>
    where
        T: DeserializeSeed<'de>,
    {
        trace!(
            "newtype_variant_seed: child index: {}, at root: {}, current tag: {:?}",
            self.de.child_index,
            *self.de.at_root.read().context("failed to read at_root")?,
            self.de.current.tag
        );
        seed.deserialize(&mut TtlvDeserializer {
            current: self.de.current.clone(),
            map_state: MapAccessState::None,
            child_index: 0,
            at_root: RwLock::new(true),
        })
    }

    // Tuple variants are not in KMIP but, if any,
    // deserialize as a sequence of data here.
    #[instrument(level = "trace", skip(self, _visitor))]
    fn tuple_variant<V>(self, len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        trace!(
            "tuple_variant of len: {len}, child index: {}, current: {:?}",
            self.de.child_index, self.de.current
        );
        unimplemented!("tuple_variant");
    }

    // Struct variants are represented in JSON as `{ NAME: { K: V, ... } }` so
    // deserialize the inner map here.
    #[instrument(level = "trace", skip(self, _visitor))]
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

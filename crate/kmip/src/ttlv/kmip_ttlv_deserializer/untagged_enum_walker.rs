use serde::de::{DeserializeSeed, MapAccess};
use tracing::{instrument, trace};

use super::TtlvDeserializer;
use crate::{
    KmipResultHelper,
    ttlv::{TTLValue, TtlvError, kmip_ttlv_deserializer::deserializer::MapAccessState},
};

/// The `UntaggedEnumWalker` is used to deserialize a struct as a map of property -> values
/// It is called by the main deserializer when receiving Visitor requests to `deserialize_struct`
pub(super) struct UntaggedEnumWalker<'a> {
    de: &'a mut TtlvDeserializer,
    completed: bool,
}

impl<'a> UntaggedEnumWalker<'a> {
    pub(super) const fn new(de: &'a mut TtlvDeserializer) -> Self {
        UntaggedEnumWalker {
            de,
            completed: false,
        }
    }
}

impl<'a, 'de: 'a> MapAccess<'de> for UntaggedEnumWalker<'a> {
    type Error = TtlvError;

    #[instrument(skip(self, seed))]
    fn next_key_seed<K>(&mut self, seed: K) -> std::result::Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        trace!(
            "Untagged Enum map: next_key_seed: completed?: {}, at root: {}, index: {}, current \
             tag: {:?}",
            self.completed,
            *self.de.at_root.read().context("failed to read at_root")?,
            self.de.child_index,
            self.de.current.tag
        );
        if self.completed {
            return Ok(None);
        }
        // we want to recover the tag of the TTLV and pass it back to the visitor
        self.de.map_state = MapAccessState::Key;
        seed.deserialize(&mut *self.de).map(Some)
    }

    #[instrument(skip(self, seed))]
    fn next_value_seed<V>(&mut self, seed: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        trace!(
            "Untagged Enum map: next_value_seed: current tag:  {:?}, at root: {}",
            self.de.current.tag,
            *self.de.at_root.read().context("failed to read at_root")?
        );
        self.de.map_state = MapAccessState::Value;
        let res = seed.deserialize(&mut *self.de)?;
        self.completed = true;
        Ok(res)
    }

    #[inline]
    fn size_hint(&self) -> Option<usize> {
        let TTLValue::Structure(child_array) = &self.de.current.value else {
            return Some(0_usize)
        };
        Some(child_array.len())
    }
}

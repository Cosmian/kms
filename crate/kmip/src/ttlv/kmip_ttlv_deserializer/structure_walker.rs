use serde::de::{DeserializeSeed, MapAccess};
use tracing::{instrument, trace};

use super::TtlvDeserializer;
use crate::ttlv::{kmip_ttlv_deserializer::deserializer::MapAccessState, TTLValue, TtlvError};

/// The `StructureWalker` is used to deserialize a struct as a map of property -> values
/// It is called by the main deserializer when receiving Visitor requests to `deserialize_struct`
pub(super) struct StructureWalker<'a> {
    de: &'a mut TtlvDeserializer,
}

impl<'a> StructureWalker<'a> {
    pub(super) fn new(de: &'a mut TtlvDeserializer) -> Self {
        StructureWalker { de }
    }
}

// MapAccess is called when deserializing a struct because deserialize_struct called visit_map
// The current input is the top structure holding an array of TTLVs which are the fields of the struct/map.
// The calls to `next_value` are driven by the visitor,
// and it is up to this Access to synchronize and advance its counter
// over the struct fields (`self.index`) in this case
impl<'a, 'de: 'a> MapAccess<'de> for StructureWalker<'a> {
    type Error = TtlvError;

    #[instrument(skip(self, seed))]
    fn next_key_seed<K>(&mut self, seed: K) -> std::result::Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        trace!(
            "map access: next_key_seed: index: {}, current: {:?}",
            self.de.child_index,
            self.de.current
        );
        // Check that the index is not out of bounds, i.e. we have not reached the end of the struct
        // If we have, return None
        // If the current value is not a Structure, return an error
        let TTLValue::Structure(current_value) = &self.de.current.value else {
            return Err(TtlvError::from(
                "Deserializing a map: expected Structure value in TTLV",
            ))
        };
        if self.de.child_index >= current_value.len() {
            return Ok(None);
        }
        // recover the tag of the element pointed at by the child index
        // by running the deserialize_identifier method on its deserializer
        self.de.map_state = MapAccessState::Key;
        seed.deserialize(&mut *self.de).map(Some)
    }

    #[instrument(skip(self, seed))]
    fn next_value_seed<V>(&mut self, seed: V) -> std::result::Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        trace!(
            "next_value_seed:index: {}, current: {:?}",
            self.de.child_index,
            self.de.current
        );
        self.de.map_state = MapAccessState::Value;
        let res = seed.deserialize(&mut *self.de);
        self.de.child_index += 1;
        res
    }

    #[inline]
    fn size_hint(&self) -> Option<usize> {
        let TTLValue::Structure(child_array) = &self.de.current.value else {
            return Some(0_usize)
        };
        Some(child_array.len())
    }
}

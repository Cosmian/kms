use cosmian_logger::trace;
use serde::de::{DeserializeSeed, SeqAccess};
use tracing::instrument;

use super::{Result, TtlvDeserializer};
use crate::ttlv::{TTLV, TtlvError};

// The `ArrayDeserializer` is used to deserialize an array from struct elements
/// It is called by the main deserializer when receiving Visitor requests to `deserialize_seq`
pub(super) struct ArrayDeserializer<'a, 't> {
    de: &'a mut TtlvDeserializer<'t>,
    // The tag of the array
    tag: &'t str,
    // all the elements of the containing struct
    struct_elements: &'t [TTLV],
}

impl<'a, 't> ArrayDeserializer<'a, 't> {
    pub(super) const fn new(
        de: &'a mut TtlvDeserializer<'t>,
        tag: &'t str,
        struct_elements: &'t [TTLV],
    ) -> Self {
        ArrayDeserializer {
            de,
            tag,
            struct_elements,
        }
    }
}

impl<'de> SeqAccess<'de> for ArrayDeserializer<'_, '_> {
    type Error = TtlvError;

    #[instrument(level = "trace", skip(self, seed))]
    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        trace!(
            "array_access: next_element_seed in seq: {}, current index: {}, elem at index:  {:?}",
            self.tag,
            self.de.child_index,
            self.struct_elements.get(self.de.child_index)
        );
        // recover the current element
        // if the current index is out of bounds, we are done with this child
        let Some(current_element) = self.struct_elements.get(self.de.child_index) else {
            return Ok(None);
        };

        // if the tag of the current element is different from the tag of the array,
        // we are done with this child
        if current_element.tag != self.tag {
            // backtrack one on the index, because the index should point to the current element
            // in the struct. The index is incremented in the `next_value_seed` method of the Struct Walker
            self.de.child_index -= 1;
            return Ok(None);
        }

        // deserialize the current element
        let mut deserializer = TtlvDeserializer::from_ttlv(current_element);
        // increment the current index
        self.de.child_index += 1;
        // deserialize the element
        let v = seed.deserialize(&mut deserializer).map(Some)?;
        Ok(v)
    }
}

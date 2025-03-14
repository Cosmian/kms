use serde::de::{DeserializeSeed, SeqAccess};
use tracing::{instrument, trace};

use super::{Result, TtlvDeserializer};
use crate::ttlv::{TtlvError, TTLV};

// The `ArrayDeserializer` is used to deserialize an array from struct elements
/// It is called by the main deserializer when receiving Visitor requests to `deserialize_seq`
pub(super) struct ArrayDeserializer<'a> {
    de: &'a mut TtlvDeserializer,
    // The tag of the array
    tag: String,
    // all the elements of the containing struct
    struct_elements: &'a [TTLV],
}

impl<'a> ArrayDeserializer<'a> {
    pub(super) fn new(
        de: &'a mut TtlvDeserializer,
        tag: &str,
        struct_elements: &'a [TTLV],
    ) -> Self {
        ArrayDeserializer {
            de,
            tag: tag.to_owned(),
            struct_elements,
        }
    }
}

impl<'a, 'de: 'a> SeqAccess<'de> for ArrayDeserializer<'a> {
    type Error = TtlvError;

    #[instrument(skip(self, seed))]
    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        trace!(
            "array_access: next_element_seed in seq: {}, current index: {}, structure elems:  {:?}",
            self.tag,
            self.de.child_index,
            self.struct_elements
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
        let mut deserializer = TtlvDeserializer::from_ttlv(current_element.clone());
        // increment the current index
        self.de.child_index += 1;
        // deserialize the element
        let v = seed.deserialize(&mut deserializer).map(Some)?;
        Ok(v)
    }
}

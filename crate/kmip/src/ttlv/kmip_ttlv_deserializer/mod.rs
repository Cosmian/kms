mod adjacently_tagged_structure;
mod array_deserializer;
mod byte_string_deserializer;
mod deserializer;
mod enum_walker;
mod offset_date_time_deserializer;
mod structure_walker;
mod untagged_enum_walker;
pub use deserializer::{TtlvDeserializer, from_ttlv};
mod kmip_big_int_deserializer;

use super::{TTLV, TTLValue, TtlvError};

type Result<T> = std::result::Result<T, TtlvError>;

/// Helper function to get the child at the specified index of a Structure TTLV
/// Used in logging
fn peek_structure_child(ttlv: &TTLV, child_index: usize) -> Option<&TTLV> {
    let TTLValue::Structure(children) = &ttlv.value else {
        return None;
    };
    children.get(child_index)
}

mod array_deserializer;
mod byte_string_deserializer;
mod deserializer;
mod enum_walker;
mod offset_date_time_deserializer;
mod structure_walker;
mod untagged_enum_walker;
pub use deserializer::{from_ttlv, TtlvDeserializer};
mod kmip_big_int_deserializer;

use super::TtlvError;

type Result<T> = std::result::Result<T, TtlvError>;

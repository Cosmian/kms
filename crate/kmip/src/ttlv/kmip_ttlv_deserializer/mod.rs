mod array_deserializer;
mod byte_string_deserializer;
mod deserializer;
mod enum_walker;
mod structure_walker;
mod untagged_enum_walker;
pub use deserializer::{from_ttlv, TtlvDeserializer};

use super::TtlvError;

type Result<T> = std::result::Result<T, TtlvError>;

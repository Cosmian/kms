mod deserialize;
mod error;
mod kmip_big_int;
mod kmip_ttlv_deserializer;
mod normalize;
mod serialize;
mod tags;
mod ttlv_struct;
mod wire;
pub mod xml;

pub use error::TtlvError;
pub(crate) use kmip_big_int::KmipBigInt;
pub use kmip_ttlv_deserializer::{TtlvDeserializer, from_ttlv};
pub(super) mod kmip_ttlv_serializer;
pub use kmip_ttlv_serializer::{TtlvSerializer, to_ttlv};
pub(crate) use normalize::{collapse_adjacently_tagged_structure, normalize_ttlv};
pub use ttlv_struct::{KmipEnumerationVariant, KmipFlavor, TTLV, TTLValue, TtlvType};
pub use wire::{TTLVBytesDeserializer, TTLVBytesSerializer};

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::as_conversions,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::expect_used
)]
#[cfg(test)]
mod tests;

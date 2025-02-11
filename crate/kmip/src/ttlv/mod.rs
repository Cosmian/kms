// pub mod deserializer;
// pub mod deserializer_old;
pub mod error;
mod kmip_big_int;
mod kmip_big_int_deserializer;
pub mod kmip_to_ttlv_serializer;
pub mod ttlv_bytes_deserializer;
pub mod ttlv_bytes_serializer;
mod ttlv_struct;

mod deserialize;
mod serialize;

pub use kmip_big_int::KmipBigInt;
pub use ttlv_struct::{KmipEnumerationVariant, TTLValue, TtlvType, TTLV};

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::as_conversions,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#[cfg(test)]
mod tests;

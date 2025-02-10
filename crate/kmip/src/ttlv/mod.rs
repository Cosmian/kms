pub mod deserializer;
pub mod deserializer_old;
pub mod error;
mod kmip_big_int;
pub mod serde_ttlv;
pub mod serializer;
mod ttlv_struct;

mod deserialize;
mod serialize;

pub use kmip_big_int::KmipBigInt;
pub use ttlv_struct::{ItemTypeEnumeration, TTLVEnumeration, TTLValue, TTLV};

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

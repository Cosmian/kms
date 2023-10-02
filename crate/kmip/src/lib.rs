#![allow(clippy::upper_case_acronyms)]
//required to detect generic type in Serializer
#![feature(min_specialization)]
// To parse a slice
#![feature(slice_take)]

pub mod error;
mod id;
pub use id::id;
pub mod kmip;
pub mod result;

#[cfg(feature = "openssl")]
pub mod openssl;

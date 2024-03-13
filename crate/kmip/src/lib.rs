#![allow(clippy::upper_case_acronyms)]
// required to detect generic type in Serializer
#![feature(min_specialization)]
// To parse a slice
#![feature(slice_take)]

pub use error::{result::KmipResultHelper, KmipError};
pub use id::id;

pub mod crypto;
mod error;
mod id;
pub mod kmip;
#[cfg(feature = "openssl")]
pub mod openssl;

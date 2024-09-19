#![allow(clippy::upper_case_acronyms)]
// required to detect generic type in Serializer
#![feature(min_specialization)]
// To parse a slice
#![feature(slice_take)]

pub use error::{result::KmipResultHelper, KmipError};

pub mod crypto;
mod error;
pub mod kmip;
#[cfg(feature = "openssl")]
pub mod openssl;

pub fn pad_be_bytes(bytes: &mut Vec<u8>, size: usize) {
    while bytes.len() != size {
        bytes.insert(0, 0);
    }
}

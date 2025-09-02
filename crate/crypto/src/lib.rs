// required to detect generic type in Serializer
#![feature(min_specialization)]

pub use error::{CryptoError, result::CryptoResultHelper};

pub mod crypto;
mod error;
pub mod openssl;

pub fn pad_be_bytes(bytes: &mut Vec<u8>, size: usize) {
    while bytes.len() < size {
        bytes.insert(0, 0);
    }
}

pub mod reexport {
    #[cfg(feature = "non-fips")]
    pub use cosmian_cover_crypt;
    pub use cosmian_kmip;
}

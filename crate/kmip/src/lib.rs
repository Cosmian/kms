// required to detect the generic type in Serializer
#![feature(min_specialization)]

pub use error::{KmipError, result::KmipResultHelper};

mod bytes_ser_de;
pub use bytes_ser_de::{Deserializer, Serializer, test_serialization, to_leb128_len};
mod data_to_encrypt;
pub use data_to_encrypt::DataToEncrypt;
mod error;
pub mod kmip_0;
pub mod kmip_1_4;
pub mod kmip_2_1;
mod safe_bigint;
pub mod ttlv;

pub use safe_bigint::SafeBigInt;

pub fn pad_be_bytes(bytes: &mut Vec<u8>, size: usize) {
    while bytes.len() < size {
        bytes.insert(0, 0);
    }
}

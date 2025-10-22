mod bytes_ser_de;
mod data_to_encrypt;
mod error;
pub mod kmip_0;
pub mod kmip_1_4;
pub mod kmip_2_1;
mod safe_bigint;
mod time_utils;
pub mod ttlv;

pub use bytes_ser_de::{Deserializer, Serializer, test_serialization, to_leb128_len};
pub use data_to_encrypt::DataToEncrypt;
pub use error::{KmipError, result::KmipResultHelper};
pub use safe_bigint::SafeBigInt;
pub use time_utils::time_normalize;

pub fn pad_be_bytes(bytes: &mut Vec<u8>, size: usize) {
    while bytes.len() < size {
        bytes.insert(0, 0);
    }
}

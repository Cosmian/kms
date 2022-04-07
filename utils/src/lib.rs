use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::{Decrypt, DecryptResponse, Encrypt, EncryptResponse},
};
use result::LibResult;

pub mod crypto;
pub mod error;
pub mod kmip_utils;
pub mod result;

pub trait EnCipher {
    fn encrypt(&self, request: &Encrypt) -> LibResult<EncryptResponse>;
}

impl<T: EnCipher + ?Sized> EnCipher for Box<T> {
    fn encrypt(&self, request: &Encrypt) -> LibResult<EncryptResponse> {
        (**self).encrypt(request)
    }
}

pub trait DeCipher {
    fn decrypt(&self, request: &Decrypt) -> LibResult<DecryptResponse>;
}

/// A `KeyPair` is a tuple `(Object::PrivateKey, Object::PublicKey)`
///
/// Note: this object does not exist in the KMIP specs,
/// hence its definition here
pub struct KeyPair(pub (Object, Object));

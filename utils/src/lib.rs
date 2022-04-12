use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_objects::Object,
        kmip_operations::{Decrypt, DecryptResponse, Encrypt, EncryptResponse},
    },
};

pub mod crypto;
pub mod kmip_utils;

pub trait EnCipher {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmipError>;
}

impl<T: EnCipher + ?Sized> EnCipher for Box<T> {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmipError> {
        (**self).encrypt(request)
    }
}

pub trait DeCipher {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmipError>;
}

/// A `KeyPair` is a tuple `(Object::PrivateKey, Object::PublicKey)`
///
/// Note: this object does not exist in the KMIP specs,
/// hence its definition here
pub struct KeyPair(pub (Object, Object));

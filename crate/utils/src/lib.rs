use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::{Decrypt, DecryptResponse, Encrypt, EncryptResponse},
};
use error::KmipUtilsError;

pub mod access;
pub mod crypto;
pub mod error;
pub mod kmip_utils;
pub mod tagging;

pub trait EncryptionSystem {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmipUtilsError>;
}

impl<T: EncryptionSystem + ?Sized> EncryptionSystem for Box<T> {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmipUtilsError> {
        (**self).encrypt(request)
    }
}

pub trait DecryptionSystem {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmipUtilsError>;
}

/// A `KeyPair` is a tuple `(Object::PrivateKey, Object::PublicKey)`
///
/// Note: this object does not exist in the KMIP specs,
/// hence its definition here
pub struct KeyPair(pub (Object, Object));
impl KeyPair {
    /// Create a new `KeyPair` from a private and public key
    #[must_use]
    pub fn new(private_key: Object, public_key: Object) -> Self {
        Self((private_key, public_key))
    }

    /// Get the private key
    #[must_use]
    pub fn private_key(&self) -> &Object {
        &self.0.0
    }

    /// Get the public key
    #[must_use]
    pub fn public_key(&self) -> &Object {
        &self.0.1
    }

    /// Get the private key
    pub fn private_key_mut(&mut self) -> &mut Object {
        &mut self.0.0
    }

    /// Get the public key
    pub fn public_key_mut(&mut self) -> &mut Object {
        &mut self.0.1
    }
}

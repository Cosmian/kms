#![feature(slice_take)]

pub mod cover_crypt;
pub mod dh_shared_keys;
pub mod elliptic_curves;
pub mod error;
pub mod generic;
pub mod hybrid_encryption;
pub mod password_derivation;
pub mod rsa;
pub mod symmetric;
pub mod wrap;

use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::{Decrypt, DecryptResponse, Encrypt, EncryptResponse},
};
pub use elliptic_curves::Q_LENGTH_BITS;
use error::KmsCryptoError;

pub trait EncryptionSystem {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmsCryptoError>;
}

impl<T: EncryptionSystem + ?Sized> EncryptionSystem for Box<T> {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmsCryptoError> {
        (**self).encrypt(request)
    }
}

pub trait DecryptionSystem {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmsCryptoError>;
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

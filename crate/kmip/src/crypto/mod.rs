pub use elliptic_curves::CURVE_25519_Q_LENGTH_BITS;
pub use password_derivation::FIPS_MIN_SALT_SIZE;

use crate::{
    error::KmipError,
    kmip::{
        kmip_objects::Object,
        kmip_operations::{Decrypt, DecryptResponse, Encrypt, EncryptResponse},
    },
};

pub mod certificates;
pub mod cover_crypt;
pub mod dh_shared_keys;
pub mod elliptic_curves;
pub mod generic;
pub mod password_derivation;
pub mod rsa;
pub mod secret;
pub mod symmetric;

pub mod wrap;

pub trait EncryptionSystem {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmipError>;
}

impl<T: EncryptionSystem + ?Sized> EncryptionSystem for Box<T> {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmipError> {
        (**self).encrypt(request)
    }
}

pub trait DecryptionSystem {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmipError>;
}

/// A `KeyPair` is a tuple `(Object::PrivateKey, Object::PublicKey)`
///
/// Note: this object does not exist in the KMIP specs,
/// hence its definition here
pub struct KeyPair(pub (Object, Object));
impl KeyPair {
    /// Create a new `KeyPair` from a private and public key
    #[must_use]
    pub const fn new(private_key: Object, public_key: Object) -> Self {
        Self((private_key, public_key))
    }

    /// Get the private key
    #[must_use]
    pub const fn private_key(&self) -> &Object {
        &self.0.0
    }

    /// Get the public key
    #[must_use]
    pub const fn public_key(&self) -> &Object {
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

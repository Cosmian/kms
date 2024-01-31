#![feature(slice_take)]

use cosmian_kmip::kmip::{
    kmip_objects::Object,
    // kmip_operations::{Decrypt, DecryptResponse, Encrypt, EncryptResponse},
};
// use error::KmipUtilsError;

pub mod access;
// pub mod crypto;
pub mod error;
// pub mod kmip_utils;
pub mod tagging;
pub mod tee;

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

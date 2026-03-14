use std::hash::Hash;

use crate::{
    ModuleResult,
    traits::{KeyAlgorithm, PublicKey},
};

pub trait Certificate: Send + Sync + std::fmt::Debug {
    fn remote_id(&self) -> String;
    fn to_der(&self) -> ModuleResult<Vec<u8>>;
    /// Returns the public key of the certificate
    /// This key should no be kept in cache the session; its ID is empty
    fn public_key(&self) -> ModuleResult<Box<dyn PublicKey>>;
    fn algorithm(&self) -> ModuleResult<KeyAlgorithm> {
        Ok(self.public_key()?.algorithm())
    }
    fn issuer(&self) -> ModuleResult<Vec<u8>>;
    fn serial_number(&self) -> ModuleResult<Vec<u8>>;
    fn subject(&self) -> ModuleResult<Vec<u8>>;

    /// This returns the private key ID associated with the certificate
    /// which the `CKA_ID`
    fn private_key_id(&self) -> String;
}

impl PartialEq for dyn Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.remote_id() == other.remote_id()
    }
}

impl Eq for dyn Certificate {}

impl Hash for dyn Certificate {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.remote_id().hash(state);
    }
}

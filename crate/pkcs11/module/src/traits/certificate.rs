use std::{any::Any, hash::Hash};

use log::trace;

use crate::{
    core::compoundid::Id,
    traits::{KeyAlgorithm, PublicKey},
    MResult,
};

pub trait Certificate: Send + Sync + std::fmt::Debug {
    fn label(&self) -> String;
    fn to_der(&self) -> MResult<Vec<u8>>;
    fn public_key(&self) -> MResult<&dyn PublicKey>;
    fn algorithm(&self) -> MResult<KeyAlgorithm> {
        Ok(self.public_key()?.algorithm())
    }
    fn issuer(&self) -> MResult<Vec<u8>>;
    fn serial_number(&self) -> MResult<Vec<u8>>;
    fn subject(&self) -> MResult<Vec<u8>>;

    /// ID used as CKA_ID when searching objects by ID
    fn id(&self) -> Id {
        trace!("Certificate::id label = {:?}", self.label());
        trace!(
            "Certificate::id public key = {:?}",
            self.public_key().unwrap().fingerprint()
        );
        trace!(
            "Certificate::id hash = {:?}",
            self.public_key().public_key_hash()
        );
        Id {
            label: self.label(),
            hash: self.serial_number(),
        }
    }
}

impl PartialEq for dyn Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.to_der().unwrap_or_else(|_| vec![]) == other.to_der().unwrap_or_else(|_| vec![])
            && self.label() == other.label()
    }
}

impl Eq for dyn Certificate {}

impl Hash for dyn Certificate {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.type_id().hash(state);
        self.to_der()
            .unwrap_or_else(|_| vec![]) //unlikely: the certificate is originally parsed from DER
            .hash(state);
        self.label().hash(state);
    }
}

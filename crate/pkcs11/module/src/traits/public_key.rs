use std::{any::Any, hash::Hash, sync::Arc};

use pkcs1::RsaPublicKey;

use crate::{
    core::compoundid::Id,
    traits::{KeyAlgorithm, SignatureAlgorithm},
    MResult,
};

pub trait PublicKey: Send + Sync {
    fn fingerprint(&self) -> &[u8];
    fn label(&self) -> String {
        "PublicKey".to_string()
    }
    // fn to_der(&self) -> Vec<u8>;
    fn verify(&self, algorithm: &SignatureAlgorithm, data: &[u8], signature: &[u8]) -> MResult<()>;
    fn delete(self: Arc<Self>);
    fn algorithm(&self) -> KeyAlgorithm;

    /// ID used as CKA_ID when searching objects by ID
    fn id(&self) -> Id {
        Id {
            label: self.label(),
            hash: self.fingerprint().to_vec(),
        }
    }

    /// Return the RSA public key if the key is an RSA key
    fn rsa_public_key(&self) -> MResult<RsaPublicKey>;

    /// Return the RSA modulus if the key is an RSA key
    /// In big endian
    fn rsa_modulus(&self) -> MResult<Vec<u8>> {
        Ok(self.rsa_public_key()?.modulus.as_bytes().to_vec())
    }

    /// Return the RSA public exponent if the key is an RSA key
    /// In big endian
    fn rsa_public_exponent(&self) -> MResult<Vec<u8>> {
        Ok(self.rsa_public_key()?.public_exponent.as_bytes().to_vec())
    }

    /// Return the EC P256 public key if the key is an EC key
    fn ec_p256_public_key(&self) -> MResult<p256::PublicKey>;
}

impl PartialEq for dyn PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.fingerprint() == other.fingerprint() && self.label() == other.label()
    }
}

impl Eq for dyn PublicKey {}

impl Hash for dyn PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.type_id().hash(state);
        self.fingerprint().hash(state);
        self.label().hash(state);
    }
}

use std::{hash::Hash, sync::Arc};

use pkcs1::RsaPublicKey;

use crate::{
    traits::{KeyAlgorithm, SignatureAlgorithm},
    MResult,
};

pub trait PublicKey: Send + Sync {
    /// The unique ID of the key (in the KMS)
    fn remote_id(&self) -> String;
    fn fingerprint(&self) -> &[u8];
    fn verify(&self, algorithm: &SignatureAlgorithm, data: &[u8], signature: &[u8]) -> MResult<()>;
    fn delete(self: Arc<Self>);
    fn algorithm(&self) -> KeyAlgorithm;
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
        self.remote_id() == other.remote_id()
    }
}

impl Eq for dyn PublicKey {}

impl Hash for dyn PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.remote_id().hash(state);
    }
}

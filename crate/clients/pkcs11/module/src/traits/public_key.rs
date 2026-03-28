use std::sync::Arc;

use pkcs1::RsaPublicKey;

use crate::{
    ModuleResult,
    traits::{KeyAlgorithm, SignatureAlgorithm},
};

pub trait PublicKey: Send + Sync {
    /// The unique ID of the key (in the KMS)
    fn remote_id(&self) -> &str;
    fn fingerprint(&self) -> &[u8];
    fn verify(
        &self,
        algorithm: &SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> ModuleResult<()>;
    fn delete(self: Arc<Self>);
    fn algorithm(&self) -> KeyAlgorithm;
    /// Return the RSA public key if the key is an RSA key
    fn rsa_public_key(&self) -> ModuleResult<RsaPublicKey<'_>>;
    /// Return the RSA modulus if the key is an RSA key
    /// In big endian
    fn rsa_modulus(&self) -> ModuleResult<Vec<u8>> {
        Ok(self.rsa_public_key()?.modulus.as_bytes().to_vec())
    }
    /// Return the RSA public exponent if the key is an RSA key
    /// In big endian
    fn rsa_public_exponent(&self) -> ModuleResult<Vec<u8>> {
        Ok(self.rsa_public_key()?.public_exponent.as_bytes().to_vec())
    }
    /// Return the EC P256 public key if the key is an EC key
    fn ec_p256_public_key(&self) -> ModuleResult<p256::PublicKey>;
}

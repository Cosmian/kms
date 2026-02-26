use std::sync::Arc;

use cosmian_logger::error;
use cosmian_pkcs11_module::{
    ModuleError, ModuleResult,
    traits::{KeyAlgorithm, PublicKey, SignatureAlgorithm},
};
use p256::pkcs8::DecodePublicKey;
use pkcs1::{RsaPublicKey, der::Decode};
use sha3::Digest;
use x509_cert::{der::Encode, spki::SubjectPublicKeyInfoOwned};
use zeroize::Zeroizing;

pub(crate) struct Pkcs11PublicKey {
    remote_id: String,
    /// DER bytes of the public key
    der_bytes: Zeroizing<Vec<u8>>,
    /// SHA 256 fingerprint of the public key
    fingerprint: Vec<u8>,
    /// DER bytes of the algorithm OID
    algorithm: KeyAlgorithm,
}

impl Pkcs11PublicKey {
    pub(crate) fn new(remote_id: String, algorithm: KeyAlgorithm) -> Self {
        Self {
            remote_id,
            der_bytes: Zeroizing::new(vec![]),
            algorithm,
            fingerprint: vec![],
        }
    }

    pub(crate) fn try_from_spki(spki: &SubjectPublicKeyInfoOwned) -> ModuleResult<Self> {
        let algorithm = &spki.algorithm;
        let algorithm = KeyAlgorithm::from_oid(&algorithm.oid).ok_or_else(|| {
            ModuleError::BadArguments(format!("OID not found: {}", algorithm.oid))
        })?;
        let der_bytes = Zeroizing::new(spki.to_der()?);
        let fingerprint = sha3::Sha3_256::digest(&der_bytes).to_vec();
        Ok(Self {
            remote_id: String::new(),
            der_bytes,
            fingerprint,
            algorithm,
        })
    }
}

impl PublicKey for Pkcs11PublicKey {
    fn remote_id(&self) -> String {
        self.remote_id.clone()
    }

    fn fingerprint(&self) -> &[u8] {
        &self.fingerprint
    }

    fn verify(
        &self,
        _algorithm: &SignatureAlgorithm,
        _data: &[u8],
        _signature: &[u8],
    ) -> ModuleResult<()> {
        error!("verify not implemented for Pkcs11PublicKey");
        Err(ModuleError::FunctionNotSupported)
    }

    fn delete(self: Arc<Self>) {}

    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    fn rsa_public_key(&self) -> ModuleResult<RsaPublicKey<'_>> {
        if self.algorithm == KeyAlgorithm::Rsa {
            RsaPublicKey::from_der(&self.der_bytes).map_err(|e| {
                error!("Failed to parse RSA public key: {:?}", e);
                ModuleError::Cryptography("Failed to parse RSA public key".to_owned())
            })
        } else {
            error!("Public key is not an RSA key");
            Err(ModuleError::Cryptography(
                "Public key is not an RSA key".to_owned(),
            ))
        }
    }

    fn ec_p256_public_key(&self) -> ModuleResult<p256::PublicKey> {
        if self.algorithm == KeyAlgorithm::EccP256 {
            let ec_p256 = p256::PublicKey::from_public_key_der(&self.der_bytes).map_err(|e| {
                ModuleError::Cryptography(format!("Failed to parse EC P256 public key: {e:?}"))
            })?;
            Ok(ec_p256)
        } else {
            error!("Public key is not an EC P256 key");
            Err(ModuleError::Cryptography(
                "Public key is not an EC P256 key".to_owned(),
            ))
        }
    }
}

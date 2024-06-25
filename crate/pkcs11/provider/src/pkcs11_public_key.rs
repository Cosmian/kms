use std::sync::Arc;

use cosmian_pkcs11_module::{
    traits::{KeyAlgorithm, PublicKey, SignatureAlgorithm},
    MError, MResult,
};
use p256::pkcs8::DecodePublicKey;
use pkcs1::{der::Decode, RsaPublicKey};
use sha3::Digest;
use tracing::error;
use x509_cert::{der::Encode, spki::SubjectPublicKeyInfoOwned};

pub struct Pkcs11PublicKey {
    /// DER bytes of the public key
    der_bytes: Vec<u8>,
    /// SHA 256 fingerprint of the public key
    fingerprint: Vec<u8>,
    /// DER bytes of the algorithm OID
    algorithm: KeyAlgorithm,
}

enum PublicKeyType<'a> {
    Rsa(RsaPublicKey<'a>),
    P256(p256::PublicKey),
}

impl Pkcs11PublicKey {
    pub fn try_from_spki(spki: &SubjectPublicKeyInfoOwned) -> MResult<Self> {
        let algorithm = &spki.algorithm;
        let algorithm =
            KeyAlgorithm::from_oid(&algorithm.oid).ok_or_else(|| MError::ArgumentsBad)?;
        let der_bytes = spki.to_der()?;
        let fingerprint = sha3::Sha3_256::digest(&der_bytes).to_vec();
        Ok(Self {
            der_bytes,
            fingerprint,
            algorithm,
        })
    }
}

impl PublicKey for Pkcs11PublicKey {
    fn fingerprint(&self) -> &[u8] {
        &self.fingerprint
    }

    // fn to_der(&self) -> Vec<u8> {
    //     self.der_bytes.clone()
    // }

    fn verify(
        &self,
        _algorithm: &SignatureAlgorithm,
        _data: &[u8],
        _signature: &[u8],
    ) -> MResult<()> {
        error!("verify not implemented for Pkcs11PublicKey");
        todo!()
    }

    fn delete(self: Arc<Self>) {}

    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm.clone()
    }

    fn rsa_public_key(&self) -> MResult<RsaPublicKey> {
        match self.algorithm {
            KeyAlgorithm::Rsa => RsaPublicKey::from_der(&self.der_bytes).map_err(|e| {
                error!("Failed to parse RSA public key: {:?}", e);
                MError::Cryptography("Failed to parse RSA public key".to_string())
            }),
            _ => {
                error!("Public key is not an RSA key");
                Err(MError::Cryptography(
                    "Public key is not an RSA key".to_string(),
                ))
            }
        }
    }

    fn ec_p256_public_key(&self) -> MResult<p256::PublicKey> {
        match self.algorithm {
            KeyAlgorithm::EccP256 => {
                let ec_p256 = p256::PublicKey::from_public_key_der(&self.der_bytes)?;
                Ok(ec_p256)
            }
            _ => {
                error!("Public key is not an EC P256 key");
                Err(MError::Cryptography(
                    "Public key is not an EC P256 key".to_string(),
                ))
            }
        }
    }
}

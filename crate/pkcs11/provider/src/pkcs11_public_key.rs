use std::sync::Arc;

use cosmian_pkcs11_module::{
    traits::{KeyAlgorithm, PublicKey, SignatureAlgorithm},
    MError, MResult,
};
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

    fn label(&self) -> String {
        "PublicKey".to_string()
    }

    fn to_der(&self) -> Vec<u8> {
        self.der_bytes.clone()
    }

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
}

use std::sync::Arc;

use cosmian_pkcs11_module::{
    traits::{KeyAlgorithm, PublicKey, SignatureAlgorithm},
    MResult,
};
use x509_cert::{
    der::Encode,
    spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfoOwned},
};

pub struct Pkcs11PublicKey {
    /// DER bytes of the public key
    der_bytes: Vec<u8>,
    /// SHA 256 fingerprint of the public key
    fingerprint: Vec<u8>,
    /// DER bytes of the algorithm OID
    algorithm_identifier: KeyAlgorithm,
}

impl Pkcs11PublicKey {
    pub fn try_from_spki(spki: &SubjectPublicKeyInfoOwned) -> MResult<Self> {
        let (oid, params_oid) = spki.algorithm.oids()?;
        Ok(Self {
            der_bytes: spki.to_der()?,
            fingerprint: spki.fingerprint_bytes()?.to_vec(),
            algorithm_identifier: oid.to_der(),
            algorithm_identifier_params: params_oid.map(|oid| oid.to_der()),
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

    fn verify(&self, algorithm: &SignatureAlgorithm, data: &[u8], signature: &[u8]) -> MResult<()> {
        todo!()
    }

    fn delete(self: Arc<Self>) {
        todo!()
    }

    fn algorithm(&self) -> KeyAlgorithm {
        todo!()
    }
}

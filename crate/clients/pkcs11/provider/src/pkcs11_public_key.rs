use std::sync::Arc;

use cosmian_kms_logger::error;
use cosmian_pkcs11_module::{
    ModuleError, ModuleResult,
    traits::{KeyAlgorithm, PublicKey, SignatureAlgorithm},
};
use pkcs1::{RsaPublicKey, der::Decode};
use sha3::Digest;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use zeroize::Zeroizing;

use crate::kms_object::KmsObject;

pub(crate) struct Pkcs11PublicKey {
    remote_id: String,
    /// For RSA: inner PKCS#1 DER bytes extracted from SPKI's BIT STRING.
    /// For EC: raw SEC1 point bytes (04 || x || y) extracted from SPKI's BIT STRING.
    /// Storing the inner bytes directly avoids re-parsing the SPKI wrapper on every
    /// attribute access and sidesteps DER crate version mismatches with `DecodePublicKey`.
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
            fingerprint: vec![],
            algorithm,
        }
    }

    pub(crate) fn try_from_spki(spki: &SubjectPublicKeyInfoOwned) -> ModuleResult<Self> {
        // For EC keys, the algorithm OID in SPKI is id-ecPublicKey (1.2.840.10045.2.1)
        // and the curve OID lives in the parameters.
        // For all other key types (RSA, EdDSA, X25519, …) the algorithm OID is the identity.
        let algorithm = if spki.algorithm.oid.to_string() == "1.2.840.10045.2.1" {
            let params = spki.algorithm.parameters.as_ref().ok_or_else(|| {
                ModuleError::BadArguments("EC SPKI is missing curve OID in parameters".to_owned())
            })?;
            let curve_oid = params.decode_as::<pkcs1::ObjectIdentifier>().map_err(|e| {
                ModuleError::Cryptography(format!(
                    "failed to decode EC curve OID from SPKI parameters: {e}"
                ))
            })?;
            KeyAlgorithm::from_oid(&curve_oid).ok_or_else(|| {
                ModuleError::BadArguments(format!("EC curve OID not supported: {curve_oid}"))
            })?
        } else {
            KeyAlgorithm::from_oid(&spki.algorithm.oid).ok_or_else(|| {
                ModuleError::BadArguments(format!("OID not found: {}", spki.algorithm.oid))
            })?
        };
        // Extract the inner key bytes from the SPKI's BIT STRING:
        //   RSA  → PKCS#1 DER (SEQUENCE { INTEGER n, INTEGER e })
        //   EC   → raw SEC1 point bytes (04 || x || y)
        let inner_key_bytes = spki.subject_public_key.raw_bytes().to_vec();
        let fingerprint = sha3::Sha3_256::digest(&inner_key_bytes).to_vec();
        let der_bytes = Zeroizing::new(inner_key_bytes);
        Ok(Self {
            remote_id: String::new(),
            der_bytes,
            fingerprint,
            algorithm,
        })
    }

    /// Build a `Pkcs11PublicKey` from a KMS-exported public key object.
    ///
    /// The KMS object is expected to carry the public key in PKCS#8 format
    /// (`SubjectPublicKeyInfo` DER bytes), which is what `get_kms_object` returns
    /// when `KeyFormatType::PKCS8` is requested for a public key.
    pub(crate) fn try_from_kms_object(kms_object: &KmsObject) -> ModuleResult<Self> {
        let raw_bytes = Zeroizing::new(
            kms_object
                .object
                .key_block()
                .map_err(|e| ModuleError::Cryptography(e.to_string()))?
                .key_bytes()
                .map_err(|e| ModuleError::Cryptography(e.to_string()))?
                .to_vec(),
        );
        let spki = SubjectPublicKeyInfoOwned::from_der(&raw_bytes)
            .map_err(|e| ModuleError::Cryptography(format!("invalid SPKI DER: {e}")))?;
        let mut key = Self::try_from_spki(&spki)?;
        key.remote_id.clone_from(&kms_object.remote_id);
        Ok(key)
    }
}

impl PublicKey for Pkcs11PublicKey {
    fn remote_id(&self) -> &str {
        &self.remote_id
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
            // der_bytes stores the PKCS#1 RSA bytes extracted from SPKI's BIT STRING
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
            // der_bytes stores the raw SEC1 point bytes (04 || x || y) from SPKI's BIT STRING
            p256::PublicKey::from_sec1_bytes(&self.der_bytes).map_err(|e| {
                error!("Failed to parse EC P256 public key: {:?}", e);
                ModuleError::Cryptography(format!("Failed to parse EC P256 public key: {e:?}"))
            })
        } else {
            error!("Public key is not an EC P256 key");
            Err(ModuleError::Cryptography(
                "Public key is not an EC P256 key".to_owned(),
            ))
        }
    }
}

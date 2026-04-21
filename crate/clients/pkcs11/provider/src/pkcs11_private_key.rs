use cosmian_kms_logger::error;
use cosmian_pkcs11_module::{
    ModuleError, ModuleResult,
    traits::{KeyAlgorithm, PrivateKey, SearchOptions, SignatureAlgorithm, backend},
};
use pkcs1::{RsaPrivateKey, der::Decode};
use zeroize::Zeroizing;

use crate::kms_object::{KmsObject, LazyKeyMaterial, key_algorithm_from_attributes};

/// A PKCS11 Private Key implementation that may only hold remote
/// references to the actual private key
#[derive(Debug)]
pub(crate) struct Pkcs11PrivateKey {
    remote_id: String,
    algorithm: KeyAlgorithm,
    key_size: usize,
    /// DER bytes of the private key — lazy-loaded on first use.
    der_bytes: LazyKeyMaterial,
}

impl Pkcs11PrivateKey {
    pub(crate) const fn new(remote_id: String, algorithm: KeyAlgorithm, key_size: usize) -> Self {
        Self {
            remote_id,
            der_bytes: LazyKeyMaterial::new(),
            algorithm,
            key_size,
        }
    }

    pub(crate) fn try_from_kms_object(kms_object: KmsObject) -> ModuleResult<Self> {
        let der_bytes = LazyKeyMaterial::preloaded(
            kms_object
                .object
                .key_block()
                .map_err(|e| ModuleError::Cryptography(e.to_string()))?
                .key_bytes()
                .map_err(|e| ModuleError::Cryptography(e.to_string()))?,
        );
        let key_size =
            usize::try_from(kms_object.attributes.cryptographic_length.ok_or_else(|| {
                ModuleError::Cryptography("try_from_kms_object: missing key size".to_owned())
            })?)?;
        let algorithm = key_algorithm_from_attributes(&kms_object.attributes)?;

        Ok(Self {
            remote_id: kms_object.remote_id,
            algorithm,
            key_size,
            der_bytes,
        })
    }
}

impl PrivateKey for Pkcs11PrivateKey {
    fn remote_id(&self) -> &str {
        &self.remote_id
    }

    fn sign(&self, algorithm: &SignatureAlgorithm, data: &[u8]) -> ModuleResult<Vec<u8>> {
        backend()?
            .remote_sign(&self.remote_id, algorithm, data)
            .map_err(|e| {
                error!(
                    "remote_sign failed for Pkcs11PrivateKey with remote_id {}: {e}",
                    self.remote_id
                );
                e
            })
    }

    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    fn key_size(&self) -> usize {
        self.key_size
    }

    fn pkcs8_der_bytes(&self) -> ModuleResult<Zeroizing<Vec<u8>>> {
        self.der_bytes.get_or_fetch(|| {
            let sk = backend()?.find_private_key(SearchOptions::Id(self.remote_id.clone()))?;
            sk.pkcs8_der_bytes()
        })
    }

    fn rsa_public_exponent(&self) -> ModuleResult<Vec<u8>> {
        let der_bytes = self.pkcs8_der_bytes()?;
        let rsa_key = RsaPrivateKey::from_der(der_bytes.as_ref()).map_err(|e| {
            error!("Failed to parse RSA private key: {:?}", e);
            ModuleError::Cryptography("Failed to parse RSA private key".to_owned())
        })?;
        Ok(rsa_key.public_exponent.as_bytes().to_vec())
    }

    // fn ec_p256_private_key(&self) -> MResult<p256::SecretKey> {
    //     match self.algorithm {
    //         KeyAlgorithm::EccP256 => {
    //             let ec_p256 = p256::SecretKey::from_pkcs8_der(self.pkcs8_der_bytes()?.as_ref())
    //                 .map_err(|e| {
    //                     ModuleError::Cryptography(format!(
    //                         "Failed to parse EC P256 private key: {:?}",
    //                         e
    //                     ))
    //                 })?;
    //             Ok(ec_p256)
    //         }
    //         _ => {
    //             error!("Public key is not an EC P256 key");
    //             Err(ModuleError::Cryptography(
    //                 "Public key is not an EC P256 key".to_string(),
    //             ))
    //         }
    //     }
    // }
}

use std::sync::{Arc, RwLock};

use cosmian_logger::error;
use cosmian_pkcs11_module::{
    ModuleError, ModuleResult,
    traits::{KeyAlgorithm, PrivateKey, SearchOptions, SignatureAlgorithm, backend},
};
use pkcs1::{RsaPrivateKey, der::Decode};
use zeroize::Zeroizing;

use crate::kms_object::{KmsObject, key_algorithm_from_attributes};

/// A PKCS11 Private Key implementation that may only hold remote
/// references to the actual private key
#[derive(Debug)]
pub(crate) struct Pkcs11PrivateKey {
    remote_id: String,
    algorithm: KeyAlgorithm,
    key_size: usize,
    /// DER bytes of the private key - those are lazy loaded
    /// when the private key is used
    der_bytes: Arc<RwLock<Zeroizing<Vec<u8>>>>,
}

impl Pkcs11PrivateKey {
    pub(crate) fn new(remote_id: String, algorithm: KeyAlgorithm, key_size: usize) -> Self {
        Self {
            remote_id,
            der_bytes: Arc::new(RwLock::new(Zeroizing::new(vec![]))),
            algorithm,
            key_size,
        }
    }

    pub(crate) fn try_from_kms_object(kms_object: KmsObject) -> ModuleResult<Self> {
        let der_bytes = Arc::new(RwLock::new(
            kms_object
                .object
                .key_block()
                .map_err(|e| ModuleError::Cryptography(e.to_string()))?
                .key_bytes()
                .map_err(|e| ModuleError::Cryptography(e.to_string()))?,
        ));
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
    fn remote_id(&self) -> String {
        self.remote_id.clone()
    }

    fn sign(&self, _algorithm: &SignatureAlgorithm, _data: &[u8]) -> ModuleResult<Vec<u8>> {
        error!(
            "sign not implemented for Pkcs11PrivateKey with remote_id: {}",
            self.remote_id
        );
        Err(ModuleError::FunctionNotSupported)
    }

    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    fn key_size(&self) -> usize {
        self.key_size
    }

    fn pkcs8_der_bytes(&self) -> ModuleResult<Zeroizing<Vec<u8>>> {
        let der_bytes = self
            .der_bytes
            .read()
            .map_err(|e| {
                error!("Failed to read DER bytes: {:?}", e);
                ModuleError::Cryptography("Failed to read DER bytes".to_owned())
            })?
            .clone();
        if !der_bytes.is_empty() {
            return Ok(der_bytes);
        }
        let sk =
            backend().find_private_key(SearchOptions::Id(self.remote_id.clone().into_bytes()))?;
        let mut der_bytes = self.der_bytes.write().map_err(|e| {
            error!("Failed to write DER bytes: {:?}", e);
            ModuleError::Cryptography("Failed to write DER bytes".to_owned())
        })?;
        *der_bytes = sk.pkcs8_der_bytes().map_err(|e| {
            error!("Failed to fetch the PKCS8 DER bytes: {:?}", e);
            ModuleError::Cryptography("Failed to fetch the PKCS8 DER bytes".to_owned())
        })?;
        Ok(der_bytes.clone())
    }

    fn rsa_public_exponent(&self) -> ModuleResult<Vec<u8>> {
        let pkcs8_der_bytes = self.der_bytes.read().map_err(|e| {
            error!("Failed to read DER bytes: {:?}", e);
            ModuleError::Cryptography("Failed to read DER bytes".to_owned())
        })?;
        let res = if pkcs8_der_bytes.is_empty() {
            return Err(ModuleError::Cryptography(
                "Failed to obtain public exponent for unloaded private key".to_owned(),
            ));
        } else {
            let rsa_key = RsaPrivateKey::from_der(pkcs8_der_bytes.as_ref()).map_err(|e| {
                error!("Failed to parse RSA public key: {:?}", e);
                ModuleError::Cryptography("Failed to parse RSA public key".to_owned())
            })?;
            rsa_key.public_exponent.as_bytes().to_vec()
        };
        drop(pkcs8_der_bytes);
        Ok(res)
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

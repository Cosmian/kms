use std::sync::{Arc, RwLock};

use cosmian_pkcs11_module::{
    traits::{backend, KeyAlgorithm, PrivateKey, SearchOptions, SignatureAlgorithm},
    MError, MResult,
};
use pkcs1::{der::Decode, RsaPrivateKey};
use tracing::{error, info};
use zeroize::Zeroizing;

use crate::kms_object::{key_algorithm_from_attributes, KmsObject};

/// A PKCS11 Private Key implementation that may only hold remote
/// references to the actual private key
#[derive(Debug)]
pub struct Pkcs11PrivateKey {
    remote_id: String,
    algorithm: KeyAlgorithm,
    key_size: usize,
    /// DER bytes of the private key - those are lazy loaded
    /// when the private key is used
    der_bytes: Arc<RwLock<Zeroizing<Vec<u8>>>>,
}

impl Pkcs11PrivateKey {
    pub fn new(remote_id: String, algorithm: KeyAlgorithm, key_size: usize) -> Self {
        Self {
            remote_id,
            der_bytes: Arc::new(RwLock::new(Zeroizing::new(vec![]))),
            algorithm,
            key_size,
        }
    }

    pub fn try_from_kms_object(remote_id: String, kms_object: KmsObject) -> MResult<Self> {
        let der_bytes = Arc::new(RwLock::new(
            kms_object
                .object
                .key_block()
                .map_err(|e| MError::Cryptography(e.to_string()))?
                .key_bytes()
                .map_err(|e| MError::Cryptography(e.to_string()))?,
        ));
        info!("attributes: {:?}", kms_object.attributes);
        let key_size = kms_object.attributes.cryptographic_length.ok_or_else(|| {
            MError::Cryptography("try_from_kms_object: missing key size".to_string())
        })? as usize;
        let algorithm = key_algorithm_from_attributes(&kms_object.attributes)?;

        Ok(Self {
            remote_id,
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

    fn sign(&self, _algorithm: &SignatureAlgorithm, _data: &[u8]) -> MResult<Vec<u8>> {
        error!(
            "sign not implemented for Pkcs11PrivateKey with remote_id: {}",
            self.remote_id
        );
        todo!(
            "sign not implemented for Pkcs11PrivateKey with remote_id: {}",
            self.remote_id
        )
    }

    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    fn key_size(&self) -> usize {
        self.key_size
    }

    fn pkcs8_der_bytes(&self) -> MResult<Zeroizing<Vec<u8>>> {
        let der_bytes = self
            .der_bytes
            .read()
            .map_err(|e| {
                error!("Failed to read DER bytes: {:?}", e);
                MError::Cryptography("Failed to read DER bytes".to_string())
            })?
            .clone();
        if der_bytes.len() > 0 {
            return Ok(der_bytes);
        }
        let sk = backend().find_private_key(SearchOptions::Id(self.remote_id.clone()))?;
        let mut der_bytes = self.der_bytes.write().map_err(|e| {
            error!("Failed to write DER bytes: {:?}", e);
            MError::Cryptography("Failed to write DER bytes".to_string())
        })?;
        *der_bytes = sk.pkcs8_der_bytes().map_err(|e| {
            error!("Failed to fetch the PKCS8 DER bytes: {:?}", e);
            MError::Cryptography("Failed to fetch the PKCS8 DER bytes".to_string())
        })?;
        Ok(der_bytes.clone())
    }

    fn rsa_public_exponent(&self) -> MResult<Vec<u8>> {
        let pkcs8_der_bytes = self.der_bytes.read().map_err(|e| {
            error!("Failed to read DER bytes: {:?}", e);
            MError::Cryptography("Failed to read DER bytes".to_string())
        })?;
        Ok(if pkcs8_der_bytes.len() > 0 {
            let rsa_key = RsaPrivateKey::from_der(pkcs8_der_bytes.as_ref()).map_err(|e| {
                error!("Failed to parse RSA public key: {:?}", e);
                MError::Cryptography("Failed to parse RSA public key".to_string())
            })?;
            rsa_key.public_exponent.as_bytes().to_vec()
        } else {
            //TODO: not great but very little chance that 1/ it is different and 2/ it has any effect
            // we do not want to fetch the key bytes just for this
            65537_u32.to_be_bytes().to_vec()
        })
    }

    // fn ec_p256_private_key(&self) -> MResult<p256::SecretKey> {
    //     match self.algorithm {
    //         KeyAlgorithm::EccP256 => {
    //             let ec_p256 = p256::SecretKey::from_pkcs8_der(self.pkcs8_der_bytes()?.as_ref())
    //                 .map_err(|e| {
    //                     MError::Cryptography(format!(
    //                         "Failed to parse EC P256 private key: {:?}",
    //                         e
    //                     ))
    //                 })?;
    //             Ok(ec_p256)
    //         }
    //         _ => {
    //             error!("Public key is not an EC P256 key");
    //             Err(MError::Cryptography(
    //                 "Public key is not an EC P256 key".to_string(),
    //             ))
    //         }
    //     }
    // }
}

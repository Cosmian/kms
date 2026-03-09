use std::sync::{Arc, RwLock};

use cosmian_logger::error;
use cosmian_pkcs11_module::{
    ModuleError, ModuleResult,
    traits::{KeyAlgorithm, SearchOptions, SymmetricKey, backend},
};
use zeroize::Zeroizing;

use crate::kms_object::{KmsObject, key_algorithm_from_attributes};

/// A PKCS11 Symmetric Key implementation that may only hold remote
/// references to the actual symmetric key
#[derive(Debug)]
pub(crate) struct Pkcs11SymmetricKey {
    remote_id: String,
    algorithm: KeyAlgorithm,
    key_size: usize,
    /// Raw bytes of the symmetric key - those are lazy loaded
    /// when the symmetric key is used
    raw_bytes: Arc<RwLock<Zeroizing<Vec<u8>>>>,
}

impl Pkcs11SymmetricKey {
    pub(crate) fn new(remote_id: String, algorithm: KeyAlgorithm, key_size: usize) -> Self {
        Self {
            remote_id,
            raw_bytes: Arc::new(RwLock::new(Zeroizing::new(vec![]))),
            algorithm,
            key_size,
        }
    }

    pub(crate) fn try_from_kms_object(kms_object: KmsObject) -> ModuleResult<Self> {
        let raw_bytes = Arc::new(RwLock::new(
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
            raw_bytes,
        })
    }
}

impl SymmetricKey for Pkcs11SymmetricKey {
    fn remote_id(&self) -> String {
        self.remote_id.clone()
    }

    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    fn key_size(&self) -> usize {
        self.key_size
    }

    fn raw_bytes(&self) -> ModuleResult<Zeroizing<Vec<u8>>> {
        let raw_bytes = self
            .raw_bytes
            .read()
            .map_err(|e| {
                error!("Failed to read raw bytes: {:?}", e);
                ModuleError::Cryptography("Failed to read raw bytes".to_owned())
            })?
            .clone();
        if !raw_bytes.is_empty() {
            return Ok(raw_bytes);
        }
        let sk =
            backend().find_symmetric_key(SearchOptions::Id(self.remote_id.clone().into_bytes()))?;

        let mut raw_bytes = self.raw_bytes.write().map_err(|e| {
            error!("Failed to write raw bytes: {:?}", e);
            ModuleError::Cryptography("Failed to write raw bytes".to_owned())
        })?;
        *raw_bytes = sk.raw_bytes().map_err(|e| {
            error!("Failed to fetch the PKCS8 raw bytes: {:?}", e);
            ModuleError::Cryptography("Failed to fetch the PKCS8 raw bytes".to_owned())
        })?;
        Ok(raw_bytes.clone())
    }
}

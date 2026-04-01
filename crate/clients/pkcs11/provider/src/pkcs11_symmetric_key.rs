use cosmian_pkcs11_module::{
    ModuleError, ModuleResult,
    traits::{KeyAlgorithm, SearchOptions, SymmetricKey, backend},
};
use zeroize::Zeroizing;

use crate::kms_object::{KmsObject, LazyKeyMaterial, key_algorithm_from_attributes};

/// A PKCS11 Symmetric Key implementation that may only hold remote
/// references to the actual symmetric key
#[derive(Debug)]
pub(crate) struct Pkcs11SymmetricKey {
    remote_id: String,
    algorithm: KeyAlgorithm,
    key_size: usize,
    /// Raw bytes of the symmetric key — lazy-loaded on first use.
    raw_bytes: LazyKeyMaterial,
}

impl Pkcs11SymmetricKey {
    pub(crate) const fn new(remote_id: String, algorithm: KeyAlgorithm, key_size: usize) -> Self {
        Self {
            remote_id,
            raw_bytes: LazyKeyMaterial::new(),
            algorithm,
            key_size,
        }
    }

    pub(crate) fn try_from_kms_object(kms_object: KmsObject) -> ModuleResult<Self> {
        let raw_bytes = LazyKeyMaterial::preloaded(
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
            raw_bytes,
        })
    }
}

impl SymmetricKey for Pkcs11SymmetricKey {
    fn remote_id(&self) -> &str {
        &self.remote_id
    }

    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    fn key_size(&self) -> usize {
        self.key_size
    }

    fn raw_bytes(&self) -> ModuleResult<Zeroizing<Vec<u8>>> {
        self.raw_bytes.get_or_fetch(|| {
            let sk = backend().find_symmetric_key(SearchOptions::Id(self.remote_id.clone()))?;
            sk.raw_bytes()
        })
    }
}

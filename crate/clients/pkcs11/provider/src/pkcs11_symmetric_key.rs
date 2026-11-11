use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_0::kmip_types::CryptographicUsageMask;
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
    /// KMIP cryptographic usage mask, when the KMS reported one; drives `CKA_SIGN`/`CKA_VERIFY`.
    usage_mask: Option<CryptographicUsageMask>,
}

impl Pkcs11SymmetricKey {
    pub(crate) const fn new(
        remote_id: String,
        algorithm: KeyAlgorithm,
        key_size: usize,
        usage_mask: Option<CryptographicUsageMask>,
    ) -> Self {
        Self {
            remote_id,
            raw_bytes: LazyKeyMaterial::new(),
            algorithm,
            key_size,
            usage_mask,
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
            usage_mask: kms_object.attributes.cryptographic_usage_mask,
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
            let sk = backend()?.find_symmetric_key(SearchOptions::Id(self.remote_id.clone()))?;
            sk.raw_bytes()
        })
    }

    fn can_generate_mac(&self) -> bool {
        self.usage_mask
            .is_some_and(|mask| mask.contains(CryptographicUsageMask::MACGenerate))
    }

    fn can_verify_mac(&self) -> bool {
        self.usage_mask
            .is_some_and(|mask| mask.contains(CryptographicUsageMask::MACVerify))
    }
}

#[cfg(test)]
mod tests {
    use cosmian_pkcs11_module::traits::{KeyAlgorithm, SymmetricKey};

    use super::{CryptographicUsageMask, Pkcs11SymmetricKey};

    fn key(mask: Option<CryptographicUsageMask>) -> Pkcs11SymmetricKey {
        Pkcs11SymmetricKey::new("id".to_owned(), KeyAlgorithm::Aes256, 256, mask)
    }

    /// `CKA_SIGN` / `CKA_VERIFY` follow the KMIP `MACGenerate` / `MACVerify` usage-mask bits.
    #[test]
    fn mac_usage_follows_the_kmip_usage_mask() {
        let encrypt_only = key(Some(CryptographicUsageMask::Encrypt));
        assert!(!encrypt_only.can_generate_mac() && !encrypt_only.can_verify_mac());
        let unknown = key(None);
        assert!(!unknown.can_generate_mac() && !unknown.can_verify_mac());
        let generate = key(Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::MACGenerate,
        ));
        assert!(generate.can_generate_mac() && !generate.can_verify_mac());
        let verify = key(Some(CryptographicUsageMask::MACVerify));
        assert!(!verify.can_generate_mac() && verify.can_verify_mac());
    }
}

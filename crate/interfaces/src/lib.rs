mod crypto_oracle;
mod error;
mod hsm;
mod stores;

pub use crypto_oracle::{
    CryptoAlgorithm, CryptoOracle, EncryptedContent, KeyMetadata, SigningAlgorithm,
};
pub use error::{InterfaceError, InterfaceResult};
pub use hsm::{
    HSM, HsmBackend, HsmKeyAlgorithm, HsmKeypairAlgorithm, HsmObject, HsmObjectFilter, KeyMaterial,
    RsaPrivateKeyMaterial, RsaPublicKeyMaterial,
};
pub use stores::{AtomicOperation, ObjectWithMetadata, ObjectsStore, PermissionsStore};

/// Supported cryptographic object types
/// in plugins
#[derive(Debug, Eq, PartialEq)]
pub enum KeyType {
    AesKey,
    RsaPrivateKey,
    RsaPublicKey,
}

#[macro_export]
macro_rules! as_hsm_uid {
    // Old format: hsm::<slot_id>::<key_id>
    ($slot:expr, $uuid:expr) => {
        format!("hsm::{}::{}", $slot, $uuid)
    };
    // New format: hsm::<model>::<slot_id>::<key_id>
    ($model:expr, $slot:expr, $uuid:expr) => {
        format!("hsm::{}::{}::{}", $model, $slot, $uuid)
    };
}

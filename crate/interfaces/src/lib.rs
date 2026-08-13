mod crypto_oracle;
mod error;
mod hsm;
mod stores;

pub use crypto_oracle::{
    CryptoAlgorithm, CryptoOracle, EncryptedContent, KeyMetadata, SigningAlgorithm,
};
pub use error::{InterfaceError, InterfaceResult};
pub use hsm::{
    HSM, HsmKeyAlgorithm, HsmKeypairAlgorithm, HsmObject, HsmObjectFilter, HsmStore, KeyMaterial,
    RsaPrivateKeyMaterial, RsaPublicKeyMaterial,
};
pub use stores::{
    AtomicOperation, AuditSink, ChainHead, ObjectWithMetadata, ObjectsStore, PermissionsStore,
};

/// Number of seconds in one day — the finest granularity PKCS#11 `CK_DATE` can represent.
pub const SECS_PER_DAY: i64 = 24 * 3600;

/// Supported cryptographic object types
/// in plugins
#[derive(Debug, Clone, Eq, PartialEq)]
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

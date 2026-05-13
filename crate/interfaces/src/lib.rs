mod crypto_oracle;
mod error;
mod hsm;
mod stores;

pub use crypto_oracle::{
    CryptoAlgorithm, CryptoOracle, EncryptedContent, KeyMetadata, SigningAlgorithm,
};
pub use error::{InterfaceError, InterfaceResult};
pub use hsm::{
    HSM, HsmCryptoOracle, HsmKeyAlgorithm, HsmKeypairAlgorithm, HsmObject, HsmObjectFilter,
    HsmStore, KeyMaterial, RsaPrivateKeyMaterial, RsaPublicKeyMaterial,
};
pub use stores::{
    AtomicOperation, Notification, NotificationsStore, ObjectWithMetadata, ObjectsStore,
    PermissionsStore,
};

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
    ($slot:expr, $uuid:expr) => {
        format!("hsm::{}::{}", $slot, $uuid)
    };
}

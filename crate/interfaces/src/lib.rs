mod encryption_oracle;
mod error;
mod hsm;
mod stores;

pub use encryption_oracle::{CryptoAlgorithm, EncryptedContent, EncryptionOracle, KeyMetadata};
pub use error::{InterfaceError, InterfaceResult};
pub use hsm::{
    HsmEncryptionOracle, HsmKeyAlgorithm, HsmKeypairAlgorithm, HsmObject, HsmObjectFilter,
    HsmStore, KeyMaterial, RsaPrivateKeyMaterial, RsaPublicKeyMaterial, HSM,
};
pub use stores::{
    AtomicOperation, DbState, Migrate, ObjectWithMetadata, ObjectsStore, PermissionsStore,
    SessionParams,
};

/// Supported cryptographic object types
/// in plugins
#[derive(Debug, Eq, PartialEq)]
pub enum KeyType {
    AesKey,
    RsaPrivateKey,
    RsaPublicKey,
}

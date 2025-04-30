mod encryption_oracle;
mod error;
mod hsm;
mod stores;

pub use encryption_oracle::{CryptoAlgorithm, EncryptedContent, EncryptionOracle, KeyMetadata};
pub use error::{InterfaceError, InterfaceResult};
pub use hsm::{
    HSM, HsmEncryptionOracle, HsmKeyAlgorithm, HsmKeypairAlgorithm, HsmObject, HsmObjectFilter,
    HsmStore, KeyMaterial, RsaPrivateKeyMaterial, RsaPublicKeyMaterial,
};
pub use stores::{
    AtomicOperation, ObjectWithMetadata, ObjectsStore, PermissionsStore, SessionParams,
};

/// Supported cryptographic object types
/// in plugins
#[derive(Debug, Eq, PartialEq)]
pub enum KeyType {
    AesKey,
    RsaPrivateKey,
    RsaPublicKey,
}

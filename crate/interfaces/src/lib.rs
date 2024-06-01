mod encryption_oracle;
mod error;
mod hsm;

pub use encryption_oracle::{
    CryptographicAlgorithm, EncryptedContent, EncryptionOracle, KeyMetadata,
};
pub use error::{InterfaceError, InterfaceResult};
pub use hsm::{
    HsmEncryptionOracle, HsmKeyAlgorithm, HsmKeypairAlgorithm, HsmObject, HsmObjectFilter,
    KeyMaterial, RsaPrivateKeyMaterial, RsaPublicKeyMaterial, HSM,
};

/// Supported cryptographic object types
/// in plugins
#[derive(Debug, Eq, PartialEq)]
pub enum KeyType {
    AesKey,
    RsaPrivateKey,
    RsaPublicKey,
}

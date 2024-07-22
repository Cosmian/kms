mod encrypt_decrypt;
mod health_status;
mod key_metadata;

pub use encrypt_decrypt::{decrypt, encrypt};
pub use health_status::get_health_status;
pub use key_metadata::get_key_metadata;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum EncrytionAlgorithm {
    AES_GCM,
}

/// Ciphertext Data Integrity Value Algorithm
#[derive(Debug, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum CdivAlgorithm {
    SHA_256,
}

mod algorithm;
mod models;

pub(crate) mod decrypt;
pub(crate) mod encrypt;
pub(crate) mod error;
pub(crate) mod mac;
pub(crate) mod sign;
pub(crate) mod verify;

// Re-export handlers under names that callers (start_kms_server, test_utils) can use
// directly without the double-path (crypto::encrypt::encrypt).
pub(crate) use decrypt::decrypt as decrypt_handler;
pub(crate) use encrypt::encrypt as encrypt_handler;
pub(crate) use mac::mac as mac_handler;
pub(crate) use sign::sign as sign_handler;
pub(crate) use verify::verify as verify_handler;

// Re-export shared types used by handlers and algorithm module
pub(crate) use algorithm::jose_to_kmip_params;
pub(crate) use error::{CryptoApiError, CryptoResult, b64_decode, b64_encode};
pub(crate) use models::*;

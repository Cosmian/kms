use base58::ToBase58;
#[cfg(feature = "openssl")]
use openssl::hash::{hash, MessageDigest};
#[cfg(not(feature = "openssl"))]
use sha3::Digest;

use crate::error::KmipError;

/// Generate a unique ID from a byte slice.
///
/// Uses SHA3-256 hash function and base58 encoding
/// which generates file system friendly IDs.
/// # Arguments
/// * `bytes` - A byte slice
/// # Example
/// ```
/// use cosmian_kmip::id;
/// let id = id(b"Hello World!").unwrap();
/// assert_eq!(id, "F4RrBrbeAHQhQQCdoBNUJwSyk3iRr4eRsdULicFwer3p");
/// ```
pub fn id(bytes: &[u8]) -> Result<String, KmipError> {
    #[cfg(feature = "openssl")]
    let digest = hash(MessageDigest::sha3_256(), bytes)?.to_vec();
    #[cfg(not(feature = "openssl"))]
    let digest = sha3::Sha3_256::digest(bytes).to_vec();
    Ok(digest.to_base58())
}

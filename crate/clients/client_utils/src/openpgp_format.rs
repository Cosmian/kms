//! Pure `OpenPGP`< transferable-key format conversion (armored ⇄ binary packets).
//!
//! Contains no RNG and no OpenSSL dependency, so it builds for
//! `wasm32-unknown-unknown` as well as native targets. Shared by
//! `cosmian_kms_crypto` (native server/CLI) and the WASM export path in
//! `export_utils::openpgp_key_to_binary`, so there is a single
//! implementation of this conversion for every client.

use pgp::{
    composed::{PublicOrSecret, SignedPublicKey, SignedSecretKey},
    ser::Serialize,
};
use thiserror::Error;
use zeroize::Zeroizing;

/// Errors raised while converting `OpenPGP` transferable keys.
#[derive(Debug, Error)]
pub enum OpenPgpFormatError {
    #[error("failed to parse OpenPGP certificate: {0}")]
    Parse(String),
    #[error("failed to parse OpenPGP certificate: no key found")]
    NoKeyFound,
    #[error("OpenPGP input contains multiple transferable keys")]
    MultipleKeys,
    #[error("failed to serialize OpenPGP secret key: {0}")]
    SerializeSecret(String),
    #[error("failed to serialize OpenPGP public key: {0}")]
    SerializePublic(String),
    #[error("failed to parse OpenPGP transferable key")]
    NotAKey,
}

/// Parse an armored or binary key into either a `SignedSecretKey` or `SignedPublicKey`.
///
/// # Errors
/// Returns an error if the input is not a single valid `OpenPGP` transferable key.
pub fn parse_secret_or_public(
    input: &[u8],
) -> Result<(Option<SignedSecretKey>, Option<SignedPublicKey>), OpenPgpFormatError> {
    let (mut keys, _) = PublicOrSecret::from_reader_many_buf(std::io::Cursor::new(input))
        .map_err(|e| OpenPgpFormatError::Parse(e.to_string()))?;
    let key = keys
        .next()
        .ok_or(OpenPgpFormatError::NoKeyFound)?
        .map_err(|e| OpenPgpFormatError::Parse(e.to_string()))?;
    if keys.next().is_some() {
        return Err(OpenPgpFormatError::MultipleKeys);
    }
    match key {
        PublicOrSecret::Secret(secret) => Ok((Some(secret), None)),
        PublicOrSecret::Public(public) => Ok((None, Some(public))),
    }
}

/// Serialize an armored or binary `OpenPGP` transferable key as binary packets.
///
/// # Errors
/// Returns an error if the input is not a valid transferable secret or public key
/// or if the key cannot be serialized.
pub fn openpgp_key_to_binary(input: &[u8]) -> Result<Zeroizing<Vec<u8>>, OpenPgpFormatError> {
    let (secret, public) = parse_secret_or_public(input)?;
    let mut binary = Zeroizing::new(Vec::new());
    match (secret, public) {
        (Some(key), None) => key
            .to_writer(&mut *binary)
            .map_err(|e| OpenPgpFormatError::SerializeSecret(e.to_string()))?,
        (None, Some(key)) => key
            .to_writer(&mut *binary)
            .map_err(|e| OpenPgpFormatError::SerializePublic(e.to_string()))?,
        _ => return Err(OpenPgpFormatError::NotAKey),
    }
    Ok(binary)
}

use clap::{Parser, Subcommand};
use cosmian_kms_client::KmsClient;
use cosmian_kms_crypto::crypto::fpe::AlphabetPreset;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

use crate::{actions::console::Stdout, error::result::KmsCliResult};

/// Lazily-computed help text for alphabet presets.
/// Computed only once at runtime to avoid adding `strum` to the crypto crate. The Alphabet is defined by `AlphabetPreset` on the server.
fn alphabet_help() -> &'static str {
    static HELP: OnceLock<String> = OnceLock::new();
    HELP.get_or_init(|| {
        format!(
            "Alphabet preset name or custom character string. \
             Available presets: {}. \
             You may also provide a custom alphabet as a raw character string \
             (e.g. \"0123456789ABCDEF\").",
            AlphabetPreset::PRESET_NAMES.join(", ")
        )
    })
}

/// Tokenize strings using AES-256 FF1 Format-Preserving Encryption (FPE).
///
/// FPE encrypts a string while preserving its length and the character set of
/// the alphabet. The encryption key must be a 32-byte AES-256 symmetric key
/// already stored in the KMS.
///
/// Alphabet presets and custom character strings are supported.
/// See the `--help` output for the encrypt/decrypt subcommands for details.
///
/// Only available in non-FIPS builds.
#[derive(Subcommand, Debug)]
pub enum TokenizeCommands {
    /// Encrypt a string using AES-256 FF1 FPE.
    Encrypt(TokenizeEncryptAction),
    /// Decrypt a string using AES-256 FF1 FPE.
    Decrypt(TokenizeDecryptAction),
}

impl TokenizeCommands {
    /// Process the subcommand.
    ///
    /// # Errors
    ///
    /// Returns an error if the server request fails or the response is invalid.
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Encrypt(action) => action.run(kms_rest_client).await,
            Self::Decrypt(action) => action.run(kms_rest_client).await,
        }
    }
}

// ── Request / Response types (mirror crate/server/src/routes/tokenize.rs) ───

#[derive(Debug, Serialize)]
struct EncryptRequest<'a> {
    key_id: &'a str,
    plaintext: &'a str,
    alphabet: &'a str,
    tweak: &'a str,
}

#[derive(Debug, Deserialize, Serialize)]
struct EncryptResponse {
    ciphertext: String,
}

#[derive(Debug, Serialize)]
struct DecryptRequest<'a> {
    key_id: &'a str,
    ciphertext: &'a str,
    alphabet: &'a str,
    tweak: &'a str,
}

#[derive(Debug, Deserialize, Serialize)]
struct DecryptResponse {
    plaintext: String,
}

// ── Encrypt action ────────────────────────────────────────────────────────────

/// Encrypt a string using AES-256 FF1 Format-Preserving Encryption.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct TokenizeEncryptAction {
    /// KMIP Unique Identifier of the 32-byte AES-256 symmetric key.
    #[clap(long = "key-id", short = 'k')]
    pub key_id: String,

    /// The plaintext to encrypt.
    #[clap(long = "plaintext", short = 'p')]
    pub plaintext: String,

    #[clap(long = "alphabet", short = 'a', default_value = "alpha_numeric", help = alphabet_help())]
    pub alphabet: String,

    /// Tweak string (domain-specific context, not secret).
    #[clap(long = "tweak", short = 't', default_value = "")]
    pub tweak: String,
}

impl TokenizeEncryptAction {
    /// Run the encrypt action.
    ///
    /// # Errors
    ///
    /// Returns an error if the server request fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let req = EncryptRequest {
            key_id: &self.key_id,
            plaintext: &self.plaintext,
            alphabet: &self.alphabet,
            tweak: &self.tweak,
        };

        let resp: EncryptResponse = kms_rest_client
            .post_no_ttlv("/tokenize/encrypt", Some(&req))
            .await?;

        Stdout::new(&resp.ciphertext).write()?;
        Ok(())
    }
}

// ── Decrypt action ────────────────────────────────────────────────────────────

/// Decrypt a string using AES-256 FF1 Format-Preserving Encryption.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct TokenizeDecryptAction {
    /// KMIP Unique Identifier of the 32-byte AES-256 symmetric key.
    #[clap(long = "key-id", short = 'k')]
    pub key_id: String,

    /// The ciphertext to decrypt.
    #[clap(long = "ciphertext", short = 'c')]
    pub ciphertext: String,

    #[clap(long = "alphabet", short = 'a', default_value = "alpha_numeric", help = alphabet_help())]
    pub alphabet: String,

    /// Tweak string (must match the value used during encryption).
    #[clap(long = "tweak", short = 't', default_value = "")]
    pub tweak: String,
}

impl TokenizeDecryptAction {
    /// Run the decrypt action.
    ///
    /// # Errors
    ///
    /// Returns an error if the server request fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let req = DecryptRequest {
            key_id: &self.key_id,
            ciphertext: &self.ciphertext,
            alphabet: &self.alphabet,
            tweak: &self.tweak,
        };

        let resp: DecryptResponse = kms_rest_client
            .post_no_ttlv("/tokenize/decrypt", Some(&req))
            .await?;

        Stdout::new(&resp.plaintext).write()?;
        Ok(())
    }
}

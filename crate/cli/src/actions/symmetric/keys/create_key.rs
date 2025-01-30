use std::fmt::Display;

use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, ValueEnum};
use cosmian_kms_client::{
    cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm,
    kmip_2_1::{
        kmip_types::UniqueIdentifier,
        requests::{
            create_symmetric_key_kmip_object, import_object_request, symmetric_key_create_request,
        },
    },
    KmsClient,
};

use crate::{
    actions::console,
    cli_bail,
    error::result::{CliResult, CliResultHelper},
};

#[derive(ValueEnum, Debug, Clone, Copy, Default)]
pub enum SymmetricAlgorithm {
    #[cfg(not(feature = "fips"))]
    Chacha20,
    #[default]
    Aes,
    Sha3,
    Shake,
}

impl Display for SymmetricAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(not(feature = "fips"))]
            Self::Chacha20 => write!(f, "chacha20"),
            Self::Aes => write!(f, "aes"),
            Self::Sha3 => write!(f, "sha3"),
            Self::Shake => write!(f, "shake"),
        }
    }
}

/// Create a new symmetric key
///
/// When the `--bytes-b64` option is specified, the key will be created from the provided bytes;
/// otherwise, the key will be randomly generated with a length of `--number-of-bits`.
///
/// If no options are specified, a fresh 256-bit AES key will be created.
///
/// Tags can later be used to retrieve the key. Tags are optional.
#[derive(Parser, Default)]
#[clap(verbatim_doc_comment)]
pub struct CreateKeyAction {
    /// The length of the generated random key or salt in bits.
    #[clap(
        long = "number-of-bits",
        short = 'l',
        group = "key",
        default_value = "256"
    )]
    pub number_of_bits: Option<usize>,

    /// The symmetric key bytes or salt as a base 64 string
    #[clap(long = "bytes-b64", short = 'k', required = false, group = "key")]
    pub wrap_key_b64: Option<String>,

    /// The algorithm
    #[clap(
        long = "algorithm",
        short = 'a',
        required = false,
        default_value = "aes"
    )]
    pub algorithm: SymmetricAlgorithm,

    /// The tag to associate with the key.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    pub tags: Vec<String>,

    /// The unique id of the key; a random uuid
    /// is generated if not specified.
    #[clap(required = false)]
    pub key_id: Option<String>,

    /// Sensitive: if set, the key will not be exportable
    #[clap(long = "sensitive", default_value = "false")]
    pub sensitive: bool,

    /// The key to wrap this new key with.
    /// If the wrapping key is:
    /// -  a symmetric key, AES-GCM will be used
    /// -  a RSA key, RSA-OAEP will be used
    /// -  a EC key, ECIES will be used (salsa20poly1305 for X25519)
    #[clap(
        long = "wrapping-key-id",
        short = 'w',
        required = false,
        verbatim_doc_comment
    )]
    pub wrapping_key_id: Option<String>,
}

impl CreateKeyAction {
    /// Create a new symmetric key
    ///
    /// # Errors
    /// Fail in input key parsing fails
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<UniqueIdentifier> {
        let mut key_bytes = None;
        let number_of_bits = if let Some(key_b64) = &self.wrap_key_b64 {
            let bytes = general_purpose::STANDARD
                .decode(key_b64)
                .with_context(|| "failed decoding the wrap key")?;
            let number_of_bits = bytes.len() * 8;
            key_bytes = Some(bytes);
            number_of_bits
        } else {
            self.number_of_bits.unwrap_or(256)
        };

        let algorithm = match self.algorithm {
            SymmetricAlgorithm::Aes => CryptographicAlgorithm::AES,
            #[cfg(not(feature = "fips"))]
            SymmetricAlgorithm::Chacha20 => CryptographicAlgorithm::ChaCha20,
            SymmetricAlgorithm::Sha3 => match number_of_bits {
                224 => CryptographicAlgorithm::SHA3224,
                256 => CryptographicAlgorithm::SHA3256,
                384 => CryptographicAlgorithm::SHA3384,
                512 => CryptographicAlgorithm::SHA3512,
                _ => cli_bail!("invalid number of bits for sha3 {}", number_of_bits),
            },
            SymmetricAlgorithm::Shake => match number_of_bits {
                128 => CryptographicAlgorithm::SHAKE128,
                256 => CryptographicAlgorithm::SHAKE256,
                _ => cli_bail!("invalid number of bits for shake {}", number_of_bits),
            },
        };

        let unique_identifier = if let Some(key_bytes) = key_bytes {
            let mut object =
                create_symmetric_key_kmip_object(key_bytes.as_slice(), algorithm, self.sensitive)?;
            if let Some(wrapping_key_id) = &self.wrapping_key_id {
                let attributes = object.attributes_mut()?;
                attributes.set_wrapping_key_id(wrapping_key_id);
            }
            let import_object_request =
                import_object_request(self.key_id.clone(), object, None, false, false, &self.tags);
            kms_rest_client
                .import(import_object_request)
                .await
                .with_context(|| "failed importing the key")?
                .unique_identifier
        } else {
            let key_id = self
                .key_id
                .as_ref()
                .map(|id| UniqueIdentifier::TextString(id.clone()));
            let create_key_request = symmetric_key_create_request(
                key_id,
                number_of_bits,
                algorithm,
                &self.tags,
                self.sensitive,
                self.wrapping_key_id.as_ref(),
            )?;
            kms_rest_client
                .create(create_key_request)
                .await
                .with_context(|| "failed creating the key")?
                .unique_identifier
        };

        let mut stdout = console::Stdout::new("The symmetric key was successfully generated.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_unique_identifier(&unique_identifier);
        stdout.write()?;

        Ok(unique_identifier)
    }
}

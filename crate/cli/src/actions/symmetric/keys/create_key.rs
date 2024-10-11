use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, ValueEnum};
use cosmian_kms_client::{
    cosmian_kmip::{
        crypto::symmetric::{create_symmetric_key_kmip_object, symmetric_key_create_request},
        kmip::kmip_types::CryptographicAlgorithm,
    },
    import_object,
    kmip::kmip_types::UniqueIdentifier,
    KmsClient,
};

use crate::{
    actions::console,
    cli_bail,
    error::result::{CliResult, CliResultHelper},
};

#[derive(ValueEnum, Debug, Clone, Copy)]
pub(crate) enum SymmetricAlgorithm {
    #[cfg(not(feature = "fips"))]
    Chacha20,
    Aes,
    Sha3,
    Shake,
}

/// Create a new symmetric key
///
/// When the `--bytes-b64` option is specified, the key will be created from the provided bytes;
/// otherwise, the key will be randomly generated with a length of `--number-of-bits`.
///
/// If no options are specified, a fresh 256-bit AES key will be created.
///
/// Tags can later be used to retrieve the key. Tags are optional.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateKeyAction {
    /// The length of the generated random key or salt in bits.
    #[clap(
        long = "number-of-bits",
        short = 'l',
        group = "key",
        default_value = "256"
    )]
    number_of_bits: Option<usize>,

    /// The symmetric key bytes or salt as a base 64 string
    #[clap(long = "bytes-b64", short = 'k', required = false, group = "key")]
    wrap_key_b64: Option<String>,

    /// The algorithm
    #[clap(
        long = "algorithm",
        short = 'a',
        required = false,
        default_value = "aes"
    )]
    algorithm: SymmetricAlgorithm,

    /// The tag to associate with the key.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,

    /// The unique id of the key; a random uuid
    /// is generated if not specified.
    #[clap(required = false)]
    key_id: Option<String>,
}

impl CreateKeyAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
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
            let object = create_symmetric_key_kmip_object(key_bytes.as_slice(), algorithm)?;
            import_object(
                kms_rest_client,
                self.key_id.clone(),
                object,
                None,
                false,
                false,
                &self.tags,
            )
            .await?
        } else {
            let key_id = self
                .key_id
                .as_ref()
                .map(|id| UniqueIdentifier::TextString(id.clone()));
            let create_key_request =
                symmetric_key_create_request(key_id, number_of_bits, algorithm, &self.tags)?;
            kms_rest_client
                .create(create_key_request)
                .await
                .with_context(|| "failed creating the key")?
                .unique_identifier
                .to_string()
        };

        let mut stdout = console::Stdout::new("The symmetric key was successfully generated.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_unique_identifier(unique_identifier);
        stdout.write()?;

        Ok(())
    }
}

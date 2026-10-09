use clap::{Parser, ValueEnum};
use cosmian_kmip::kmip_2_1::{
    kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
    requests::pgp_key_create_request,
};
use cosmian_kms_client::KmsClient;

use crate::{
    actions::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// `OpenPGP` key algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum PgpAlgorithm {
    /// Ed25519 primary key (certify/sign) + Curve25519 ECDH subkey (encrypt)
    #[default]
    Ed25519,
    /// RSA primary key (certify/sign) + RSA subkey (encrypt)
    Rsa,
}

/// Create a new `OpenPGP` key (v4 transferable secret key)
///
/// The key is generated unprotected: the KMS is the protection boundary, and
/// passphrase-protected `OpenPGP` keys cannot be used for Decrypt or Sign.
#[derive(Parser, Default)]
#[clap(verbatim_doc_comment)]
pub struct CreatePgpKeyAction {
    /// The `OpenPGP` key algorithm
    #[clap(long = "algorithm", short = 'a', default_value = "ed25519")]
    pub algorithm: PgpAlgorithm,

    /// RSA modulus size in bits: 2048, 3072 or 4096.
    /// Ignored unless `--algorithm rsa`.
    #[clap(long = "size_in_bits", short = 's', default_value = "3072")]
    pub key_size: usize,

    /// The `OpenPGP` User ID packet, e.g. "Alice <alice@example.com>"
    #[clap(long = "user-id", short = 'u')]
    pub user_id: Option<String>,

    /// The tag to associate with the key. Repeat for multiple tags.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    pub tags: Vec<String>,

    /// The unique id of the key; a random uuid is generated if not specified.
    #[clap(required = false)]
    pub key_id: Option<String>,

    /// Sensitive: if set, the key will not be exportable
    #[clap(long, default_value = "false")]
    pub sensitive: bool,

    /// The key encryption key (KEK) used to wrap this new key with.
    /// Note: a wrapped `OpenPGP` key cannot be unwrapped on export.
    #[clap(long, short = 'w', required = false)]
    pub wrapping_key_id: Option<String>,
}

impl CreatePgpKeyAction {
    /// Create a new `OpenPGP` key.
    ///
    /// # Errors
    ///
    /// Returns an error if the request building or KMS creation fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let (algorithm, cryptographic_length) = match self.algorithm {
            PgpAlgorithm::Ed25519 => (CryptographicAlgorithm::Ed25519, None),
            PgpAlgorithm::Rsa => (
                CryptographicAlgorithm::RSA,
                Some(i32::try_from(self.key_size)?),
            ),
        };

        let key_id = self
            .key_id
            .as_ref()
            .map(|id| UniqueIdentifier::TextString(id.clone()));
        let vendor_id = kms_rest_client.config.vendor_id.as_str();

        let create_request = pgp_key_create_request(
            vendor_id,
            key_id,
            algorithm,
            cryptographic_length,
            self.user_id.as_deref(),
            &self.tags,
            self.sensitive,
            self.wrapping_key_id.as_ref(),
        )?;

        let response = kms_rest_client
            .create(create_request)
            .await
            .with_context(|| "failed creating the OpenPGP key")?;

        let unique_identifier = response.unique_identifier;

        let mut stdout = console::Stdout::new("The OpenPGP key was successfully generated.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_unique_identifier(&unique_identifier);
        stdout.write()?;

        Ok(unique_identifier)
    }
}

use std::path::PathBuf;

use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use cloudproof::reexport::crypto_core::CsRng;
use cosmian_kmip::kmip::kmip_types::CryptographicAlgorithm;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::{
    password_derivation::{derive_key, KMS_ARGON2_SALT},
    symmetric::create_symmetric_key,
    wrap::wrap_key_block,
};
use rand::SeedableRng;

use crate::{
    actions::shared::utils::{export_object, read_key_from_file, write_kmip_object_to_file},
    cli_bail,
    error::{result::CliResultHelper, CliError},
};

/// Locally wrap a key in KMIP JSON TTLV format.
///
/// The key can be wrapped using either:
///  - a password derived into a symmetric key using Argon2
///  - symmetric key bytes in base64
///  - a key in the KMS (which will be exported first)
///  - a key in a KMIP JSON TTLV file
///
/// For the latter 2 cases, the key may be a symmetric key
/// and RFC 5649 will be used or a curve 25519 public key
/// and ECIES will be used.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct WrapKeyAction {
    /// The KMIP JSON TTLV input key file to wrap
    #[clap(required = true)]
    key_file_in: PathBuf,

    /// The KMIP JSON output file. When not specified the input file is overwritten.
    #[clap(required = false)]
    key_file_out: Option<PathBuf>,

    /// A password to wrap the imported key.
    #[clap(long = "wrap-password", short = 'p', required = false, group = "wrap")]
    wrap_password: Option<String>,

    /// A symmetric key as a base 64 string to wrap the imported key.
    #[clap(long = "wrap-key-b64", short = 'k', required = false, group = "wrap")]
    wrap_key_b64: Option<String>,

    /// The id of a wrapping key in the KMS that will be exported and used to wrap the key.
    #[clap(long = "wrap-key-id", short = 'i', required = false, group = "wrap")]
    wrap_key_id: Option<String>,

    /// A wrapping key in a KMIP JSON TTLV file used to wrap the key.
    #[clap(long = "wrap-key-file", short = 'f', required = false, group = "wrap")]
    wrap_key_file: Option<PathBuf>,
}

impl WrapKeyAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        // read the key file
        let mut object = read_key_from_file(&self.key_file_in)?;

        // cannot wrap an already wrapped key
        if object.key_wrapping_data().is_some() {
            cli_bail!("cannot wrap an already wrapped key");
        }

        // cache the object type
        let object_type = object.object_type();

        // if the key must be wrapped, prepare the wrapping key
        let wrapping_key = if let Some(b64) = &self.wrap_key_b64 {
            let key_bytes = general_purpose::STANDARD
                .decode(b64)
                .with_context(|| "failed decoding the wrap key")?;
            create_symmetric_key(&key_bytes, CryptographicAlgorithm::AES, None)
        } else if let Some(password) = &self.wrap_password {
            let key_bytes = derive_key(password.as_bytes(), KMS_ARGON2_SALT)?.to_vec();
            println!("wrap derived key {}", hex::encode(&key_bytes));
            create_symmetric_key(&key_bytes, CryptographicAlgorithm::AES, None)
        } else if let Some(key_id) = &self.wrap_key_id {
            export_object(client_connector, key_id, false, &None, false).await?
        } else if let Some(key_file) = &self.wrap_key_file {
            read_key_from_file(key_file)?
        } else {
            cli_bail!("one of the wrapping options must be specified");
        };

        let mut rng = CsRng::from_entropy();
        wrap_key_block(&mut rng, object.key_block_mut()?, &wrapping_key, None)?;

        // set the output file path to the input file path if not specified
        let output_file = self
            .key_file_out
            .as_ref()
            .unwrap_or(&self.key_file_in)
            .to_path_buf();

        write_kmip_object_to_file(&object, &output_file)?;

        println!(
            "The key of type {:?} in file {:?} was wrapped in file: {:?}",
            object_type, self.key_file_in, &output_file
        );

        Ok(())
    }
}

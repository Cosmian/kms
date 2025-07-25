use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose};
use clap::Parser;
use cosmian_kms_client::{
    ExportObjectParams, KmsClient,
    cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm,
    export_object,
    kmip_2_1::{kmip_attributes::Attributes, requests::create_symmetric_key_kmip_object},
    read_object_from_json_ttlv_file, write_kmip_object_to_file,
};
use cosmian_kms_crypto::crypto::wrap::unwrap_key_block;
use tracing::trace;

use crate::{
    actions::kms::console,
    cli_bail,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Locally unwrap a secret data or key in KMIP JSON TTLV format.
///
/// The secret data or key can be unwrapped using either:
///  - a password derived into a symmetric key using Argon2
///  - symmetric key bytes in base64
///  - a key in the KMS (which will be exported first)
///  - a key in a KMIP JSON TTLV file
///
/// For the latter 2 cases, the key may be a symmetric key,
/// and RFC 5649 will be used, or a curve 25519 private key
/// and ECIES will be used.
#[derive(Parser, Default, Debug)]
#[clap(verbatim_doc_comment)]
pub struct UnwrapSecretDataOrKeyAction {
    /// The KMIP JSON TTLV input key file to unwrap
    #[clap(required = true)]
    pub(crate) key_file_in: PathBuf,

    /// The KMIP JSON output file. When not specified the input file is overwritten.
    #[clap(required = false)]
    pub(crate) key_file_out: Option<PathBuf>,

    /// A symmetric key as a base 64 string to unwrap the imported key.
    #[clap(
        long = "unwrap-key-b64",
        short = 'k',
        required = false,
        group = "unwrap"
    )]
    pub(crate) unwrap_key_b64: Option<String>,

    /// The id of an unwrapping key in the KMS that will be exported and used to unwrap the key.
    #[clap(
        long = "unwrap-key-id",
        short = 'i',
        required = false,
        group = "unwrap"
    )]
    pub(crate) unwrap_key_id: Option<String>,

    /// An unwrapping key in a KMIP JSON TTLV file used to unwrap the key.
    #[clap(
        long = "unwrap-key-file",
        short = 'f',
        required = false,
        group = "unwrap"
    )]
    pub(crate) unwrap_key_file: Option<PathBuf>,
}

impl UnwrapSecretDataOrKeyAction {
    /// Export a key from the KMS
    ///
    /// # Errors
    ///
    /// This function can return an error if:
    ///
    /// - The key file cannot be read.
    /// - The unwrap key fails to decode from base64.
    /// - The unwrapping key fails to be created.
    /// - The unwrapping key fails to unwrap the key.
    /// - The output file fails to be written.
    /// - The console output fails to be written.
    ///
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        // read the key file
        let mut object = read_object_from_json_ttlv_file(&self.key_file_in)?;

        // cache the object type
        let object_type = object.object_type();

        // if the key must be unwrapped, prepare the unwrapping key
        let unwrapping_key = if let Some(b64) = &self.unwrap_key_b64 {
            trace!("unwrap using a base64 encoded key: {b64}");
            let key_bytes = general_purpose::STANDARD
                .decode(b64)
                .with_context(|| "failed decoding the unwrap key")?;
            create_symmetric_key_kmip_object(
                &key_bytes,
                &Attributes {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    ..Default::default()
                },
            )?
        } else if let Some(key_id) = &self.unwrap_key_id {
            trace!("unwrap using the KMS server with the unique identifier of the unwrapping key");
            export_object(&kms_rest_client, key_id, ExportObjectParams::default())
                .await?
                .1
        } else if let Some(key_file) = &self.unwrap_key_file {
            trace!("unwrap using a key file path");
            read_object_from_json_ttlv_file(key_file)?
        } else {
            cli_bail!("one of the unwrapping options must be specified");
        };

        unwrap_key_block(object.key_block_mut()?, &unwrapping_key)?;

        // set the output file path to the input file path if not specified
        let output_file = self
            .key_file_out
            .as_ref()
            .unwrap_or(&self.key_file_in)
            .clone();

        write_kmip_object_to_file(&object, &output_file)?;

        let stdout = format!(
            "The key of type {:?} in file {} was unwrapped in file: {}",
            object_type,
            self.key_file_in.display(),
            &output_file.display()
        );
        console::Stdout::new(&stdout).write()?;

        Ok(())
    }
}

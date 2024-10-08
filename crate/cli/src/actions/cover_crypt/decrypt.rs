use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::{
        crypto::generic::kmip_requests::build_decryption_request,
        kmip::{kmip_operations::DecryptedData, kmip_types::CryptographicAlgorithm},
    },
    kmip::kmip_types::CryptographicParameters,
    read_bytes_from_file, read_bytes_from_files_to_bulk, write_bulk_decrypted_data,
    write_single_decrypted_data, KmsClient,
};

use crate::{
    cli_bail,
    error::result::{CliResult, CliResultHelper},
};

/// Decrypt a file using Covercrypt
///
/// Note: this is not a streaming call: the file is entirely loaded in memory before being sent for decryption.
#[derive(Parser, Debug)]
pub struct DecryptAction {
    /// The files to decrypt
    #[clap(required = true, name = "FILE")]
    input_files: Vec<PathBuf>,

    /// The user key unique identifier
    /// If not specified, tags should be specified
    #[clap(long = "key-id", short = 'k', group = "key-tags")]
    key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,

    /// The encrypted output file path
    #[clap(required = false, long, short = 'o')]
    output_file: Option<PathBuf>,

    /// Optional authentication data that was supplied during encryption.
    #[clap(required = false, long, short)]
    authentication_data: Option<String>,
}

impl DecryptAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        // Read the file(s) to decrypt
        let (cryptographic_algorithm, data) = if self.input_files.len() > 1 {
            (
                CryptographicAlgorithm::CoverCryptBulk,
                read_bytes_from_files_to_bulk(&self.input_files).with_context(|| {
                    "Cannot read bytes from encrypted files to LEB-serialize them"
                })?,
            )
        } else {
            (
                CryptographicAlgorithm::CoverCrypt,
                read_bytes_from_file(&self.input_files[0]).with_context(|| {
                    "Cannot read bytes from encrypted files to LEB-serialize them"
                })?,
            )
        };

        // Recover the unique identifier or set of tags
        let id = if let Some(key_id) = &self.key_id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either `--key-id` or one or more `--tag` must be specified")
        };

        // Create the kmip query
        let decrypt_request = build_decryption_request(
            &id,
            None,
            data,
            None,
            self.authentication_data
                .as_deref()
                .map(|s| s.as_bytes().to_vec()),
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(cryptographic_algorithm),
                ..Default::default()
            }),
        );

        tracing::debug!("{decrypt_request}");

        // Query the KMS with your kmip data and get the key pair ids
        let decrypt_response = kms_rest_client
            .decrypt(decrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        let metadata_and_cleartext: DecryptedData = decrypt_response
            .data
            .context("The plain data are empty")?
            .as_slice()
            .try_into()?;

        // Write the decrypted files
        if cryptographic_algorithm == CryptographicAlgorithm::CoverCryptBulk {
            write_bulk_decrypted_data(
                &metadata_and_cleartext.plaintext,
                &self.input_files,
                self.output_file.as_ref(),
            )?;
        } else {
            write_single_decrypted_data(
                &metadata_and_cleartext.plaintext,
                &self.input_files[0],
                self.output_file.as_ref(),
            )?;
        }
        Ok(())
    }
}

use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm,
    kmip_2_1::{kmip_types::CryptographicParameters, requests::decrypt_request},
    read_bytes_from_file, read_bytes_from_files_to_bulk, write_bulk_decrypted_data,
    write_single_decrypted_data, KmsClient,
};

use crate::{
    actions::{labels::KEY_ID, shared::get_key_uid},
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
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
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
        let id = get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;

        // Create the kmip query
        let decrypt_request = decrypt_request(
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

        let cleartext = decrypt_response.data.context("The plain data are empty")?;

        // Write the decrypted files
        if cryptographic_algorithm == CryptographicAlgorithm::CoverCryptBulk {
            write_bulk_decrypted_data(&cleartext, &self.input_files, self.output_file.as_ref())?;
        } else {
            write_single_decrypted_data(
                &cleartext,
                &self.input_files[0],
                self.output_file.as_ref(),
            )?;
        }
        Ok(())
    }
}

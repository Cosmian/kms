use std::{fs::File, io::prelude::*, path::PathBuf};

use clap::Parser;
use cosmian_kmip::kmip::kmip_types::CryptographicAlgorithm;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::generic::kmip_requests::build_encryption_request;

use crate::{
    actions::shared::utils::{read_bytes_from_file, read_bytes_from_files_to_bulk},
    cli_bail,
    error::{result::CliResultHelper, CliError},
};

/// Encrypt a file using AES GCM
///
/// The resulting bytes are the concatenation of
///   - the nonce (12 bytes)
///   - the encrypted data (same size as the plaintext)
///   - the authentication tag (16 bytes)
///
/// Note: this is not a streaming call: the file is entirely loaded in memory before being sent for encryption.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct EncryptAction {
    /// The files to encrypt
    #[clap(required = true, name = "FILE")]
    input_files: Vec<PathBuf>,

    /// The symmetric key unique identifier.
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

    /// Optional authentication data.
    /// This data needs to be provided back for decryption.
    #[clap(required = false, long, short = 'a')]
    authentication_data: Option<String>,
}

impl EncryptAction {
    pub async fn run(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        // Read the file(s) to encrypt
        let (cryptographic_algorithm, data) = if self.input_files.len() > 1 {
            (
                CryptographicAlgorithm::CoverCryptBulk,
                read_bytes_from_files_to_bulk(&self.input_files)
                    .with_context(|| "Cannot read bytes from files to LEB-serialize them")?,
            )
        } else {
            (
                CryptographicAlgorithm::CoverCrypt,
                read_bytes_from_file(&self.input_files[0])
                    .with_context(|| "Cannot read bytes from iles to LEB-serialize them")?,
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
        let encrypt_request = build_encryption_request(
            &id,
            None,
            data,
            None,
            self.authentication_data
                .as_deref()
                .map(|s| s.as_bytes().to_vec()),
            Some(cryptographic_algorithm),
        )?;

        // Query the KMS with your kmip data and get the key pair ids
        let encrypt_response = kms_rest_client
            .encrypt(encrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        let nonce = encrypt_response
            .iv_counter_nonce
            .context("the nonce is empty")?;
        let data = encrypt_response
            .data
            .context("The encrypted data are empty")?;
        let authentication_tag = encrypt_response
            .authenticated_encryption_tag
            .context("the authentication tag is empty")?;

        if cryptographic_algorithm == CryptographicAlgorithm::CoverCryptBulk {
            self.write_bulk_encrypted_data(&nonce, &data, &authentication_tag)
        } else {
            self.write_single_encrypted_data(&nonce, &data, &authentication_tag)
        }
    }

    fn write_single_encrypted_data(
        &self,
        nonce: &[u8],
        data: &[u8],
        authentication_tag: &[u8],
    ) -> Result<(), CliError> {
        // Write the encrypted file
        let output_file = self
            .output_file
            .clone()
            .unwrap_or_else(|| self.input_files[0].with_extension("enc"));
        let mut buffer =
            File::create(&output_file).with_context(|| "failed to write the encrypted file")?;

        // write the nonce
        buffer
            .write_all(nonce)
            .with_context(|| "failed to write the nonce")?;

        // write the ciphertext
        buffer
            .write_all(data)
            .context("failed to write the ciphertext")?;

        // write the authentication tag
        buffer
            .write_all(authentication_tag)
            .context("failed to write the authentication tag")?;

        println!("The encrypted file is available at {output_file:?}");
        Ok(())
    }

    fn write_bulk_encrypted_data(
        &self,
        nonce: &[u8],
        mut data: &[u8],
        authentication_tag: &[u8],
    ) -> Result<(), CliError> {
        // number of encrypted chunks
        let nb_chunks = leb128::read::unsigned(&mut data).map_err(|e| {
            CliError::Conversion(format!(
                "expected a LEB128 encoded number (number of encrypted chunks) at the beginning \
                 of the encrypted data: {e}"
            ))
        })? as usize;

        (0..nb_chunks).try_for_each(|idx| {
            let chunk_size = leb128::read::unsigned(&mut data)
                .map_err(|e| CliError::Conversion(format!("Cannot read the chunk size: {e}")))?
                as usize;

            #[allow(clippy::needless_borrow)]
            let chunk_data = (&mut data).take(..chunk_size).ok_or_else(|| {
                CliError::Conversion(
                    "Unable to get a valid slice from encrypted response buffer".to_string(),
                )
            })?;

            // Write the encrypted files
            // Reuse input file names if there are multiple inputs (and ignore `self.output_file`)
            let output_file = if nb_chunks == 1 {
                self.output_file
                    .clone()
                    .unwrap_or_else(|| self.input_files[idx].with_extension("enc"))
            } else if let Some(output_file) = &self.output_file {
                let file_name = self.input_files[idx].file_name().ok_or_else(|| {
                    CliError::Conversion(format!(
                        "cannot get file name from input file {:?}",
                        self.input_files[idx],
                    ))
                })?;
                output_file.join(PathBuf::from(file_name).with_extension("enc"))
            } else {
                self.input_files[idx].with_extension("enc")
            };

            let mut buffer =
                File::create(&output_file).with_context(|| "failed to write the encrypted file")?;

            // write the nonce
            buffer
                .write_all(nonce)
                .with_context(|| "failed to write the nonce")?;

            // write the ciphertext
            buffer
                .write_all(chunk_data)
                .context("failed to write the ciphertext")?;

            // write the authentication tag
            buffer
                .write_all(authentication_tag)
                .context("failed to write the authentication tag")?;

            println!("The encrypted file is available at {output_file:?}");
            Ok(())
        })
    }
}

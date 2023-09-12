use std::{fs::File, io::prelude::*, path::PathBuf};

use clap::Parser;
use cosmian_kmip::kmip::{kmip_operations::DecryptedData, kmip_types::CryptographicAlgorithm};
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::generic::kmip_requests::build_decryption_request;

use crate::{
    cli_bail,
    error::{result::CliResultHelper, CliError},
};

/// Decrypt a file using Covercrypt
///
/// Note: this is not a streaming call: the file is entirely loaded in memory before being sent for decryption.
#[derive(Parser, Debug)]
pub struct DecryptAction {
    /// The file to decrypt
    #[clap(required = true, name = "FILE")]
    input_files: Vec<PathBuf>,

    /// The user key unique identifier
    /// If not specified, tags should be specified
    #[clap(long = "key-id", short = 'k', group = "key-tags")]
    user_key_id: Option<String>,

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
    pub async fn run(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        let cryptographic_algorithm = if self.input_files.len() > 1 {
            Some(CryptographicAlgorithm::CoverCryptBulk)
        } else {
            Some(CryptographicAlgorithm::CoverCrypt)
        };

        let data = if let Some(CryptographicAlgorithm::CoverCryptBulk) = cryptographic_algorithm {
            self.prepare_data_bulk()?
        } else {
            let input_file = self.input_files.first().ok_or_else(|| {
                CliError::Conversion("Cannot get at least one input file to decrypt".to_string())
            })?;
            // Read the file to encrypt
            let mut f = File::open(input_file).with_context(|| "Can't read the file to decrypt")?;
            let mut data = Vec::new();
            f.read_to_end(&mut data)
                .with_context(|| "Fail to read the file to decrypt")?;
            data
        };

        // Recover the unique identifier or set of tags
        let id = if let Some(key_id) = &self.user_key_id {
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
            cryptographic_algorithm,
        );

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

        if let Some(CryptographicAlgorithm::CoverCryptBulk) = cryptographic_algorithm {
            self.write_bulk_decrypted_data(&metadata_and_cleartext)?;
        } else {
            // Write the decrypted file
            let output_file = if let Some(output_file) = &self.output_file {
                output_file.clone()
            } else {
                let input_file = self.input_files.first().ok_or_else(|| {
                    CliError::Conversion(
                        "Cannot get filename from at least first input file".to_string(),
                    )
                })?;
                input_file.with_extension("plain")
            };
            let mut buffer =
                File::create(&output_file).with_context(|| "Fail to write the plain file")?;
            buffer
                .write_all(&metadata_and_cleartext.plaintext)
                .with_context(|| "Fail to write the plain file")?;

            println!("The decrypted file is available at {:?}", &output_file);
        }

        Ok(())
    }

    /// Several files need to be decrypted.
    /// A custom protocol is used to serialize these data.
    ///
    /// Bulk encryption / decryption scheme
    ///
    /// ENC request
    /// | nb_chunks (LEB128) | chunk_size (LEB128) | chunk_data (plaintext)
    ///                        <------------- nb_chunks times ------------>
    ///
    /// ENC response
    /// | EH | nb_chunks (LEB128) | chunk_size (LEB128) | chunk_data (encrypted)
    ///                             <------------- nb_chunks times ------------>
    ///
    /// DEC request
    /// | nb_chunks (LEB128) | size(EH + chunk_data) (LEB128) | EH | chunk_data (encrypted)
    ///                                                         <----- chunk with EH ----->
    ///                        <---------------------- nb_chunks times ------------------->
    ///
    /// DEC response
    /// | nb_chunks (LEB128) | chunk_size (LEB128) | chunk_data (plaintext)
    ///                        <------------- nb_chunks times ------------>
    fn prepare_data_bulk(&self) -> Result<Vec<u8>, CliError> {
        let mut data = Vec::new();

        // number of files to decrypt
        leb128::write::unsigned(&mut data, self.input_files.len() as u64).map_err(|_| {
            CliError::Conversion("Cannot write the number of files to encrypt".to_string())
        })?;

        for input_file in &self.input_files {
            // Read the file to decrypt
            let mut f = File::open(input_file)
                .with_context(|| format!("Can't read the file to decrypt ({input_file:?})"))?;
            let mut content = Vec::new();
            f.read_to_end(&mut content)
                .with_context(|| "Fail to read the file to decrypt")?;

            leb128::write::unsigned(&mut data, content.len() as u64).map_err(|_| {
                CliError::Conversion("Cannot write the size of the chunk to encrypt".to_string())
            })?;
            data.append(&mut content);
        }

        Ok(data)
    }

    fn write_bulk_decrypted_data(
        &self,
        metadata_and_cleartext: &DecryptedData,
    ) -> Result<(), CliError> {
        let mut data_slice: &[u8] = metadata_and_cleartext.plaintext.as_ref();

        // number of decrypted chunks
        let nb_chunks = leb128::read::unsigned(&mut data_slice).map_err(|_| {
            CliError::Conversion(
                "expected a LEB128 encoded number (number of encrypted chunks) at the beginning \
                 of the encrypted data"
                    .to_string(),
            )
        })? as usize;

        for idx in 0..nb_chunks {
            let chunk_size = leb128::read::unsigned(&mut data_slice)
                .map_err(|_| CliError::Conversion("Cannot read the chunk size".to_string()))?
                as usize;

            #[allow(clippy::needless_borrow)]
            let chunk_data = (&mut data_slice).take(..chunk_size).ok_or_else(|| {
                CliError::Conversion(
                    "Unable to get a valid slice from decrypted response buffer".to_string(),
                )
            })?;

            // Write the decrypted files
            // Reuse input file names if there are multiple inputs (and ignore `self.output_file`)
            let output_file = if nb_chunks == 1 {
                self.output_file
                    .clone()
                    .unwrap_or_else(|| self.input_files[idx].with_extension("plain"))
            } else if let Some(output_file) = &self.output_file {
                let file_name = self.input_files[idx].file_name().ok_or_else(|| {
                    CliError::Conversion(format!(
                        "cannot get file name from input file {:?}",
                        self.input_files[idx],
                    ))
                })?;
                output_file.join(PathBuf::from(file_name).with_extension("plain"))
            } else {
                self.input_files[idx].with_extension("plain")
            };

            let mut buffer =
                File::create(&output_file).with_context(|| "failed to write the decrypted file")?;
            buffer
                .write_all(chunk_data)
                .with_context(|| "failed to write the decrypted file")?;

            println!("The decrypted file is available at {output_file:?}");
        }

        Ok(())
    }
}

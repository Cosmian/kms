use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use cloudproof::reexport::{
    cover_crypt::EncryptedHeader,
    crypto_core::bytes_ser_de::{Deserializer, Serializable},
};
use cosmian_kmip::kmip::kmip_types::CryptographicAlgorithm;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::generic::kmip_requests::build_encryption_request;

use crate::{
    actions::shared::utils::{
        read_bytes_from_file, read_bytes_from_files_to_bulk, write_single_encrypted_data,
    },
    cli_bail,
    error::{result::CliResultHelper, CliError},
};

/// Encrypt a file using Covercrypt
///
/// Note: this is not a streaming call: the file is entirely loaded in memory before being sent for encryption.
#[derive(Parser, Debug)]
pub struct EncryptAction {
    /// The files to encrypt
    #[clap(required = true, name = "FILE")]
    input_files: Vec<PathBuf>,

    /// The encryption policy to encrypt the file with
    /// Example: "department::marketing && level::confidential"`
    #[clap(required = true)]
    encryption_policy: String,

    /// The public key unique identifier.
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
        let cryptographic_algorithm = if self.input_files.len() > 1 {
            Some(CryptographicAlgorithm::CoverCryptBulk)
        } else {
            Some(CryptographicAlgorithm::CoverCrypt)
        };

        // Read the file(s) to encrypt
        let mut data = if let Some(CryptographicAlgorithm::CoverCryptBulk) = cryptographic_algorithm
        {
            read_bytes_from_files_to_bulk(&self.input_files)
                .with_context(|| "Cannot read bytes from files to LEB-serialize them")?
        } else {
            read_bytes_from_file(&self.input_files[0])
                .with_context(|| "Cannot read bytes from files to LEB-serialize them")?
        };

        // Recover the unique identifier or set of tags
        let id = if let Some(key_id) = &self.key_id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(tags)?
        } else {
            cli_bail!("Either `--key-id` or one or more `--tag` must be specified")
        };

        // Create the kmip query
        let encrypt_request = build_encryption_request(
            &id,
            Some(self.encryption_policy.to_string()),
            data,
            None,
            self.authentication_data
                .as_deref()
                .map(|s| s.as_bytes().to_vec()),
            cryptographic_algorithm,
        )?;

        // Query the KMS with your kmip data and get the key pair ids
        let encrypt_response = kms_rest_client
            .encrypt(encrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        data = encrypt_response
            .data
            .context("The encrypted data are empty")?;

        if let Some(CryptographicAlgorithm::CoverCryptBulk) = cryptographic_algorithm {
            self.write_bulk_encrypted_data(&data)
        } else {
            write_single_encrypted_data(&data, &self.input_files[0], self.output_file.as_ref())
        }
    }

    /// Write each chunk of encrypted data to its own file.
    ///
    /// Several files need to be encrypted.
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
    ///
    /// Each file begins with a copy of the encrypted header, this way
    /// any chunk serialized in a file is usable on its own.
    fn write_bulk_encrypted_data(&self, encrypted_data: &[u8]) -> Result<(), CliError> {
        // Read encrypted header
        let mut de = Deserializer::new(encrypted_data);
        let encrypted_header = EncryptedHeader::read(&mut de)
            .map_err(|_| {
                CliError::Conversion(
                    "Unable to recognize encrypted header structure from slice".to_string(),
                )
            })?
            .serialize()
            .map_err(|_| {
                CliError::Conversion(
                    "Unable to serialize encrypted header structure to bytes".to_string(),
                )
            })?;
        let encrypted_block = de.finalize();

        let mut data_slice: &[u8] = encrypted_block.as_ref();

        // number of encrypted chunks
        let nb_chunks = leb128::read::unsigned(&mut data_slice).map_err(|_| {
            CliError::Conversion(
                "expected a LEB128 encoded number (number of encrypted chunks) at the beginning \
                 of the encrypted data"
                    .to_string(),
            )
        })? as usize;

        (0..nb_chunks).try_for_each(|idx| {
            let chunk_size = leb128::read::unsigned(&mut data_slice)
                .map_err(|_| CliError::Conversion("Cannot read the chunk size".to_string()))?
                as usize;

            #[allow(clippy::needless_borrow)]
            let chunk_data = (&mut data_slice).take(..chunk_size).ok_or_else(|| {
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
                let file_name = &self.input_files[idx].file_name().ok_or_else(|| {
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

            buffer
                .write_all(&encrypted_header)
                .with_context(|| "failed to write the encrypted header to file")?;
            buffer
                .write_all(chunk_data)
                .with_context(|| "failed to write the encrypted data to file")?;

            println!("The encrypted file is available at {output_file:?}");
            Ok(())
        })
    }
}

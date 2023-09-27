use std::path::PathBuf;

use clap::Parser;
use cloudproof::reexport::crypto_core::bytes_ser_de::Deserializer;
use cosmian_kmip::kmip::kmip_types::CryptographicAlgorithm;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::generic::kmip_requests::build_encryption_request;

use crate::{
    actions::shared::utils::{
        read_bytes_from_file, read_bytes_from_files_to_bulk, write_bytes_to_file,
        write_single_encrypted_data,
    },
    cli_bail,
    error::{result::CliResultHelper, CliError},
};

/// Encrypt a file with the given public key using ECIES
///
/// Note: this is not a streaming call: the file is entirely loaded in memory before being sent for encryption.
#[derive(Parser, Debug)]
pub struct EncryptAction {
    /// The files to encrypt
    #[clap(required = true, name = "FILE")]
    input_files: Vec<PathBuf>,

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
        // Read the file(s) to encrypt
        let (cryptographic_algorithm, mut data) = if self.input_files.len() > 1 {
            (
                CryptographicAlgorithm::CoverCryptBulk,
                read_bytes_from_files_to_bulk(&self.input_files)
                    .with_context(|| "Cannot read bytes from files to LEB-serialize them")?,
            )
        } else {
            (
                CryptographicAlgorithm::CoverCrypt,
                read_bytes_from_file(&self.input_files[0])
                    .with_context(|| "Cannot read bytes from files to LEB-serialize them")?,
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

        data = encrypt_response
            .data
            .context("The encrypted data are empty")?;

        // Write the encrypted files
        if cryptographic_algorithm == CryptographicAlgorithm::CoverCryptBulk {
            self.write_bulk_encrypted_data(&data)?;
        } else {
            write_single_encrypted_data(&data, &self.input_files[0], self.output_file.as_ref())?;
        }

        Ok(())
    }

    /// Store multiple encrypted data on disk
    ///
    /// The input data is serialized using LEB128 (bulk mode).
    /// Each chunk of data is stored in its own file on disk.
    fn write_bulk_encrypted_data(&self, data: &[u8]) -> Result<(), CliError> {
        let mut de = Deserializer::new(data);

        // number of encrypted chunks
        let nb_chunks = {
            let len = de.read_leb128_u64()?;
            usize::try_from(len).map_err(|_| {
                CliError::Conversion(format!(
                    "size of vector is too big for architecture: {len} bytes",
                ))
            })?
        };

        (0..nb_chunks).try_for_each(|idx| {
            // get chunk of data from slice
            let chunk_data = de.read_vec_as_ref()?;

            // reuse input file names if there are multiple inputs (and ignore `self.output_file`)
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

            write_bytes_to_file(chunk_data, &output_file)
                .with_context(|| "failed to write the encrypted file")?;

            println!("The encrypted file is available at {output_file:?}");
            Ok(())
        })
    }
}

use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm,
    kmip_2_1::{kmip_types::CryptographicParameters, requests::encrypt_request},
    read_bytes_from_file, read_bytes_from_files_to_bulk, write_bulk_encrypted_data,
    write_single_encrypted_data,
};
use cosmian_logger::debug;

use crate::{
    actions::kms::{labels::KEY_ID, shared::get_key_uid},
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Encrypt a file using Covercrypt
///
/// Note: this is not a streaming call: the file is entirely loaded in memory before being sent for encryption.
#[derive(Parser, Debug)]
pub struct EncryptAction {
    /// The files to encrypt
    #[clap(required = true, name = "FILE")]
    pub(crate) input_files: Vec<PathBuf>,

    /// The encryption policy to encrypt the file with
    /// Example: "`department::marketing` && `level::confidential`"
    #[clap(required = true)]
    pub(crate) encryption_policy: String,

    /// The public key unique identifier.
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// The encrypted output file path
    #[clap(required = false, long, short = 'o')]
    pub(crate) output_file: Option<PathBuf>,

    /// Optional authentication data.
    /// This data needs to be provided back for decryption.
    #[clap(required = false, long, short = 'a')]
    pub(crate) authentication_data: Option<String>,
}

impl EncryptAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        // Read the file(s) to encrypt
        let (cryptographic_algorithm, mut data) = if self.input_files.len() > 1 {
            (
                CryptographicAlgorithm::CoverCryptBulk,
                read_bytes_from_files_to_bulk(&self.input_files)
                    .with_context(|| "Cannot read bytes from files to LEB-serialize them")?,
            )
        } else {
            let first_file = self.input_files.first().context("No input file provided")?;
            (
                CryptographicAlgorithm::CoverCrypt,
                read_bytes_from_file(first_file)
                    .with_context(|| "Cannot read bytes from files to LEB-serialize them")?,
            )
        };

        // Recover the unique identifier or set of tags
        let id = get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;

        // Create the kmip query
        let encrypt_request = encrypt_request(
            &id,
            Some(self.encryption_policy.clone()),
            data,
            None,
            self.authentication_data
                .as_deref()
                .map(|s| s.as_bytes().to_vec()),
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(cryptographic_algorithm),
                ..Default::default()
            }),
        )?;

        debug!("{encrypt_request}");

        // Query the KMS with your kmip data and get the key pair ids
        let encrypt_response = kms_rest_client
            .encrypt(encrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        data = encrypt_response
            .data
            .context("The encrypted data are empty")?;

        // Write the encrypted data
        if cryptographic_algorithm == CryptographicAlgorithm::CoverCryptBulk {
            write_bulk_encrypted_data(&data, &self.input_files, self.output_file.as_ref())?;
        } else {
            let first_file = self.input_files.first().context("No input file provided")?;
            write_single_encrypted_data(&data, first_file, self.output_file.as_ref())?;
        }
        Ok(())
    }
}

use std::{fs::File, io::prelude::*, path::PathBuf};

use clap::Parser;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::generic::kmip_requests::build_encryption_request;

use crate::error::{result::CliResultHelper, CliError};

/// Encrypt a file using Covercrypt
///
/// Note: this is not a streaming call: the file is entirely loaded in memory before being sent for encryption.
#[derive(Parser, Debug)]
pub struct EncryptAction {
    /// The file to encrypt
    #[clap(required = true, name = "FILE")]
    input_file: PathBuf,

    /// The identifier public key unique identifier stored in the KMS
    #[clap(required = true)]
    public_key_id: String,

    /// The encryption policy to encrypt the file with
    /// Example: "department::marketing && level::confidential"`
    #[clap(required = true)]
    encryption_policy: String,

    /// The encrypted output file path
    #[clap(required = false, long, short = 'o')]
    output_file: Option<PathBuf>,

    /// Optional authentication data.
    /// This data needs to be provided back for decryption.
    #[clap(required = false, long, short = 'a')]
    authentication_data: Option<String>,
}

impl EncryptAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        // Read the file to encrypt
        let mut f =
            File::open(&self.input_file).with_context(|| "Can't read the file to encrypt")?;
        let mut data = Vec::new();
        f.read_to_end(&mut data)
            .with_context(|| "Fail to read the file to encrypt")?;

        // Create the kmip query
        let encrypt_request = build_encryption_request(
            &self.public_key_id,
            Some(self.encryption_policy.to_string()),
            data,
            None,
            self.authentication_data
                .clone()
                .map(|s| s.as_bytes().to_vec()),
        )?;

        // Query the KMS with your kmip data and get the key pair ids
        let encrypt_response = client_connector
            .encrypt(encrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        data = encrypt_response
            .data
            .context("The encrypted data are empty")?;

        // Write the encrypted file
        let output_file = self
            .output_file
            .clone()
            .unwrap_or_else(|| self.input_file.with_extension("enc"));
        let mut buffer =
            File::create(&output_file).with_context(|| "failed to write the encrypted file")?;
        buffer
            .write_all(&data)
            .with_context(|| "failed to write the encrypted file")?;

        println!("The encrypted file is available at {:?}", &output_file);

        Ok(())
    }
}

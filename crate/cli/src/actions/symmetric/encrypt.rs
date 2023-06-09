use std::{fs::File, io::prelude::*, path::PathBuf};

use clap::Parser;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::generic::kmip_requests::build_encryption_request;

use crate::error::{result::CliResultHelper, CliError};

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
    /// The file to encrypt
    #[clap(required = true, name = "FILE")]
    input_file: PathBuf,

    /// The symmetric key unique identifier stored in the KMS
    #[clap(required = true)]
    key_id: String,

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
        let mut plaintext = Vec::new();
        f.read_to_end(&mut plaintext)
            .with_context(|| "Fail to read the file to encrypt")?;

        // Create the kmip query
        let encrypt_request = build_encryption_request(
            &self.key_id,
            None,
            plaintext,
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

        // Write the encrypted file
        let output_file = self
            .output_file
            .clone()
            .unwrap_or_else(|| self.input_file.with_extension("enc"));
        let mut buffer =
            File::create(&output_file).with_context(|| "failed to write the encrypted file")?;

        // extract the nonce and write it
        let nonce = encrypt_response
            .iv_counter_nonce
            .context("the nonce is empty")?;
        buffer
            .write_all(&nonce)
            .with_context(|| "failed to write the nonce")?;

        // extract the ciphertext and write it
        let data = encrypt_response
            .data
            .context("The encrypted data are empty")?;
        buffer
            .write_all(&data)
            .context("failed to write the ciphertext")?;

        // extract the authentication tag and write it
        let authentication_tag = encrypt_response
            .authenticated_encryption_tag
            .context("the authentication tag is empty")?;
        buffer
            .write_all(&authentication_tag)
            .context("failed to write the authentication tag")?;

        println!("The encrypted file is available at {:?}", &output_file);

        Ok(())
    }
}

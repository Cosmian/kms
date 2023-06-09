use std::{fs::File, io::prelude::*, path::PathBuf};

use clap::Parser;
use cosmian_kmip::kmip::kmip_operations::DecryptedData;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::generic::kmip_requests::build_decryption_request;

use crate::error::{result::CliResultHelper, CliError};

/// Decrypt a file using Covercrypt
///
/// Note: this is not a streaming call: the file is entirely loaded in memory before being sent for decryption.
#[derive(Parser, Debug)]
pub struct DecryptAction {
    /// The file to decrypt
    #[clap(required = true, name = "FILE")]
    input_file: PathBuf,

    /// The identifier of the user decryption key stored in the KMS
    #[clap(required = true)]
    user_key_id: String,

    /// The encrypted output file path
    #[clap(required = false, long, short = 'o')]
    output_file: Option<PathBuf>,

    /// Optional authentication data that was supplied during encryption.
    #[clap(required = false, long, short)]
    authentication_data: Option<String>,
}

impl DecryptAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        // Read the file to decrypt
        let mut f =
            File::open(&self.input_file).with_context(|| "Can't read the file to decrypt")?;
        let mut data = Vec::new();
        f.read_to_end(&mut data)
            .with_context(|| "Fail to read the file to decrypt")?;

        // Create the kmip query
        let decrypt_request = build_decryption_request(
            &self.user_key_id,
            None,
            data,
            None,
            self.authentication_data
                .clone()
                .map(|s| s.as_bytes().to_vec()),
        );

        // Query the KMS with your kmip data and get the key pair ids
        let decrypt_response = client_connector
            .decrypt(decrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        let metadata_and_cleartext: DecryptedData = decrypt_response
            .data
            .context("The plain data are empty")?
            .as_slice()
            .try_into()?;

        // Write the decrypted file
        let output_file = self
            .output_file
            .clone()
            .unwrap_or_else(|| self.input_file.clone().with_extension(".plain"));
        let mut buffer =
            File::create(&output_file).with_context(|| "Fail to write the plain file")?;
        buffer
            .write_all(&metadata_and_cleartext.plaintext)
            .with_context(|| "Fail to write the plain file")?;

        println!("The decrypted file is available at {:?}", &output_file);

        Ok(())
    }
}

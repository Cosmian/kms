use std::{fs::File, io::prelude::*, path::PathBuf};

use clap::Parser;
use cosmian_kmip::kmip::kmip_operations::{Decrypt, DecryptedData};
use cosmian_kms_client::KmsRestClient;

use crate::{
    actions::shared::utils::read_bytes_from_file,
    cli_bail,
    error::{result::CliResultHelper, CliError},
};

/// Decrypt a file using the private key of a certificate
///
/// Note: this is not a streaming call: the file is entirely loaded in memory before being sent for decryption.
#[derive(Parser, Debug)]
pub struct DecryptCertificateAction {
    /// The file to decrypt
    #[clap(required = true, name = "FILE")]
    input_file: PathBuf,

    /// The private key unique identifier related to certificate
    /// If not specified, tags should be specified
    #[clap(long = "key-id", short = 'k', group = "key-tags")]
    private_key_id: Option<String>,

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

impl DecryptCertificateAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        // Read the file to decrypt
        let ciphertext = read_bytes_from_file(&self.input_file)?;

        // Recover the unique identifier or set of tags
        let id = if let Some(key_id) = &self.private_key_id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --key-id or one or more --tag must be specified")
        };

        // Create the kmip query
        let decrypt_request = Decrypt {
            unique_identifier: Some(id.clone()),
            data: Some(ciphertext),
            authenticated_encryption_additional_data: self
                .authentication_data
                .clone()
                .map(|s| s.as_bytes().to_vec()),
            ..Decrypt::default()
        };

        // Query the KMS with your kmip data and retrieve the cleartext
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

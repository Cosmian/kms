use std::{fs::File, io::prelude::*, path::PathBuf};

use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::kmip::{kmip_operations::Encrypt, kmip_types::UniqueIdentifier},
    read_bytes_from_file, KmsClient,
};
use zeroize::Zeroizing;

use crate::{
    actions::console,
    cli_bail,
    error::result::{CliResult, CliResultHelper},
};

/// Encrypt a file using the certificate public key.
///
/// Note: this is not a streaming call: the file is entirely loaded in memory before being sent for encryption.
#[derive(Parser, Debug)]
pub struct EncryptCertificateAction {
    /// The file to encrypt
    #[clap(required = true, name = "FILE")]
    input_file: PathBuf,

    /// The certificate unique identifier.
    /// If not specified, tags should be specified
    #[clap(long = "certificate-id", short = 'c', group = "key-tags")]
    certificate_id: Option<String>,

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

impl EncryptCertificateAction {
    pub async fn run(&self, client_connector: &KmsClient) -> CliResult<()> {
        // Read the file to encrypt
        let data = Zeroizing::from(read_bytes_from_file(&self.input_file)?);

        // Recover the unique identifier or set of tags
        let id = if let Some(key_id) = &self.certificate_id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --certificate-id or one or more --tag must be specified")
        };

        let authentication_data = self
            .authentication_data
            .as_ref()
            .map(|auth_data| auth_data.as_bytes().to_vec());

        let encrypt_request = Encrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(id.clone())),
            data: Some(data),
            authenticated_encryption_additional_data: authentication_data,
            ..Encrypt::default()
        };

        // Query the KMS for encryption
        let encrypt_response = client_connector
            .encrypt(encrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        // Retrieve the ciphertext
        let ciphertext = encrypt_response
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
            .write_all(&ciphertext)
            .with_context(|| "failed to write the encrypted file")?;

        console::Stdout::new(&format!(
            "The encrypted file is available at {:?}",
            &output_file
        ))
        .write()?;

        Ok(())
    }
}

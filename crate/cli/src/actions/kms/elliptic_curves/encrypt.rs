use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use cosmian_kms_client::{KmsClient, kmip_2_1::requests::encrypt_request, read_bytes_from_file};

use crate::{
    actions::kms::{console, labels::KEY_ID, shared::get_key_uid},
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Encrypt a file with the given public key using ECIES
///
/// Note: this is not a streaming call: the file is entirely loaded in memory before being sent for encryption.
#[derive(Parser, Debug)]
pub struct EncryptAction {
    /// The file to encrypt
    #[clap(required = true, name = "FILE")]
    pub(crate) input_file: PathBuf,

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
}

impl EncryptAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        // Read the file to encrypt
        let mut data = read_bytes_from_file(&self.input_file)
            .with_context(|| "Cannot read bytes from the file to encrypt")?;

        // Recover the unique identifier or set of tags
        let id = get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;

        // Create the kmip query
        let encrypt_request = encrypt_request(&id, None, data, None, None, None)?;

        // Query the KMS with your kmip data and get the key pair ids
        let encrypt_response = kms_rest_client
            .encrypt(encrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        data = encrypt_response
            .data
            .context("The encrypted data is empty")?;

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

        let stdout = format!(
            "The encrypted file is available at {}",
            output_file.display()
        );
        console::Stdout::new(&stdout).write()?;

        Ok(())
    }
}

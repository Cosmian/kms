use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::crypto::generic::kmip_requests::build_decryption_request, read_bytes_from_file,
    KmsClient,
};

use crate::{
    actions::console,
    cli_bail,
    error::result::{CliResult, CliResultHelper},
};

/// Decrypts a file with the given private key using ECIES
///
/// Note: this is not a streaming call: the file is entirely loaded in memory before being sent for decryption.
#[derive(Parser, Debug)]
pub struct DecryptAction {
    /// The file to decrypt
    #[clap(required = true, name = "FILE")]
    input_file: PathBuf,

    /// The private key unique identifier
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

    /// Optional authentication data that was supplied during encryption.
    #[clap(required = false, long, short)]
    authentication_data: Option<String>,
}

impl DecryptAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        // Read the file to decrypt
        let data = read_bytes_from_file(&self.input_file)
            .with_context(|| "Cannot read bytes from the file to decrypt")?;

        // Recover the unique identifier or set of tags
        let id = if let Some(key_id) = &self.key_id {
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
            None,
        );

        // Query the KMS with your kmip data and get the key pair ids
        let decrypt_response = kms_rest_client
            .decrypt(decrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;
        let plaintext = decrypt_response
            .data
            .context("Decrypt with elliptic curve: the plaintext is empty")?;

        // Write the decrypted file
        let output_file = self
            .output_file
            .clone()
            .unwrap_or_else(|| self.input_file.clone().with_extension(".plain"));
        let mut buffer =
            File::create(&output_file).with_context(|| "Fail to write the plain file")?;
        buffer
            .write_all(&plaintext)
            .with_context(|| "Fail to write the plain file")?;

        let stdout = format!("The decrypted file is available at {output_file:?}");
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_tags(self.tags.as_ref());
        stdout.write()?;

        Ok(())
    }
}

use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use cosmian_kms_client::{KmsClient, kmip_2_1::requests::decrypt_request, read_bytes_from_file};

use crate::{
    actions::{console, labels::KEY_ID, shared::get_key_uid},
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Decapsulate a KEM ciphertext using a private key (ML-KEM or Hybrid KEM).
///
/// Reads the encapsulation from a file and outputs the shared secret.
#[derive(Parser, Debug)]
pub struct DecapsulateAction {
    /// The encapsulation file to decapsulate
    #[clap(required = true, name = "FILE")]
    pub(crate) input_file: PathBuf,

    /// The private key unique identifier.
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// The output file path for the shared secret
    #[clap(required = false, long, short = 'o')]
    pub(crate) output_file: Option<PathBuf>,
}

impl DecapsulateAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let encapsulation_bytes = read_bytes_from_file(&self.input_file)
            .with_context(|| "Cannot read bytes from the encapsulation file")?;

        let request = decrypt_request(
            &get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?,
            None,
            encapsulation_bytes,
            None,
            None,
            None,
        );

        let response = kms_rest_client
            .decrypt(request)
            .await
            .with_context(|| "ML-KEM decapsulation failed")?;

        let shared_secret = response.data.context("shared secret is empty")?;

        let output_file = self
            .output_file
            .clone()
            .unwrap_or_else(|| self.input_file.with_extension("key"));
        let mut buffer =
            File::create(&output_file).with_context(|| "failed to write the shared secret file")?;
        buffer
            .write_all(&shared_secret)
            .with_context(|| "failed to write the shared secret file")?;

        let stdout = format!(
            "The shared secret is available at {}",
            output_file.display()
        );
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_tags(self.tags.as_ref());
        stdout.write()?;

        Ok(())
    }
}

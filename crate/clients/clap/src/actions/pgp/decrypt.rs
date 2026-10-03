use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::{
    KmsClient, kmip_2_1::requests::decrypt_request, read_bytes_from_file, write_bytes_to_file,
};

use crate::{
    actions::labels::KEY_ID,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Decrypt an `OpenPGP` message
///
/// Both binary `OpenPGP` messages and ASCII-armored messages are supported as input.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct DecryptAction {
    /// The file to decrypt
    #[clap(required = true, name = "FILE")]
    pub(crate) input_file: PathBuf,

    /// The `OpenPGP` key unique identifier. If not specified, tags should be specified.
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified. Repeat for multiple tags.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// The decrypted output file path. Defaults to `<FILE>.plain`.
    #[clap(required = false, long, short = 'o')]
    pub(crate) output_file: Option<PathBuf>,
}

impl DecryptAction {
    /// Run the `OpenPGP` decryption action.
    ///
    /// # Errors
    ///
    /// Returns an error if reading input, KMS decryption, or writing output fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let ciphertext = read_bytes_from_file(&self.input_file)
            .with_context(|| "Cannot read bytes from the file to decrypt")?;

        let id =
            crate::actions::shared::get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;

        let request = decrypt_request(&id, None, ciphertext, None, None, None);

        let response = kms_rest_client
            .decrypt(request)
            .await
            .with_context(|| "Can't execute the decrypt query on the kms server")?;

        let plaintext = response
            .data
            .context("Decrypt with OpenPGP: plaintext is empty")?;

        let out = self
            .output_file
            .clone()
            .unwrap_or_else(|| self.input_file.with_extension("plain"));

        write_bytes_to_file(&plaintext, &out)?;

        Ok(())
    }
}

use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::{
    KmsClient, kmip_2_1::requests::encrypt_request, read_bytes_from_file, write_bytes_to_file,
};

use crate::{
    actions::labels::KEY_ID,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Encrypt a file to an `OpenPGP` key
///
/// The output is a binary `OpenPGP` message (PKESK + SEIPDv1/AES-256) that
/// `gpg --decrypt` reads directly.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct EncryptAction {
    /// The file to encrypt
    #[clap(required = true, name = "FILE")]
    pub(crate) input_file: PathBuf,

    /// The `OpenPGP` key unique identifier. If not specified, tags should be specified.
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified. Repeat for multiple tags.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// The encrypted output file path. Defaults to `<FILE>.gpg`.
    #[clap(required = false, long, short = 'o')]
    pub(crate) output_file: Option<PathBuf>,
}

impl EncryptAction {
    /// Run the `OpenPGP` encryption action.
    ///
    /// # Errors
    ///
    /// Returns an error if reading input, KMS encryption, or writing output fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let data = read_bytes_from_file(&self.input_file)
            .with_context(|| "Cannot read bytes from the file to encrypt")?;

        let id =
            crate::actions::shared::get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;

        let request = encrypt_request(&id, None, data, None, None, None)?;

        let response = kms_rest_client
            .encrypt(request)
            .await
            .with_context(|| "Can't execute the encrypt query on the kms server")?;

        let ciphertext = response
            .data
            .context("Encrypt with OpenPGP: ciphertext is empty")?;

        let out = self
            .output_file
            .clone()
            .unwrap_or_else(|| self.input_file.with_extension("gpg"));

        write_bytes_to_file(&ciphertext, &out)?;

        Ok(())
    }
}

use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{
    actions::{labels::KEY_ID, shared::sign::run_sign},
    error::result::KmsCliResult,
};

/// Sign data with an `OpenPGP` key
///
/// Produces a binary detached `OpenPGP` signature made with the primary key using SHA-256.
/// Note that pre-hashed (`--digested`) data and streaming are not supported for `OpenPGP` keys.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct SignAction {
    /// The file to sign
    #[clap(required = true, name = "FILE")]
    pub(crate) input_file: PathBuf,

    /// The `OpenPGP` key unique identifier
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// The signature output file path
    #[clap(required = false, long, short = 'o')]
    pub(crate) output_file: Option<PathBuf>,
}

impl SignAction {
    /// Run the `OpenPGP` signing action.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        run_sign(
            kms_rest_client,
            self.input_file.clone(),
            self.key_id.clone(),
            self.tags.clone(),
            self.output_file.clone(),
            None,  // cryptographic_parameters: OpenPGP sign ignores them
            false, // digested: rejected for OpenPGP keys
        )
        .await
    }
}

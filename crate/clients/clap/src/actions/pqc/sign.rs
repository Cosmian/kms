use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{
    actions::{labels::KEY_ID, shared::sign::run_sign},
    error::result::KmsCliResult,
};

/// Sign data using a PQC private key (ML-DSA-44/65/87 or SLH-DSA).
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct SignAction {
    /// The file to sign
    #[clap(required = true, name = "FILE")]
    pub(crate) input_file: PathBuf,

    /// The private key unique identifier.
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// The signature output file path
    #[clap(required = false, long, short = 'o')]
    pub(crate) output_file: Option<PathBuf>,
}

impl SignAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        run_sign(
            kms_rest_client,
            self.input_file.clone(),
            self.key_id.clone(),
            self.tags.clone(),
            self.output_file.clone(),
            None,
            false,
        )
        .await
    }
}

use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::{KmsClient, reexport::cosmian_kms_client_utils::create_utils::Curve};

use crate::{
    actions::kms::{labels::KEY_ID, shared::sign::run_sign},
    error::result::KmsCliResult,
};

/// Sign a file using elliptic curve digital signature algorithms (ECDSA)
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct SignAction {
    /// The elliptic curve
    #[clap(long, short = 'c', default_value = "nist-p256")]
    pub(crate) curve: Curve,

    /// The file to sign
    #[clap(required = true, name = "FILE")]
    pub(crate) input_file: PathBuf,

    /// The private key unique identifier
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

    /// Treat input as already-digested data (pre-hash)
    #[clap(long = "digested", action)]
    pub(crate) digested: bool,
}

impl SignAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        run_sign(
            kms_rest_client,
            self.input_file.clone(),
            self.key_id.clone(),
            self.tags.clone(),
            self.output_file.clone(),
            self.digested,
        )
        .await
    }
}

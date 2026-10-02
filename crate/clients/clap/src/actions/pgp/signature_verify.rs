use std::path::PathBuf;

use clap::Parser;
use cosmian_kmip::kmip_2_1::kmip_types::ValidityIndicator;
use cosmian_kms_client::KmsClient;

use crate::{actions::labels::KEY_ID, error::result::KmsCliResult};

/// Verify an `OpenPGP` detached signature for a given data file
///
/// Only detached signatures are supported. Both binary and ASCII-armored signature
/// files are accepted.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct SignatureVerifyAction {
    /// The data that was signed
    #[clap(required = true, name = "FILE")]
    pub(crate) data_file: PathBuf,

    /// The detached signature file (binary or ASCII-armored)
    #[clap(required = true, name = "SIGNATURE_FILE")]
    pub(crate) signature_file: PathBuf,

    /// The `OpenPGP` key unique identifier
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,
}

impl SignatureVerifyAction {
    /// Run the `OpenPGP` signature verification action.
    ///
    /// # Errors
    ///
    /// Returns an error if verification query execution fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<ValidityIndicator> {
        crate::actions::shared::signature_verify::run_signature_verify(
            kms_rest_client,
            &self.data_file,
            &self.signature_file,
            &self.key_id,
            &self.tags,
            None,
            false,
        )
        .await
    }
}

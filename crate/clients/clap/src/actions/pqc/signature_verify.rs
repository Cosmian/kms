use std::path::PathBuf;

use clap::Parser;
use cosmian_kmip::kmip_2_1::kmip_types::ValidityIndicator;
use cosmian_kms_client::KmsClient;

use crate::{actions::labels::KEY_ID, error::result::KmsCliResult};

/// Verify a PQC signature (ML-DSA or SLH-DSA) for a given data file.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct SignatureVerifyAction {
    /// The data that was signed
    #[clap(required = true, name = "FILE")]
    pub(crate) data_file: PathBuf,

    /// The signature file
    #[clap(required = true, name = "SIGNATURE_FILE")]
    pub(crate) signature_file: PathBuf,

    /// The public key unique identifier.
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,
}

impl SignatureVerifyAction {
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

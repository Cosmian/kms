use std::path::PathBuf;

use clap::Parser;
use cosmian_kmip::kmip_2_1::kmip_types::{CryptographicParameters, ValidityIndicator};
use cosmian_kms_client::KmsClient;

use crate::{
    actions::kms::{labels::KEY_ID, shared::CDigitalSignatureAlgorithmEC},
    error::result::KmsCliResult,
};

/// Verify an ECDSA signature for a given data file
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct SignatureVerifyAction {
    /// The data that was signed
    #[clap(required = true, name = "FILE")]
    pub(crate) data_file: PathBuf,

    /// The signature file
    #[clap(required = true, name = "FILE")]
    pub(crate) signature_file: PathBuf,

    /// The private key unique identifier
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// The signature algorithm
    #[clap(long, short = 's', default_value = "ecdsa-with-sha256")]
    pub(crate) signature_algorithm: CDigitalSignatureAlgorithmEC,

    /// Optional output file path
    #[clap(required = false, long, short = 'o')]
    pub(crate) output_file: Option<PathBuf>,

    /// Treat data input as already-digested (pre-hash)
    #[clap(long = "digested", action)]
    pub(crate) digested: bool,
}

impl SignatureVerifyAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<ValidityIndicator> {
        let cryptographic_parameters: Option<CryptographicParameters> =
            Some(self.signature_algorithm.to_cryptographic_parameters());

        crate::actions::kms::shared::signature_verify::run_signature_verify(
            kms_rest_client,
            &self.data_file,
            &self.signature_file,
            &self.key_id,
            &self.tags,
            cryptographic_parameters,
            self.digested,
        )
        .await
    }
}

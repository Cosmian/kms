use std::path::PathBuf;

use clap::Parser;
use cosmian_kmip::kmip_2_1::{kmip_types::ValidityIndicator, requests::signature_verify_request};
use cosmian_kms_client::{KmsClient, read_bytes_from_file};

use crate::{
    actions::kms::{
        console,
        labels::KEY_ID,
        shared::{CDigitalSignatureAlgorithmRSA, get_key_uid},
    },
    error::result::{KmsCliResult, KmsCliResultHelper},
};

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
    #[clap(long = "signature-algorithm", short = 's', default_value = "rsassapss")]
    pub(crate) signature_algorithm: CDigitalSignatureAlgorithmRSA,

    /// The encrypted output file path
    #[clap(required = false, long, short = 'o')]
    pub(crate) output_file: Option<PathBuf>,
}

impl SignatureVerifyAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<ValidityIndicator> {
        // Read the data that was signed
        let data = read_bytes_from_file(&self.data_file)
            .with_context(|| "Cannot read bytes from the signed data file")?;

        // Read the signature file
        let signature_data = read_bytes_from_file(&self.signature_file)
            .with_context(|| "Cannot read bytes from the signature file")?;

        // Recover the unique identifier or set of tags
        let id = get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;

        // Create the kmip query
        let verify_request = signature_verify_request(
            &id,
            Some(data),
            None,
            Some(signature_data),
            Some(self.signature_algorithm.to_cryptographic_parameters()),
        );

        // Query the KMS with your kmip data and get the key pair ids
        let response = kms_rest_client
            .signature_verify(verify_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;
        let validity_indicator = response
            .validity_indicator
            .context("Verify with RSA: the validity indicator is not set")?;

        let stdout = format!("Signature verification is {validity_indicator}");
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_tags(self.tags.as_ref());
        stdout.write()?;

        Ok(validity_indicator)
    }
}

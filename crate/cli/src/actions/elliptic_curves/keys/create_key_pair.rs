use clap::Parser;
use cosmian_kmip::kmip::kmip_types::RecommendedCurve;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::curve_25519::kmip_requests::ec_create_key_pair_request;

use crate::error::{result::CliResultHelper, CliError};

/// Create a new X25519 key pair
///
///  - The public is used to encrypt
///      and can be safely shared.
///  - The private key is used to decrypt
///      and must be kept secret.
///
/// Tags can later be used to retrieve the keys. Tags are optional.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateKeyPairAction {
    /// The tag to associate with the master key pair.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,
}

impl CreateKeyPairAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        let create_key_pair_request =
            ec_create_key_pair_request(&self.tags, RecommendedCurve::CURVE25519)?;

        // Query the KMS with your kmip data and get the key pair ids
        let create_key_pair_response = client_connector
            .create_key_pair(create_key_pair_request)
            .await
            .with_context(|| "failed creating a Elliptic Curve key pair")?;

        let private_key_unique_identifier = &create_key_pair_response.private_key_unique_identifier;
        let public_key_unique_identifier = &create_key_pair_response.public_key_unique_identifier;

        println!("The EC key pair has been created.");
        println!("  Private key unique identifier: {private_key_unique_identifier}\n");
        println!("  Public key unique identifier : {public_key_unique_identifier}");

        Ok(())
    }
}

use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::{
        crypto::elliptic_curves::kmip_requests::create_ec_key_pair_request,
        kmip::kmip_types::RecommendedCurve,
    },
    KmsRestClient,
};
use cosmian_kms_client::KmsClient;

use crate::error::{CliError, result::CliResultHelper};

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub enum Curve {
    #[cfg(not(feature = "fips"))]
    NistP192,
    NistP224,
    NistP256,
    NistP384,
    NistP521,
    #[cfg(not(feature = "fips"))]
    X25519,
    #[cfg(not(feature = "fips"))]
    Ed25519,
    #[cfg(not(feature = "fips"))]
    X448,
    #[cfg(not(feature = "fips"))]
    Ed448,
}

impl From<Curve> for RecommendedCurve {
    fn from(curve: Curve) -> RecommendedCurve {
        match curve {
            #[cfg(not(feature = "fips"))]
            Curve::NistP192 => RecommendedCurve::P192,
            Curve::NistP224 => RecommendedCurve::P224,
            Curve::NistP256 => RecommendedCurve::P256,
            Curve::NistP384 => RecommendedCurve::P384,
            Curve::NistP521 => RecommendedCurve::P521,
            #[cfg(not(feature = "fips"))]
            Curve::X25519 => RecommendedCurve::CURVE25519,
            #[cfg(not(feature = "fips"))]
            Curve::Ed25519 => RecommendedCurve::CURVEED25519,
            #[cfg(not(feature = "fips"))]
            Curve::X448 => RecommendedCurve::CURVE448,
            #[cfg(not(feature = "fips"))]
            Curve::Ed448 => RecommendedCurve::CURVEED448,
        }
    }
}

/// Create an elliptic curve key pair
///
///  - The public is used to encrypt
///      and can be safely shared.
///  - The private key is used to decrypt
///      and must be kept secret.
///
/// Run this subcommand with --help to see the list of supported curves.
/// Defaults to NIST P256
///
/// Tags can later be used to retrieve the keys. Tags are optional.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateKeyPairAction {
    /// The elliptic curve
    #[clap(long = "curve", short = 'c', default_value = "nist-p256")]
    curve: Curve,

    /// The tag to associate with the master key pair.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,
}

impl CreateKeyPairAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> Result<(), CliError> {
        let create_key_pair_request = create_ec_key_pair_request(&self.tags, self.curve.into())?;

        // Query the KMS with your kmip data and get the key pair ids
        let create_key_pair_response = kms_rest_client
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

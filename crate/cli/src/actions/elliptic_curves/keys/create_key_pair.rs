use clap::{Parser, ValueEnum};
use cosmian_kms_client::{
    cosmian_kmip::{
        crypto::elliptic_curves::kmip_requests::create_ec_key_pair_request,
        kmip::kmip_types::RecommendedCurve,
    },
    kmip::kmip_types::UniqueIdentifier,
    KmsClient,
};

use crate::{
    actions::console,
    error::result::{CliResult, CliResultHelper},
};

#[derive(ValueEnum, Debug, Clone, Copy)]
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
    fn from(curve: Curve) -> Self {
        match curve {
            #[cfg(not(feature = "fips"))]
            Curve::NistP192 => Self::P192,
            Curve::NistP224 => Self::P224,
            Curve::NistP256 => Self::P256,
            Curve::NistP384 => Self::P384,
            Curve::NistP521 => Self::P521,
            #[cfg(not(feature = "fips"))]
            Curve::X25519 => Self::CURVE25519,
            #[cfg(not(feature = "fips"))]
            Curve::Ed25519 => Self::CURVEED25519,
            #[cfg(not(feature = "fips"))]
            Curve::X448 => Self::CURVE448,
            #[cfg(not(feature = "fips"))]
            Curve::Ed448 => Self::CURVEED448,
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
/// Default to NIST P256
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

    /// The unique id of the private key; a random uuid
    /// is generated if not specified.
    #[clap(required = false)]
    private_key_id: Option<String>,

    /// Sensitive: if set, the key will not be exportable
    #[clap(long = "sensitive", default_value = "false")]
    sensitive: bool,
}

impl CreateKeyPairAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let private_key_id = self
            .private_key_id
            .as_ref()
            .map(|id| UniqueIdentifier::TextString(id.clone()));
        let create_key_pair_request = create_ec_key_pair_request(
            private_key_id,
            &self.tags,
            self.curve.into(),
            self.sensitive,
        )?;
        // Query the KMS with your kmip data and get the key pair ids
        let create_key_pair_response = kms_rest_client
            .create_key_pair(create_key_pair_request)
            .await
            .with_context(|| "failed creating a Elliptic Curve key pair")?;

        let private_key_unique_identifier = &create_key_pair_response.private_key_unique_identifier;
        let public_key_unique_identifier = &create_key_pair_response.public_key_unique_identifier;

        let mut stdout = console::Stdout::new("The EC key pair has been created.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_key_pair_unique_identifier(
            private_key_unique_identifier,
            public_key_unique_identifier,
        );
        stdout.write()?;

        Ok(())
    }
}

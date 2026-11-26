use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_operations::CreateKeyPair, kmip_types::UniqueIdentifier,
        requests::create_ec_key_pair_request,
    },
    reexport::cosmian_kms_client_utils::create_utils::Curve,
};

use crate::{
    actions::shared::RotationPolicyArgs,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Create an elliptic curve key pair
///
///  - The public is used to encrypt
///    and can be safely shared.
///  - The private key is used to decrypt
///    and must be kept secret.
///
/// Run this subcommand with --help to see the list of supported curves.
/// Default to NIST P256
///
/// Tags can later be used to retrieve the keys. Tags are optional.
#[derive(Parser, Default)]
#[clap(verbatim_doc_comment)]
pub struct CreateKeyPairAction {
    /// The elliptic curve
    #[clap(long = "curve", short = 'c', default_value = "nist-p256")]
    pub(crate) curve: Curve,

    /// The tag to associate with the master key pair.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    pub(crate) tags: Vec<String>,

    /// The unique id of the private key; a random uuid
    /// is generated if not specified.
    #[clap(required = false)]
    pub(crate) private_key_id: Option<String>,

    /// Sensitive: `--sensitive` (or `--sensitive true`) makes the private key non-exportable;
    /// `--sensitive false` explicitly allows its export, including on an HSM, where keys
    /// are sensitive (non-extractable) by default.
    #[clap(long = "sensitive", num_args = 0..=1, default_missing_value = "true")]
    pub(crate) sensitive: Option<bool>,

    /// The key encryption key (KEK) used to wrap the keypair with.
    /// If the wrapping key is:
    /// - a symmetric key, AES-GCM will be used
    /// - a RSA key, RSA-OAEP will be used
    /// - a EC key, ECIES will be used (salsa20poly1305 for X25519)
    #[clap(
        long = "wrapping-key-id",
        short = 'w',
        required = false,
        verbatim_doc_comment
    )]
    pub(crate) wrapping_key_id: Option<String>,

    /// Optional rotation policy to apply immediately after key pair creation.
    #[clap(flatten)]
    pub(crate) rotation_policy: RotationPolicyArgs,
}

impl CreateKeyPairAction {
    /// Build the `CreateKeyPair` request. `--sensitive false` is sent explicitly as
    /// `Sensitive=false` (opt-out of the HSM sensitive-by-default policy).
    fn build_request(&self, vendor_id: &str) -> KmsCliResult<CreateKeyPair> {
        let private_key_id = self
            .private_key_id
            .as_ref()
            .map(|id| UniqueIdentifier::TextString(id.clone()));
        let mut request = create_ec_key_pair_request(
            vendor_id,
            private_key_id,
            &self.tags,
            self.curve.into(),
            self.sensitive == Some(true),
            self.wrapping_key_id.as_ref(),
        )?;
        if self.sensitive == Some(false)
            && let Some(private_key_attributes) = request.private_key_attributes.as_mut()
        {
            private_key_attributes.sensitive = Some(false);
        }
        Ok(request)
    }

    pub async fn run(
        &self,
        kms_rest_client: KmsClient,
    ) -> KmsCliResult<(UniqueIdentifier, UniqueIdentifier)> {
        let create_key_pair_request =
            self.build_request(kms_rest_client.config.vendor_id.as_str())?;
        // Query the KMS with your kmip data and get the key pair ids
        let create_key_pair_response = kms_rest_client
            .create_key_pair(create_key_pair_request)
            .await
            .with_context(|| "failed creating a Elliptic Curve key pair")?;

        self.rotation_policy
            .finish_key_pair_creation(
                &kms_rest_client,
                create_key_pair_response,
                &self.tags,
                "The EC key pair has been created.",
            )
            .await
    }
}

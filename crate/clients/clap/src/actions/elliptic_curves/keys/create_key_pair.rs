use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{kmip_types::UniqueIdentifier, requests::create_ec_key_pair_request},
    reexport::cosmian_kms_client_utils::create_utils::Curve,
};

use crate::{
    actions::{console, shared::RotationPolicyArgs},
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

    /// Sensitive: if set, the key will not be exportable
    #[clap(long = "sensitive", default_value = "false")]
    pub(crate) sensitive: bool,

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
    pub async fn run(
        &self,
        kms_rest_client: KmsClient,
    ) -> KmsCliResult<(UniqueIdentifier, UniqueIdentifier)> {
        // Validate key_id / rotate_name consistency before sending any request.
        let effective_key_id = self
            .rotation_policy
            .effective_key_id(self.private_key_id.as_deref())?;

        let private_key_id = effective_key_id
            .as_ref()
            .map(|id| UniqueIdentifier::TextString(id.clone()));
        let create_key_pair_request = create_ec_key_pair_request(
            kms_rest_client.config.vendor_id.as_str(),
            private_key_id,
            &self.tags,
            self.curve.into(),
            self.sensitive,
            self.wrapping_key_id.as_ref(),
        )?;
        // Query the KMS with your kmip data and get the key pair ids
        let create_key_pair_response = kms_rest_client
            .create_key_pair(create_key_pair_request)
            .await
            .with_context(|| "failed creating a Elliptic Curve key pair")?;

        let private_key_unique_identifier = &create_key_pair_response.private_key_unique_identifier;
        let public_key_unique_identifier = &create_key_pair_response.public_key_unique_identifier;

        // Apply rotation policy on the private key (which is the keyset anchor)
        if self.rotation_policy.is_set() {
            let sk_id = private_key_unique_identifier
                .as_str()
                .with_context(|| "the server did not return a private key id as a string")?;
            self.rotation_policy.apply(&kms_rest_client, sk_id).await?;
        }

        let mut stdout = console::Stdout::new("The EC key pair has been created.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_key_pair_unique_identifier(
            private_key_unique_identifier,
            public_key_unique_identifier,
        );
        stdout.write()?;

        Ok((
            private_key_unique_identifier.clone(),
            public_key_unique_identifier.clone(),
        ))
    }
}

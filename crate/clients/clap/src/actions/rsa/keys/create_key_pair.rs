use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{kmip_types::UniqueIdentifier, requests::create_rsa_key_pair_request},
};

use crate::{
    actions::{console, shared::utils::apply_rotation_policy_if_set},
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Create a new RSA key pair
///
///  - The public is used to encrypt or verify a signature
///    and can be safely shared.
///  - The private key is used to decrypt or sign
///    and must be kept secret.
///
/// Tags can later be used to retrieve the keys. Tags are optional.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateKeyPairAction {
    /// The expected size in bits
    #[clap(
        long = "size_in_bits",
        short = 's',
        value_name = "SIZE_IN_BITS",
        default_value = "4096"
    )]
    pub key_size: usize,

    /// The tag to associate with the master key pair.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    pub tags: Vec<String>,

    /// The unique id of the private key; a random uuid
    /// is generated if not specified.
    #[clap(required = false)]
    pub private_key_id: Option<String>,

    /// Sensitive: if set, the private key will not be exportable
    #[clap(long = "sensitive", default_value = "false")]
    pub sensitive: bool,

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
    pub wrapping_key_id: Option<String>,

    /// Auto-rotation interval in seconds. Set to 0 to disable.
    /// Example: 86400 for daily rotation, 604800 for weekly rotation.
    #[clap(long = "rotate-interval", short = 'i', required = false)]
    pub rotate_interval: Option<i32>,

    /// Optional name to identify the rotation policy lineage.
    #[clap(long = "rotate-name", required = false)]
    pub rotate_name: Option<String>,

    /// Delay in seconds before the first automatic rotation is triggered.
    /// Defaults to the rotation interval if not set.
    #[clap(long = "rotate-offset", required = false)]
    pub rotate_offset: Option<i32>,
}

impl Default for CreateKeyPairAction {
    fn default() -> Self {
        Self {
            key_size: 4096,
            tags: Vec::new(),
            private_key_id: None,
            sensitive: false,
            wrapping_key_id: None,
            rotate_interval: None,
            rotate_name: None,
            rotate_offset: None,
        }
    }
}

impl CreateKeyPairAction {
    /// Run the create key pair action
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - A reference to the KMS client used to perform the key pair creation.
    ///
    /// # Results
    ///
    /// This function returns a `KmsCliResult<(UniqueIdentifier, UniqueIdentifier)>` indicating the success or failure of the key pair creation action.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The key pair request cannot be built.
    /// * The KMS server query fails.
    /// * The key pair unique identifiers are empty.
    pub async fn run(
        &self,
        kms_rest_client: KmsClient,
    ) -> KmsCliResult<(UniqueIdentifier, UniqueIdentifier)> {
        let private_key_id = self
            .private_key_id
            .as_ref()
            .map(|id| UniqueIdentifier::TextString(id.clone()));
        let create_key_pair_request = create_rsa_key_pair_request(
            kms_rest_client.config.vendor_id.as_str(),
            private_key_id,
            &self.tags,
            self.key_size,
            self.sensitive,
            self.wrapping_key_id.as_ref(),
        )?;

        // Query the KMS with your kmip data and get the key pair ids
        let create_key_pair_response = kms_rest_client
            .create_key_pair(create_key_pair_request)
            .await
            .with_context(|| "failed creating a RSA key pair")?;

        let private_key_unique_identifier = &create_key_pair_response.private_key_unique_identifier;
        let public_key_unique_identifier = &create_key_pair_response.public_key_unique_identifier;

        let mut stdout = console::Stdout::new("The RSA key pair has been created.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_key_pair_unique_identifier(
            private_key_unique_identifier,
            public_key_unique_identifier,
        );
        stdout.write()?;

        // Apply rotation policy on the private key if any fields are set
        apply_rotation_policy_if_set(
            &kms_rest_client,
            &private_key_unique_identifier.to_string(),
            self.rotate_interval,
            self.rotate_name.as_deref(),
            self.rotate_offset,
        )
        .await?;

        Ok((
            private_key_unique_identifier.to_owned(),
            public_key_unique_identifier.to_owned(),
        ))
    }
}

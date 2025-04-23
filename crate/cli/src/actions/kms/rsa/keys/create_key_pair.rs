use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{kmip_types::UniqueIdentifier, requests::create_rsa_key_pair_request},
};

use crate::{
    actions::console,
    error::result::{CosmianResult, CosmianResultHelper},
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
}

impl Default for CreateKeyPairAction {
    fn default() -> Self {
        Self {
            key_size: 4096,
            tags: Vec::new(),
            private_key_id: None,
            sensitive: false,
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
    /// This function returns a `CosmianResult<(UniqueIdentifier, UniqueIdentifier)>` indicating the success or failure of the key pair creation action.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The key pair request cannot be built.
    /// * The KMS server query fails.
    /// * The key pair unique identifiers are empty.
    pub async fn run(
        &self,
        kms_rest_client: &KmsClient,
    ) -> CosmianResult<(UniqueIdentifier, UniqueIdentifier)> {
        let private_key_id = self
            .private_key_id
            .as_ref()
            .map(|id| UniqueIdentifier::TextString(id.clone()));
        let create_key_pair_request =
            create_rsa_key_pair_request(private_key_id, &self.tags, self.key_size, self.sensitive)?;

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

        Ok((
            private_key_unique_identifier.to_owned(),
            public_key_unique_identifier.to_owned(),
        ))
    }
}

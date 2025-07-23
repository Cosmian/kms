use clap::Parser;
use cosmian_kmip::kmip_2_1::{
    kmip_attributes::Attributes, requests::create_secret_data_kmip_object,
};
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{kmip_types::UniqueIdentifier, requests::import_object_request},
    reexport::cosmian_kms_client_utils::create_utils::SecretDataType,
};
use zeroize::Zeroizing;

use crate::{
    actions::kms::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
    reexport::cosmian_kms_client::kmip_2_1::requests::secret_data_create_request,
};

/// Create a new secret data
///
/// Tags can later be used to retrieve the secret data. Tags are optional.
#[derive(Parser, Default)]
#[clap(verbatim_doc_comment)]
pub struct CreateSecretDataAction {
    /// Optional secret data string, UTF-8 encoded.
    /// If not provided, a random 32-byte seed will be generated.
    #[clap(long = "value", short = 'v', required = false)]
    pub secret_value: Option<String>,

    /// The type of secret data.
    /// Defaults to a randomly generated Seed.
    /// To use a Password type, you must provide both this and a valid secret value.
    #[clap(
        long = "type",
        required = false,
        default_value = "seed",
        requires = "secret_value"
    )]
    pub secret_type: SecretDataType,

    /// The tag to associate with the secret data.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    pub tags: Vec<String>,

    /// The unique id of the secret; a random uuid
    /// is generated if not specified.
    #[clap(required = false)]
    pub secret_id: Option<String>,

    /// Sensitive: if set, the secret will not be exportable
    #[clap(long = "sensitive", default_value = "false")]
    pub sensitive: bool,

    /// The key encryption key (KEK) used to wrap this new secret data with.
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
}

impl CreateSecretDataAction {
    /// Create a new secret data
    ///
    /// # Errors
    /// Fail in input key parsing fails
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let secret_data_type: cosmian_kmip::kmip_0::kmip_types::SecretDataType = match self
            .secret_type
        {
            SecretDataType::Seed => cosmian_kmip::kmip_0::kmip_types::SecretDataType::Seed,
            SecretDataType::Password => cosmian_kmip::kmip_0::kmip_types::SecretDataType::Password,
        };

        let unique_identifier = if let Some(value) = &self.secret_value {
            let secret_bytes = Zeroizing::from(value.as_bytes().to_vec());

            let mut object = create_secret_data_kmip_object(
                secret_bytes.as_slice(),
                secret_data_type,
                &Attributes::default(),
            )?;
            if let Some(wrapping_key_id) = &self.wrapping_key_id {
                let attributes = object.attributes_mut()?;
                attributes.set_wrapping_key_id(wrapping_key_id);
            }
            let import_object_request = import_object_request(
                self.secret_id.clone(),
                object,
                None,
                false,
                false,
                &self.tags,
            );
            kms_rest_client
                .import(import_object_request)
                .await
                .with_context(|| "failed importing the secret data")?
                .unique_identifier
        } else {
            let secret_id = self
                .secret_id
                .as_ref()
                .map(|id| UniqueIdentifier::TextString(id.clone()));
            let create_secret_data_request = secret_data_create_request(
                secret_id,
                &self.tags,
                self.sensitive,
                self.wrapping_key_id.as_ref(),
            )?;
            kms_rest_client
                .create(create_secret_data_request)
                .await
                .with_context(|| "failed creating the secret data")?
                .unique_identifier
        };

        let mut stdout = console::Stdout::new("The secret data was successfully generated.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_unique_identifier(&unique_identifier);
        stdout.write()?;

        Ok(unique_identifier)
    }
}

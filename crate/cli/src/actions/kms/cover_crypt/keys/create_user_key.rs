use clap::Parser;
use cosmian_kms_client::{
    KmsClient, kmip_2_1::kmip_types::UniqueIdentifier,
    reexport::cosmian_kms_client_utils::cover_crypt_utils::build_create_covercrypt_usk_request,
};
use cosmian_kms_crypto::reexport::cosmian_cover_crypt::AccessPolicy;

use crate::{
    actions::kms::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Create a new user secret key for an access policy, and index it under some
/// (optional) tags, that can later be used to retrieve the key.
#[derive(Parser, Default, Debug)]
#[clap(verbatim_doc_comment)]
pub struct CreateUserKeyAction {
    /// The master secret key unique identifier
    #[clap(required = true)]
    pub(crate) master_secret_key_id: String,

    /// The access policy should be expressed as a boolean expression of
    /// attributes. For example (provided the corresponding attributes are
    /// defined in the MSK):
    ///
    /// `"(Department::HR || Department::MKG) && Security Level::Confidential"`
    #[clap(required = true)]
    pub(crate) access_policy: String,

    /// The tag to associate with the user decryption key.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    pub(crate) tags: Vec<String>,

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
}

impl CreateUserKeyAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        // Validate the access policy: side-effect only.
        AccessPolicy::parse(&self.access_policy).with_context(|| "bad access policy syntax")?;

        let request = build_create_covercrypt_usk_request(
            &self.access_policy,
            &self.master_secret_key_id,
            &self.tags,
            self.sensitive,
            self.wrapping_key_id.as_ref(),
        )?;

        let response = kms_rest_client
            .create(request)
            .await
            .with_context(|| "user decryption key creation failed")?;

        let mut stdout =
            console::Stdout::new("The user decryption key pair has been properly generated.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_unique_identifier(&response.unique_identifier);
        stdout.write()?;
        Ok(response.unique_identifier)
    }
}

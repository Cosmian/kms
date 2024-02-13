use clap::Parser;
use cloudproof::reexport::cover_crypt::abe_policy::Attribute;
use cosmian_kmip::crypto::cover_crypt::{
    attributes::EditPolicyAction, kmip_requests::build_rekey_keypair_request,
};
use cosmian_kms_client::KmsRestClient;

use crate::{
    cli_bail,
    error::{result::CliResultHelper, CliError},
};

/// Rotate attributes and rekey the master and user keys.
///
/// Data encrypted with the rotated attributes
/// cannot be decrypted by user decryption keys unless they have been re-keyed.
///
/// Active user decryption keys are automatically re-keyed.
/// Revoked or destroyed user decryption keys are not re-keyed.
///
/// User keys that have not been rekeyed can still decrypt data encrypted
/// with the old attribute values.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct RekeyAction {
    /// The policy attributes to rotate.
    /// Example: `department::marketing level::confidential`
    #[clap(required = true)]
    access_policy: String,

    /// The private master key unique identifier stored in the KMS
    /// If not specified, tags should be specified
    #[clap(long = "key-id", short = 'k', group = "key-tags")]
    secret_key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,
}

impl RekeyAction {
    pub async fn run(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        let id = if let Some(key_id) = &self.secret_key_id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --key-id or one or more --tag must be specified")
        };

        // Create the kmip query
        let rekey_query = build_rekey_keypair_request(
            &id,
            RekeyEditAction::RekeyAccessPolicy(self.access_policy.clone()),
        )?;

        // Query the KMS with your kmip data
        let rekey_response = kms_rest_client
            .rekey_keypair(rekey_query)
            .await
            .with_context(|| "failed rotating the master keys")?;

        println!(
            "The master private key {} and master public key {} were rekeyed for the access \
             policy {:?}",
            &rekey_response.private_key_unique_identifier,
            &rekey_response.public_key_unique_identifier,
            &self.access_policy
        );
        Ok(())
    }
}

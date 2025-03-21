use clap::Parser;
use cosmian_kms_client::KmsClient;
use cosmian_kms_crypto::crypto::cover_crypt::{
    attributes::RekeyEditAction, kmip_requests::build_rekey_keypair_request,
};

use crate::{
    actions::{console, labels::KEY_ID, shared::get_key_uid},
    error::result::{CliResult, CliResultHelper},
};

/// Rekey the given access policy.
///
/// Active user decryption keys are automatically re-keyed.
/// Revoked or destroyed user decryption keys are not re-keyed.
///
/// User keys that have not been rekeyed will only be able to decrypt
/// data encrypted before this operation.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct RekeyAction {
    /// The access policy to rekey.
    /// Example: `department::marketing && level::confidential`
    #[clap(required = true)]
    access_policy: String,

    /// The master secret key unique identifier stored in the KMS.
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    master_secret_key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,
}

impl RekeyAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let id = get_key_uid(
            self.master_secret_key_id.as_ref(),
            self.tags.as_ref(),
            KEY_ID,
        )?;

        let res = kms_rest_client
            .rekey_keypair(build_rekey_keypair_request(
                &id,
                &RekeyEditAction::RekeyAccessPolicy(self.access_policy.clone()),
            )?)
            .await
            .with_context(|| "failed rekeying the master keys")?;

        let stdout = format!(
            "The MSK {} and MPK {} were rekeyed for the access policy {:?}",
            &res.private_key_unique_identifier,
            &res.public_key_unique_identifier,
            &self.access_policy
        );

        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_key_pair_unique_identifier(
            res.private_key_unique_identifier,
            res.public_key_unique_identifier,
        );
        stdout.write()
    }
}

/// Prune the master and user keys for a given access policy.
///
/// Active user decryption keys are automatically pruned.
/// Revoked or destroyed user decryption keys are not.
///
/// Pruned user keys will only be able to decrypt ciphertexts
/// generated after the last rekeying.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct PruneAction {
    /// The access policy to prune.
    /// Example: `department::marketing && level::confidential`
    #[clap(required = true)]
    access_policy: String,

    /// The private master key unique identifier stored in the KMS.
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    master_secret_key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,
}

impl PruneAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let id = get_key_uid(
            self.master_secret_key_id.as_ref(),
            self.tags.as_ref(),
            KEY_ID,
        )?;

        // Create the kmip query
        let query = build_rekey_keypair_request(
            &id,
            &RekeyEditAction::PruneAccessPolicy(self.access_policy.clone()),
        )?;

        // Query the KMS with your kmip data
        let response = kms_rest_client
            .rekey_keypair(query)
            .await
            .with_context(|| "failed pruning the master keys")?;

        let stdout = format!(
            "The master secret key {} and master public key {} were pruned for the access policy \
             {:?}",
            &response.private_key_unique_identifier,
            &response.public_key_unique_identifier,
            &self.access_policy
        );

        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_tags(self.tags.as_ref());
        stdout.set_key_pair_unique_identifier(
            response.private_key_unique_identifier,
            response.public_key_unique_identifier,
        );
        stdout.write()?;

        Ok(())
    }
}

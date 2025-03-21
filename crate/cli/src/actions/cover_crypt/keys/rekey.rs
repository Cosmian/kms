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
/// Active USKs are automatically re-keyed. Revoked or destroyed USKs are not
/// re-keyed.
///
/// USKs that have not been rekeyed will only be able to decrypt data encrypted
/// before this operation.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct RekeyAction {
    /// The access policy should be expressed as a boolean expression of
    /// attributes. For example (provided the corresponding attributes are
    /// defined in the MSK):
    ///
    /// `"(Department::HR || Department::MKG) && Security Level::Confidential"`
    #[clap(required = true)]
    access_policy: String,

    /// The MSK UID stored in the KMS. If not specified, tags should be
    /// specified.
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    msk_uid: Option<String>,

    /// Tag to use to retrieve the MSK when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,
}

impl RekeyAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let uid = get_key_uid(self.msk_uid.as_ref(), self.tags.as_ref(), KEY_ID)?;

        let res = kms_rest_client
            .rekey_keypair(build_rekey_keypair_request(
                &uid,
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

/// Prune all keys linked to an MSK w.r.t an given access policy.
///
/// Active USKs are automatically pruned. Revoked or destroyed user decryption
/// keys are not.
///
/// Pruned user keys can only open encapsulations generated for this access
/// policy since the last rekeying.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct PruneAction {
    /// The access policy should be expressed as a boolean expression of
    /// attributes. For example (provided the corresponding attributes are
    /// defined in the MSK):
    ///
    /// `"(Department::HR || Department::MKG) && Security Level::Confidential"`
    #[clap(required = true)]
    access_policy: String,

    /// The private master key unique identifier stored in the KMS.
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    msk_uid: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,
}

impl PruneAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let uid = get_key_uid(self.msk_uid.as_ref(), self.tags.as_ref(), KEY_ID)?;

        let request = build_rekey_keypair_request(
            &uid,
            &RekeyEditAction::PruneAccessPolicy(self.access_policy.clone()),
        )?;

        let res = kms_rest_client
            .rekey_keypair(request)
            .await
            .with_context(|| "failed pruning the master keys")?;

        let stdout = format!(
            "The MSK {} and MPK {} were pruned for the access policy {:?}",
            &res.private_key_unique_identifier,
            &res.public_key_unique_identifier,
            &self.access_policy
        );

        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_tags(self.tags.as_ref());
        stdout.set_key_pair_unique_identifier(
            res.private_key_unique_identifier,
            res.public_key_unique_identifier,
        );
        stdout.write()
    }
}

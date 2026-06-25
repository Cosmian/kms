use clap::Parser;
use cosmian_kms_client::{
    KmsClient, cosmian_kmip::kmip_0::kmip_types::RevocationReasonCode,
    kmip_2_1::kmip_types::UniqueIdentifier,
};

use crate::{
    actions::{
        labels::KEY_ID,
        shared::{
            get_key_uid,
            utils::{parse_revocation_reason_code, revoke},
        },
    },
    error::result::KmsCliResult,
};

/// Revoke a PQC public or private key.
#[derive(Parser, Debug)]
pub struct RevokeKeyAction {
    /// The reason for the revocation
    #[clap(required = true)]
    revocation_reason: String,

    /// The revocation reason code [default: unspecified]
    ///
    /// Valid values: unspecified, key-compromise, ca-compromise,
    /// affiliation-changed, superseded, cessation-of-operation,
    /// privilege-withdrawn
    #[clap(long = "reason-code", short = 'r', default_value = "unspecified",
           value_parser = parse_revocation_reason_code)]
    reason_code: RevocationReasonCode,

    /// The key unique identifier of the key to revoke
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,
}

impl RevokeKeyAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let id = get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;
        revoke(
            kms_rest_client,
            &id,
            &self.revocation_reason,
            self.reason_code,
        )
        .await
    }
}

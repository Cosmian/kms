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

/// Revoke an `OpaqueObject`.
///
/// Once revoked, the object can typically only be exported by the owner when explicitly allowed.
#[derive(Parser, Debug)]
pub struct RevokeOpaqueObjectAction {
    /// The reason for the revocation as a string
    #[clap(required = true)]
    pub(crate) revocation_reason: String,

    /// The revocation reason code [default: unspecified]
    ///
    /// Valid values: unspecified, key-compromise, ca-compromise,
    /// affiliation-changed, superseded, cessation-of-operation,
    /// privilege-withdrawn
    #[clap(long = "reason-code", short = 'r', default_value = "unspecified",
           value_parser = parse_revocation_reason_code)]
    pub(crate) reason_code: RevocationReasonCode,

    /// The opaque object unique identifier to revoke. If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) object_id: Option<String>,

    /// Tags to locate the object if id is not provided. Repeat to specify multiple tags.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,
}

impl RevokeOpaqueObjectAction {
    pub(crate) async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let id = get_key_uid(self.object_id.as_ref(), self.tags.as_ref(), KEY_ID)?;
        revoke(
            kms_rest_client,
            &id,
            &self.revocation_reason,
            self.reason_code,
        )
        .await
    }
}

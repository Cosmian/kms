use clap::Parser;
use cosmian_kms_client::{
    KmsClient, cosmian_kmip::kmip_0::kmip_types::RevocationReasonCode,
    kmip_2_1::kmip_types::UniqueIdentifier,
};

use crate::{
    actions::{
        labels::{CERTIFICATE_ID, TAG},
        shared::{
            get_key_uid,
            utils::{parse_revocation_reason_code, revoke},
        },
    },
    error::result::KmsCliResult,
};

/// Revoke a certificate.
///
/// When a certificate is revoked, it can only be exported by the owner of the certificate,
/// using the --allow-revoked flag on the export function.
#[derive(Parser, Debug)]
pub struct RevokeCertificateAction {
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

    /// The certificate unique identifier of the certificate to revoke.
    /// If not specified, tags should be specified
    #[clap(long = CERTIFICATE_ID, short = 'c', group = "certificate-tags")]
    pub(crate) certificate_id: Option<String>,

    /// Tag to use to retrieve the certificate when no certificate id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(
        long = TAG,
        short = 't',
        value_name = "TAG",
        group = "certificate-tags"
    )]
    pub(crate) tags: Option<Vec<String>>,
}

impl RevokeCertificateAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let id = get_key_uid(
            self.certificate_id.as_ref(),
            self.tags.as_ref(),
            CERTIFICATE_ID,
        )?;
        revoke(
            kms_rest_client,
            &id,
            &self.revocation_reason,
            self.reason_code,
        )
        .await
    }
}

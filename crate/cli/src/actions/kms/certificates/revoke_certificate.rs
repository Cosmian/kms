use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{
    actions::kms::{
        labels::{CERTIFICATE_ID, TAG},
        shared::{get_key_uid, utils::revoke},
    },
    error::result::CosmianResult,
};

/// Revoke a certificate.
///
/// When a certificate is revoked, it can only be exported by the owner of the certificate,
/// using the --allow-revoked flag on the export function.
#[derive(Parser, Debug)]
pub struct RevokeCertificateAction {
    /// The reason for the revocation as a string
    #[clap(required = true)]
    revocation_reason: String,

    /// The certificate unique identifier of the certificate to revoke.
    /// If not specified, tags should be specified
    #[clap(long = CERTIFICATE_ID, short = 'c', group = "certificate-tags")]
    certificate_id: Option<String>,

    /// Tag to use to retrieve the certificate when no certificate id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(
        long = TAG,
        short = 't',
        value_name = "TAG",
        group = "certificate-tags"
    )]
    tags: Option<Vec<String>>,
}

impl RevokeCertificateAction {
    pub async fn run(&self, client_connector: &KmsClient) -> CosmianResult<()> {
        let id = get_key_uid(
            self.certificate_id.as_ref(),
            self.tags.as_ref(),
            CERTIFICATE_ID,
        )?;
        revoke(client_connector, &id, &self.revocation_reason).await
    }
}

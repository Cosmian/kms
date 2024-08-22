use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{actions::shared::utils::revoke, cli_bail, error::result::CliResult};

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
    #[clap(long = "certificate-id", short = 'c', group = "certificate-tags")]
    certificate_id: Option<String>,

    /// Tag to use to retrieve the certificate when no certificate id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(
        long = "tag",
        short = 't',
        value_name = "TAG",
        group = "certificate-tags"
    )]
    tags: Option<Vec<String>>,
}

impl RevokeCertificateAction {
    pub async fn run(&self, client_connector: &KmsClient) -> CliResult<()> {
        let id = if let Some(certificate_id) = &self.certificate_id {
            certificate_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --certificate-id or one or more --tag must be specified")
        };
        revoke(client_connector, &id, &self.revocation_reason).await
    }
}

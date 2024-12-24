use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{actions::shared::utils::destroy, cli_bail, error::result::CliResult};

/// Destroy a certificate.
///
/// The certificate must have been revoked first.
///
/// When a certificate is destroyed but not removed,
/// its metadata can only be exported
/// by the owner of the certificate
#[derive(Parser, Debug)]
pub struct DestroyCertificateAction {
    /// The certificate unique identifier.
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

    /// If the certificate should be removed from the database
    /// If not specified, the certificate will be destroyed
    /// but its metadata will still be available in the database.
    /// Please note that the KMIP specification does not support the removal of objects.
    #[clap(long = "remove", default_value = "false", verbatim_doc_comment)]
    remove: bool,
}

impl DestroyCertificateAction {
    pub async fn run(&self, client_connector: &KmsClient) -> CliResult<()> {
        let id = if let Some(certificate_id) = &self.certificate_id {
            certificate_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either `--certificate-id` or one or more `--tag` must be specified")
        };

        destroy(client_connector, &id, self.remove).await
    }
}

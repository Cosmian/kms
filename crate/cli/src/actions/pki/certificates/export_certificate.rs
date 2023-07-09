use std::path::PathBuf;

use clap::Parser;
use cosmian_kmip::kmip::kmip_objects::Object;
use cosmian_kms_client::KmsRestClient;

use crate::{
    actions::shared::utils::{export_object, write_bytes_to_file, write_kmip_object_to_file},
    cli_bail,
    error::CliError,
};

/// Export a certificate from the KMS
///
/// The certificate is exported in JSON KMIP TTLV format
/// unless the `--bytes` option is specified, in which case
/// the certificate bytes are exported without metadata, such as
///  - the links between the certificates in a pair
///  - other metadata: policies, etc.
/// certificate bytes are sufficient to perform local encryption or decryption.
///
/// When using tags to retrieve the certificate, rather than the certificate id,
/// an error is returned if multiple certificates matching the tags are found.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ExportCertificateAction {
    /// The file to export the certificate to
    #[clap(required = true)]
    certificate_file: PathBuf,

    /// The certificate unique identifier stored in the KMS.
    /// If not specified, tags should be specified
    #[clap(long = "certificate-id", short = 'k', group = "certificate-tags")]
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

    /// Export the certificate bytes only
    #[clap(long = "bytes", short = 'b', default_value = "false")]
    bytes: bool,

    /// Allow exporting revoked and destroyed certificates.
    /// The user must be the owner of the certificate.
    /// Destroyed certificates have their certificate material removed.
    #[clap(long = "allow-revoked", short = 'i', default_value = "false")]
    allow_revoked: bool,
}

impl ExportCertificateAction {
    /// Export a certificate from the KMS
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        let id = if let Some(certificate_id) = &self.certificate_id {
            certificate_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --certificate-id or one or more --tag must be specified")
        };

        // export the object
        let object = export_object(client_connector, &id, false, &None, self.allow_revoked).await?;

        let certificate_bytes = match &object {
            Object::Certificate {
                certificate_type: _,
                certificate_value,
            } => certificate_value,
            _ => {
                cli_bail!(
                    "The object {} is not a certificate but a {}",
                    &id,
                    object.object_type()
                );
            }
        };

        // write the object to a file
        if self.bytes {
            // export the certificate bytes only
            write_bytes_to_file(certificate_bytes, &self.certificate_file)?;
        } else {
            // save it to a file
            write_kmip_object_to_file(&object, &self.certificate_file)?;
        }

        println!(
            "The certificate {} of type {} was exported to {:?}",
            &id,
            object.object_type(),
            &self.certificate_file
        );
        Ok(())
    }
}

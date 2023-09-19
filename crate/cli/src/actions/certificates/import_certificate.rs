use std::path::PathBuf;

use clap::Parser;
use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_types::CertificateType,
};
use cosmian_kms_client::KmsRestClient;
use tracing::{debug, trace};

use crate::{
    actions::shared::utils::{import_object, read_bytes_from_file, read_key_from_file},
    error::CliError,
};

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum CertificateInputFormat {
    TTLV,
    PEM,
}

/// Import a certificate or a private/public keys the KMS.
///
/// The certificate can be in:
/// - KMIP JSON TTLV format
/// - PEM format
///
/// The private/public keys format is PEM format.
///
/// When no certificate unique id is specified, a random UUID v4 is generated.
///
/// Tags can later be used to retrieve the certificate. Tags are optional.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ImportCertificateAction {
    /// The KMIP JSON TTLV certificate file
    #[clap(required = true)]
    certificate_file: PathBuf,

    /// The unique id of the certificate; a random UUID v4 is generated if not specified
    #[clap(required = false)]
    certificate_id: Option<String>,

    /// Import the certificate in the selected format
    #[clap(long = "format", short = 'f')]
    input_format: CertificateInputFormat,

    /// Replace an existing certificate under the same id
    #[clap(
        required = false,
        long = "replace",
        short = 'r',
        default_value = "false"
    )]
    replace_existing: bool,

    /// The tag to associate with the certificate.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,
}

impl ImportCertificateAction {
    pub async fn run(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        debug!("CLI: entering import certificate");
        let object = match self.input_format {
            CertificateInputFormat::TTLV => {
                trace!("CLI: import certificate as TTLV JSON file");
                // read the certificate file
                let object = read_key_from_file(&self.certificate_file)?;
                trace!("CLI: read key from file OK");

                if object.object_type() != ObjectType::Certificate {
                    return Err(CliError::InvalidRequest(
                        "Object type MUST be equal to Certificate".to_string(),
                    ))
                }
                object
            }
            CertificateInputFormat::PEM => {
                debug!("CLI: import certificate as PEM file");
                let pem_value = read_bytes_from_file(&self.certificate_file)?;

                Object::Certificate {
                    certificate_type: CertificateType::X509,
                    certificate_value: pem_value,
                }
            }
        };

        // import the certificate
        let unique_identifier = import_object(
            kms_rest_client,
            self.certificate_id.clone(),
            object,
            false,
            self.replace_existing,
            &self.tags,
        )
        .await?;

        // print the response
        println!(
            "The certificate in file {:?} was imported with id: {}",
            &self.certificate_file, unique_identifier,
        );
        if !self.tags.is_empty() {
            println!("Tags:");
            for tag in &self.tags {
                println!("    - {tag}");
            }
        }

        Ok(())
    }
}

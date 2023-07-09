use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::KmsRestClient;

use crate::{
    actions::shared::utils::{import_object, read_key_from_file},
    error::CliError,
};

/// Import a certificate in the KMS.
///
/// The certificate must be in KMIP JSON TTLV format.
/// When no certificate unique id is specified, a random UUID v4 is generated.
///
///
/// A password is first converted to a 256-bit certificate using Argon 2.
/// Wrapping is performed according to RFC 5649.
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
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        // read the certificate file
        let object = read_key_from_file(&self.certificate_file)?;
        let object_type = object.object_type();

        // import the certificate
        let unique_identifier = import_object(
            client_connector,
            self.certificate_id.clone(),
            object,
            false,
            self.replace_existing,
            &self.tags,
        )
        .await?;

        // print the response
        println!(
            "The certificate of type {:?} in file {:?} was imported with id: {}",
            &self.certificate_file, object_type, unique_identifier,
        );
        if !self.tags.is_empty() {
            println!("Tags:");
            for tag in &self.tags {
                println!("    - {}", tag);
            }
        }

        Ok(())
    }
}

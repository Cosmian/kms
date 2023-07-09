use clap::Parser;
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType, kmip_operations::Certify, kmip_types::Attributes,
};
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::{
    crypto::certificate::attributes::{ca_as_vendor_attribute, subject_as_vendor_attribute},
    tagging::set_tags,
};

use crate::error::CliError;

/// Create a new certificate
///
/// If no options are specified, a fresh signed certificate will be created in the same time of the underlying keypair.
///
/// Tags can later be used to retrieve the key. Tags are optional.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateCertificateAction {
    /// The public key unique identifier.
    #[clap(long = "public-key-id", short = 'k', group = "key-tags")]
    public_key_id: Option<String>,

    /// The CA CN
    #[clap(long = "ca", required = true)]
    ca: String,

    /// The subject CN
    #[clap(long = "subject", short = 's', required = true)]
    subject: String,

    /// The tag to associate with the certificate.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,
}

impl CreateCertificateAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        let mut attributes = Attributes {
            vendor_attributes: Some(vec![
                subject_as_vendor_attribute(&self.subject)?,
                ca_as_vendor_attribute(&self.ca)?,
            ]),
            ..Attributes::new(ObjectType::Certificate)
        };

        println!("attributes: {:?}", attributes);
        set_tags(&mut attributes, &self.tags)?;
        println!("attributes: {:?}", attributes);
        let certify_request = Certify {
            unique_identifier: self.public_key_id.clone(),
            attributes: Some(attributes),
            ..Certify::default()
        };

        let certificate_unique_identifier = client_connector
            .certify(certify_request)
            .await
            .expect("failed creating certificate")
            .unique_identifier;

        println!(
            "The certificate was created with id: {}.",
            certificate_unique_identifier
        );
        Ok(())
    }
}

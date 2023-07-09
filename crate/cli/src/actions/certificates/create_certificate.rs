use clap::Parser;
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType, kmip_operations::Certify, kmip_types::Attributes,
};
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::{
    crypto::certificate::attributes::{
        ca_subject_common_names_as_vendor_attribute, subject_common_name_as_vendor_attribute,
    },
    tagging::set_tags,
};

use crate::error::CliError;

/// Create a new certificate
///
/// If no option is specified, a fresh signed certificate will be created in the same time of the underlying keypair.
///
/// Tags can be later used to retrieve the key. Tags are optional.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateCertificateAction {
    /// The public key unique identifier.
    #[clap(long = "public-key-id", short = 'k', group = "key-tags")]
    public_key_id: Option<String>,

    /// The full CA chain Subject Common Names separated by slashes.
    /// If no CA/SubCA certificate exists, the KMS server will create them.
    /// Example:
    /// - "CA Root/Sub CA"
    /// -> "CA Root" is the Subject Common Name of the root CA
    /// -> "Sub CA" is the Subject Common Name of the intermediate CA
    #[clap(long = "ca", required = true)]
    ca: String,

    /// The subject CN of the desired certificate
    #[clap(long = "subject", short = 's', required = true)]
    subject: String,

    /// The tag to associate to the certificate.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,
}

impl CreateCertificateAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        let mut attributes = Attributes {
            object_type: Some(ObjectType::Certificate),
            // Since there is no place for CA Subject Common Name nor Certificate Subject Common Name in the `Certify` request, those fields are placed in the vendors attributes.
            vendor_attributes: Some(vec![
                subject_common_name_as_vendor_attribute(&self.subject)?,
                ca_subject_common_names_as_vendor_attribute(&self.ca)?,
            ]),
            ..Attributes::default()
        };

        set_tags(&mut attributes, &self.tags)?;
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

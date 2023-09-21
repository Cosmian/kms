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

/// Create a new X509 certificate. If absent, the Certificate Authority certificates will be also created.
///
/// If no option is specified, a fresh signed certificate will be created in the same time of the underlying keypair.
///
/// Tags can be later used to retrieve the key. Tags are optional.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateCertificateAction {
    /// The certificate unique identifier.
    #[clap(long = "certificate-id", short = 'k', group = "key-tags")]
    certificate_id: Option<String>,

    /// The full Certificate Authority chain Subject Common Names separated by slashes (for example: CA/SubCA). If chain certificates does not exist, the KMS server will create them.
    #[clap(long = "ca_subject_common_names", short = 'c', required = true)]
    ca_subject_common_names: String,

    /// The subject CN of the desired certificate
    #[clap(long = "subject_common_name", short = 's', required = true)]
    subject_common_name: String,

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
                subject_common_name_as_vendor_attribute(&self.subject_common_name)?,
                ca_subject_common_names_as_vendor_attribute(&self.ca_subject_common_names)?,
            ]),
            ..Attributes::default()
        };

        set_tags(&mut attributes, &self.tags)?;
        let certify_request = Certify {
            unique_identifier: self.certificate_id.clone(),
            attributes: Some(attributes),
            ..Certify::default()
        };

        let certificate_unique_identifier = client_connector
            .certify(certify_request)
            .await
            .expect("failed creating certificate")
            .unique_identifier;

        println!("The certificate was created with id: {certificate_unique_identifier}.");
        Ok(())
    }
}

use std::path::PathBuf;

use clap::Parser;
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::Certify,
    kmip_types::{Attributes, CertificateRequestType},
};
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::{
    crypto::certificate::attributes::{
        certificate_id_as_vendor_attribute, issuer_private_key_id_as_vendor_attribute,
    },
    tagging::set_tags,
};

use crate::{actions::shared::utils::read_bytes_from_file, error::CliError};

/// Certify a Certificate Signing Request to create a X509 certificate.
///
/// Tags can be later used to retrieve the key. Tags are optional.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CertifyAction {
    /// The certificate unique identifier.
    /// A random one will be generated if not provided.
    #[clap(long = "certificate-id", short = 'k')]
    certificate_id: Option<String>,

    /// The path to a certificate signing request..
    #[clap(required = true, value_name = "CERTIFICATE_SIGNING_REQUEST")]
    certificate_signing_request: PathBuf,

    /// The format of the certificate signing request.
    #[clap(long ="certificate-signing-request-format", short = 'f', default_value="pem", value_parser(["pem", "der"]))]
    certificate_signing_request_format: String,

    /// The unique identifier of the private key of the issuer.
    /// A certificate must be linked to that private key
    #[clap(required = true, value_name = "ISSUER_PRIVATE_KEY_ID")]
    issuer_private_key_id: String,

    /// The requested number of validity days
    /// The server may grant a different value
    #[clap(long = "days", short = 'd', default_value = "365")]
    number_of_days: usize,

    /// The tag to associate to the certificate.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,
}

impl CertifyAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        // Providing a particular issuer is not provided by the KMIP protocol.
        // We use a vendor attribute to provide it.
        let mut vendor_attributes = vec![issuer_private_key_id_as_vendor_attribute(
            &self.issuer_private_key_id,
        )?];

        // A certificate id has been provided
        if let Some(certificate_id) = &self.certificate_id {
            vendor_attributes.push(certificate_id_as_vendor_attribute(certificate_id)?);
        }

        // The CSR
        let certificate_request_value =
            Some(read_bytes_from_file(&self.certificate_signing_request)?);
        let certificate_request_type = match self.certificate_signing_request_format.as_str() {
            "der" => Some(CertificateRequestType::PKCS10),
            _ => Some(CertificateRequestType::PEM),
        };

        // Request attributes with tags
        let mut attributes = Attributes {
            object_type: Some(ObjectType::Certificate),
            vendor_attributes: Some(vendor_attributes),
            ..Attributes::default()
        };
        set_tags(&mut attributes, &self.tags)?;

        let certify_request = Certify {
            unique_identifier: None, // not supported yet
            attributes: Some(attributes),
            certificate_request_value,
            certificate_request_type,
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

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
        ca_subject_common_names_as_vendor_attribute, certificate_id_as_vendor_attribute,
        subject_common_name_as_vendor_attribute,
    },
    tagging::set_tags,
};

use crate::{actions::shared::utils::read_bytes_from_file, error::CliError};

/// Create a new X509 certificate from parameters or a Certificate Signing Request (CSR).
///
/// When a CSR is provided, the KMS server will sign it with the CA private key.
/// When a CSR is not provided, the KMS server will generate a new X25519 keypair,
/// create a certificate with the provided Subject Common Name and sign it with the CA private key.
///
/// If the Certificate Authority certificates chain does not exist,
/// the corresponding certificates will be also created.
///
/// Tags can be later used to retrieve the key. Tags are optional.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateCertificateAction {
    /// The certificate unique identifier.
    /// A random one will be generated if not provided.
    #[clap(long = "certificate-id", short = 'k')]
    certificate_id: Option<String>,

    /// The Subject Common Names of the full Certificate Authority chain, separated by slashes (for example: CA/SubCA).
    /// If the certificates chain does not exist, the KMS server will create it.
    #[clap(required = true, name = "CA_SUBJECT_COMMON_NAMES")]
    ca_subject_common_names: String,

    /// The path to a certificate signing request..
    #[clap(long = "certificate_signing_request", short = 'c', group = "csr_or_cn")]
    certificate_signing_request: Option<PathBuf>,

    /// The format of the certificate signing request.
    #[clap(long ="certificate_signing_request_format", short = 'f', default_value="pem", value_parser(["pem", "der"]))]
    certificate_signing_request_format: String,

    /// The subject CN of the desired certificate when a CSR is not provided.
    /// A certificate will be created after generating a X25519 keypair
    #[clap(long = "subject_common_name", short = 's', group = "csr_or_cn")]
    subject_common_name: Option<String>,

    /// The tag to associate to the certificate.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,
}

impl CreateCertificateAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        // guard
        if self.subject_common_name.is_none() && self.certificate_signing_request.is_none() {
            return Err(CliError::UserError(
                "either a Subject Common Name or a Certificate Signing Request must be provided"
                    .to_string(),
            ))
        }

        // Since there is no place for CA Subject Common Name nor Certificate Subject Common Name in the `Certify` request,
        // those fields are placed in the vendors attributes.
        let mut vendor_attributes = vec![ca_subject_common_names_as_vendor_attribute(
            &self.ca_subject_common_names,
        )?];

        // A certificate id has been provided
        if let Some(certificate_id) = &self.certificate_id {
            vendor_attributes.push(certificate_id_as_vendor_attribute(&certificate_id)?);
        }

        // A Subject Common Name is provided.
        if let Some(subject_common_name) = &self.subject_common_name {
            vendor_attributes.push(subject_common_name_as_vendor_attribute(
                &subject_common_name,
            )?);
        }

        // A CSR is provided
        let (certificate_request_value, certificate_request_type) = if let Some(input_file) =
            &self.certificate_signing_request
        {
            let certificate_request_value = Some(read_bytes_from_file(input_file)?);
            let certificate_request_type = match self.certificate_signing_request_format.as_str() {
                "der" => Some(CertificateRequestType::PKCS10),
                _ => Some(CertificateRequestType::PEM),
            };
            (certificate_request_value, certificate_request_type)
        } else {
            (None, None)
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

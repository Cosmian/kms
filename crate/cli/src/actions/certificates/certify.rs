use std::path::PathBuf;

use clap::Parser;
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::Certify,
    kmip_types::{
        Attributes, CertificateAttributes, CertificateRequestType, LinkType,
        LinkedObjectIdentifier, UniqueIdentifier,
    },
};
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::tagging::set_tags;

use crate::{actions::shared::utils::read_bytes_from_file, error::CliError};

/// Certify a Certificate Signing Request or a Public key to create a X509 certificate.
///
/// Tags can be later used to retrieve the key. Tags are optional.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CertifyAction {
    /// The certificate unique identifier.
    /// A random one will be generated if not provided.
    #[clap(long = "certificate-id", short = 'i')]
    certificate_id: Option<String>,

    /// The path to a certificate signing request.
    #[clap(long = "certificate-signing-request", short = 'r', group = "csr_pk")]
    certificate_signing_request: Option<PathBuf>,

    /// The format of the certificate signing request.
    #[clap(long ="certificate-signing-request-format", short = 'f', default_value="pem", value_parser(["pem", "der"]))]
    certificate_signing_request_format: String,

    /// If not using a CSR, the id of the public key to certify
    #[clap(
        long = "public-key-id-to-certify",
        short = 'p',
        group = "csr_pk",
        requires = "subject_name"
    )]
    public_key_id_to_certify: Option<String>,

    /// When certifying a public key, the subject name to use
    ///
    /// For instance: "CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"
    #[clap(long = "subject-name", short = 's')]
    subject_name: Option<String>,

    /// The unique identifier of the private key of the issuer.
    /// A certificate must be linked to that private key
    /// if no issuer certificate id is provided.
    #[clap(long = "issuer-private-key-id", short = 'k')]
    issuer_private_key_id: Option<String>,

    /// The unique identifier of the certificate of the issuer.
    /// A private key must be linked to that certificate
    /// if no issuer private key id is provided.
    #[clap(long = "issuer-certificate-id", short = 'c')]
    issuer_certificate_id: Option<String>,

    /// The requested number of validity days
    /// The server may grant a different value
    #[clap(long = "days", short = 'd', default_value = "365")]
    number_of_days: usize,

    /// The path to a X509 extension's file, containing a `v3_ca` parag
    #[clap(long = "certificate-extensions", short = 'e')]
    certificate_extensions: Option<PathBuf>,

    /// The tag to associate to the certificate.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,
}

impl CertifyAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        if self.certificate_signing_request.is_none() && self.public_key_id_to_certify.is_none() {
            return Err(CliError::Default(
                "Either a certificate signing request or a public key to certify must be provided"
                    .to_string(),
            ))
        }

        if self.issuer_certificate_id.is_none() && self.issuer_private_key_id.is_none() {
            return Err(CliError::Default(
                "Either an issuer certificate id or an issuer private key id or both must be \
                 provided"
                    .to_string(),
            ))
        }

        let mut attributes = Attributes {
            object_type: Some(ObjectType::Certificate),
            ..Attributes::default()
        };

        // set the issuer certificate id
        if let Some(issuer_certificate_id) = &self.issuer_certificate_id {
            attributes.add_link(
                LinkType::CertificateLink,
                LinkedObjectIdentifier::TextString(issuer_certificate_id.clone()),
            );
        }

        // set the issuer private key id
        if let Some(issuer_private_key_id) = &self.issuer_private_key_id {
            attributes.add_link(
                LinkType::PrivateKeyLink,
                LinkedObjectIdentifier::TextString(issuer_private_key_id.clone()),
            );
        }

        // set the number of requested days
        attributes.set_requested_validity_days(self.number_of_days);

        // A certificate id has been provided
        if let Some(certificate_id) = &self.certificate_id {
            attributes.unique_identifier =
                Some(UniqueIdentifier::TextString(certificate_id.clone()));
        }

        set_tags(&mut attributes, &self.tags)?;

        // Using a CSR ?
        let (certificate_request_value, certificate_request_type) =
            if let Some(certificate_signing_request) = &self.certificate_signing_request {
                let certificate_request_value =
                    Some(read_bytes_from_file(certificate_signing_request)?);

                let certificate_request_type =
                    match self.certificate_signing_request_format.as_str() {
                        "der" => Some(CertificateRequestType::PKCS10),
                        _ => Some(CertificateRequestType::PEM),
                    };
                (certificate_request_value, certificate_request_type)
            } else {
                (None, None)
            };

        // Using a Public Key ?
        let unique_identifier = if let Some(public_key_to_certify) = &self.public_key_id_to_certify
        {
            attributes.certificate_attributes = Some(CertificateAttributes::parse_subject_line(
                self.subject_name.as_ref().ok_or_else(|| {
                    CliError::Default(
                        "subject name is required when certifying a public key".to_string(),
                    )
                })?,
            )?);
            Some(UniqueIdentifier::TextString(
                public_key_to_certify.to_string(),
            ))
        } else {
            None
        };

        if let Some(extension_file) = &self.certificate_extensions {
            attributes.set_x509_extension_file(std::fs::read(extension_file)?);
        }

        let certify_request = Certify {
            unique_identifier,
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

        println!("The certificate was issued with id: {certificate_unique_identifier}.");
        Ok(())
    }
}

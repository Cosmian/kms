use std::path::PathBuf;

use clap::Parser;
use cosmian_kmip::kmip::{kmip_objects::Object, kmip_types::CertificateType};
use cosmian_kms_client::KmsRestClient;
use openssl::x509::X509;
use tracing::{debug, trace};
use x509_parser::{nom::AsBytes, prelude::parse_x509_pem};

use crate::{
    actions::shared::utils::{import_object, read_bytes_from_file, read_key_from_file},
    error::CliError,
};

const MOZILLA_CCADB: &str =
    "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites";

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum CertificateInputFormat {
    TTLV,
    PEM,
    CHAIN,
    CCADB,
    PKCS12,
}

/// Import into the KMS database the following elements:
/// - a certificate (as PEM or TTLV format)
/// - a private key (as PEM or TTLV format)
/// - a certificate chain as a PEM-stack
/// - the Mozilla Common CA Database (CCADB). Automate the Mozilla database fetch.
///
/// The certificate can be in:
/// - KMIP JSON TTLV format
/// - PEM format
///
///
/// The private/public keys format is PEM format.
///
/// When no certificate unique id is specified, a random UUID v4 is generated.
///
/// Tags can later be used to retrieve the certificate. Tags are optional.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ImportCertificateAction {
    /// The input file in PEM or KMIP-JSON-TTLV format
    #[clap(required = false)]
    certificate_file: Option<PathBuf>,

    /// The unique id of the certificate; a random UUID v4 is generated if not specified
    #[clap(required = false)]
    certificate_id: Option<String>,

    /// Import the certificate in the selected format
    #[clap(long = "format", short = 'f')]
    input_format: CertificateInputFormat,

    /// PKCS12 password: only available for PKCS12 format
    #[clap(long = "pkcs12-password", short = 'p')]
    pkcs12_password: Option<String>,

    /// Unwrap the object if it is wrapped before storing it
    #[clap(
        long = "unwrap",
        short = 'u',
        required = false,
        default_value = "false"
    )]
    unwrap: bool,

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

        match self.input_format {
            CertificateInputFormat::TTLV => {
                trace!("CLI: import certificate as TTLV JSON file");
                // read the certificate file
                let object = read_key_from_file(self.get_certificate_file()?)?;
                trace!("CLI: read key from file OK");

                self.import(kms_rest_client, object, self.replace_existing)
                    .await?;
            }
            CertificateInputFormat::PEM => {
                debug!("CLI: import certificate as PEM file");
                let pem_value = read_bytes_from_file(&self.get_certificate_file()?)?;

                let (_, pem) = parse_x509_pem(&pem_value)?;

                let object = Object::Certificate {
                    certificate_type: CertificateType::X509,
                    certificate_value: pem.contents,
                };
                self.import(kms_rest_client, object, self.replace_existing)
                    .await?;
            }
            CertificateInputFormat::PKCS12 => {
                debug!("CLI: import certificate as PKCS12 file");
                let password = self
                    .pkcs12_password
                    .as_deref()
                    .ok_or(CliError::InvalidRequest("PKCS12 is required".to_string()))?;
                let pkcs12_bytes = read_bytes_from_file(&self.get_certificate_file()?)?;

                let pkcs12_parser = openssl::pkcs12::Pkcs12::from_der(&pkcs12_bytes)?;
                let pkcs12 = pkcs12_parser.parse2(password)?;

                // Import PKCS12 X509 certificate
                let object = Object::Certificate {
                    certificate_type: CertificateType::X509,
                    certificate_value: pkcs12
                        .cert
                        .ok_or_else(|| {
                            CliError::InvalidRequest(
                                "X509 certificate not found in PKCS12".to_string(),
                            )
                        })?
                        .to_der()?,
                };
                self.import(kms_rest_client, object, self.replace_existing)
                    .await?;
                // Import PKCS12 private key
                let object = Object::Certificate {
                    certificate_type: CertificateType::X509,
                    certificate_value: pkcs12
                        .pkey
                        .ok_or_else(|| {
                            CliError::InvalidRequest("Private key not found in PKCS12".to_string())
                        })?
                        .private_key_to_der()?,
                };
                self.import(kms_rest_client, object, self.replace_existing)
                    .await?;

                // Import PKCS12 chain
                let chain = pkcs12.ca.ok_or_else(|| {
                    CliError::InvalidRequest("CA Chain not found in PKCS12".to_string())
                })?;
                for x509 in chain {
                    let object = Object::Certificate {
                        certificate_type: CertificateType::X509,
                        certificate_value: x509.to_der()?,
                    };
                    self.import(kms_rest_client, object, self.replace_existing)
                        .await?;
                }
            }
            CertificateInputFormat::CHAIN => {
                debug!("CLI: import certificate chain as PEM file");
                let pem_value = read_bytes_from_file(&self.get_certificate_file()?)?;

                let stack = X509::stack_from_pem(&pem_value)?;
                for cert in stack {
                    let object = Object::Certificate {
                        certificate_type: CertificateType::X509,
                        certificate_value: cert.to_der()?,
                    };
                    self.import(kms_rest_client, object, self.replace_existing)
                        .await?;
                }
            }
            CertificateInputFormat::CCADB => {
                let ccadb_bytes = reqwest::get(MOZILLA_CCADB)
                    .await
                    .map_err(|e| {
                        CliError::ItemNotFound(format!(
                            "Cannot fetch Mozilla CCADB ({MOZILLA_CCADB:?}. Error: {e:?})",
                        ))
                    })?
                    .bytes()
                    .await
                    .map_err(|e| {
                        CliError::Conversion(format!(
                            "Cannot convert Mozilla CCADB content to bytes. Error: {e:?}"
                        ))
                    })?;

                //
                let stack = X509::stack_from_pem(ccadb_bytes.as_bytes())?;
                for cert in stack {
                    let object = Object::Certificate {
                        certificate_type: CertificateType::X509,
                        certificate_value: cert.to_der()?,
                    };
                    self.import(kms_rest_client, object, true).await?;
                }
            }
        };

        Ok(())
    }

    fn get_certificate_file(&self) -> Result<&PathBuf, CliError> {
        self.certificate_file
            .as_ref()
            .ok_or(CliError::InvalidRequest(format!(
                "Certificate file parameter is MANDATORY for {:?} format",
                self.input_format
            )))
    }

    async fn import(
        &self,
        kms_rest_client: &KmsRestClient,
        object: Object,
        replace_existing: bool,
    ) -> Result<(), CliError> {
        // import the certificate
        let unique_identifier = import_object(
            kms_rest_client,
            self.certificate_id.clone(),
            object,
            self.unwrap,
            replace_existing,
            &self.tags,
        )
        .await?;

        // print the response
        if let Some(cert_file) = &self.certificate_file {
            println!(
                "The certificate in file {:?} was imported with id: {}",
                &cert_file, unique_identifier,
            );
        } else {
            println!(
                "[{:?}] The certificate was imported with id: {}",
                self.input_format, unique_identifier,
            );
        }
        if !self.tags.is_empty() {
            println!("Tags:");
            for tag in &self.tags {
                println!("    - {tag}");
            }
        }

        Ok(())
    }
}

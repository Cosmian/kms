use std::path::PathBuf;

use clap::Parser;
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_types::{Attributes, CertificateType, LinkType, LinkedObjectIdentifier},
};
use cosmian_kms_client::KmsRestClient;
use der::{Decode, DecodePem, Encode, EncodePem};
use tracing::{debug, trace};
use x509_parser::nom::AsBytes;

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
    DER,
    CHAIN,
    CCADB,
    PKCS12,
}

/// Import into the KMS database one of the following:
/// - a certificate (in PEM, DER or JSON TTLV format)
/// - a certificate chain as a PEM-stack
/// - a PKCS12 file containing a certificate, a private key and possibly a chain
/// - the Mozilla Common CA Database (CCADB - fetched by the CLI before import)
///
/// When no certificate unique id is specified, a random UUID v4 is generated.
///
/// Tags can later be used to retrieve the certificate. Tags are optional.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ImportCertificateAction {
    /// The input file in PEM, KMIP-JSON-TTLV or PKCS#12 format.
    #[clap(
        required_if_eq_any([("input_format", "ttlv"), ("input_format", "pem"),("input_format", "der"), ("input_format", "chain"), ("input_format", "pkcs12")])
    )]
    certificate_file: Option<PathBuf>,

    /// The unique id of the leaf certificate; a random UUID v4 is generated if not specified.
    #[clap(required = false)]
    certificate_id: Option<String>,

    /// Import the certificate in the selected format.
    #[clap(long = "format", short = 'f')]
    input_format: CertificateInputFormat,

    /// PKCS12 password: only available for PKCS12 format.
    #[clap(long = "pkcs12-password", short = 'p')]
    pkcs12_password: Option<String>,

    /// Replace an existing certificate under the same id.
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
                self.import_chain(kms_rest_client, vec![object], self.replace_existing)
                    .await?;
            }
            CertificateInputFormat::PEM => {
                debug!("CLI: import certificate as PEM file");
                let pem_value = read_bytes_from_file(&self.get_certificate_file()?)?;
                // convert the PEM to X509 to make sure it is correct
                let certificate = Certificate::from_pem(&pem_value).map_err(|e| {
                    CliError::Conversion(format!("Cannot read PEM content to X509. Error: {e:?}"))
                })?;
                let object = Object::Certificate {
                    certificate_type: CertificateType::X509,
                    // TODO: change to DER: https://github.com/Cosmian/kms/issues/72
                    certificate_value: certificate.to_pem(der::pem::LineEnding::LF)?.into_bytes(),
                };
                self.import_chain(kms_rest_client, vec![object], self.replace_existing)
                    .await?;
            }
            CertificateInputFormat::DER => {
                debug!("CLI: import certificate as PEM file");
                let der_value = read_bytes_from_file(&self.get_certificate_file()?)?;
                // convert DER to X509 to make sure it is correct
                let certificate = Certificate::from_der(&der_value).map_err(|e| {
                    CliError::Conversion(format!("Cannot read DER content to X509. Error: {e:?}"))
                })?;
                let object = Object::Certificate {
                    certificate_type: CertificateType::X509,
                    // TODO: change to DER: https://github.com/Cosmian/kms/issues/72
                    certificate_value: certificate.to_pem(der::pem::LineEnding::LF)?.into_bytes(),
                };
                self.import_chain(kms_rest_client, vec![object], self.replace_existing)
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
                let leaf_certificate = Object::Certificate {
                    certificate_type: CertificateType::X509,
                    // TODO: change to DER: https://github.com/Cosmian/kms/issues/72
                    certificate_value: pkcs12
                        .cert
                        .ok_or_else(|| {
                            CliError::InvalidRequest(
                                "X509 certificate not found in PKCS12".to_string(),
                            )
                        })?
                        .to_pem()?,
                };
                let mut objects = vec![leaf_certificate];
                //add the chain if any
                if let Some(chain) = pkcs12.ca {
                    for x509 in chain {
                        let object = Object::Certificate {
                            certificate_type: CertificateType::X509,
                            // TODO: change to DER: https://github.com/Cosmian/kms/issues/72
                            certificate_value: x509.to_pem()?,
                        };
                        objects.push(object);
                    }
                }
                // import the full chain
                self.import_chain(kms_rest_client, objects, self.replace_existing)
                    .await?;
                // Import PKCS12 private key
                // let object = Object::Certificate {
                //     certificate_type: CertificateType::X509,
                //     certificate_value: pkcs12
                //         .pkey
                //         .ok_or_else(|| {
                //             CliError::InvalidRequest("Private key not found in PKCS12".to_string())
                //         })?
                //         .private_key_to_pem_pkcs8()?,
                // };
                // self.import(kms_rest_client, object, self.replace_existing)
                //     .await?;
            }
            CertificateInputFormat::CHAIN => {
                debug!("CLI: import certificate chain as PEM file");
                let pem_stack = read_bytes_from_file(&self.get_certificate_file()?)?;
                let objects = build_chain_from_stack(&pem_stack)?;
                // import the full chain
                self.import_chain(kms_rest_client, objects, self.replace_existing)
                    .await?;
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

                // import the certificates
                let objects = build_chain_from_stack(&ccadb_bytes)?;
                self.import_chain(kms_rest_client, objects, self.replace_existing)
                    .await?;
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

    /// Import the certificates in reverse order (from root to leaf)
    /// linking the child to the parent with `Link` of `LinkType::CertificateLink`
    async fn import_chain(
        &self,
        kms_rest_client: &KmsRestClient,
        mut objects: Vec<Object>,
        replace_existing: bool,
    ) -> Result<(), CliError> {
        let mut previous_identifier: Option<String> = None;
        loop {
            let object = match objects.pop() {
                Some(o) => o,
                None => return Ok(()),
            };
            let import_attributes = previous_identifier.map(|id| {
                let mut attributes = Attributes::default();
                attributes.add_link(
                    LinkType::CertificateLink,
                    LinkedObjectIdentifier::TextString(id.to_owned()),
                );
                attributes
            });
            // import the certificate
            let unique_identifier = import_object(
                kms_rest_client,
                self.certificate_id.clone(),
                object,
                import_attributes,
                false,
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
            previous_identifier = Some(unique_identifier);
        }
    }
}

fn build_chain_from_stack(pem_chain: &[u8]) -> Result<Vec<Object>, CliError> {
    let certs_string = String::from_utf8(pem_chain.to_vec())?;
    // split the certificates using the PEM headers `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----`
    let certs: Vec<&str> = certs_string.split("-----END CERTIFICATE-----").collect();
    let mut objects = vec![];
    for cert in certs {
        // (re)add the PEM footer
        let cert = format!("{}-----END CERTIFICATE-----", cert);
        // convert the PEM to X509 to make sure it is correct
        let certificate = Certificate::from_pem(cert.as_bytes()).map_err(|e| {
            CliError::Conversion(format!("Cannot read PEM content to X509. Error: {e:?}"))
        })?;
        let object = Object::Certificate {
            certificate_type: CertificateType::X509,
            certificate_value: certificate.to_der()?,
        };
        objects.push(object);
    }
    Ok(objects)
}

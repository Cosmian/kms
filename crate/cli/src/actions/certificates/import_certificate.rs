use std::path::PathBuf;

use clap::Parser;
use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_types::{
        Attributes, CertificateType, CryptographicAlgorithm, CryptographicDomainParameters,
        CryptographicUsageMask, KeyFormatType, RecommendedCurve,
    },
};
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::curve_25519::operation::Q_LENGTH_BITS;
use openssl::{
    ec::EcKey,
    nid::Nid,
    pkey::{Id, PKey},
};
use tracing::{debug, trace};
use x509_parser::prelude::parse_x509_pem;

use crate::{
    actions::shared::utils::{import_object, read_bytes_from_file, read_key_from_file},
    cli_bail,
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
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        debug!("CLI: entering import certificate");
        let unique_identifier = match self.input_format {
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

                // import the certificate
                import_object(
                    client_connector,
                    self.certificate_id.clone(),
                    object,
                    false,
                    self.replace_existing,
                    &self.tags,
                )
                .await?
            }
            CertificateInputFormat::PEM => {
                debug!("CLI: import certificate as PEM file");
                let pem_value = read_bytes_from_file(&self.certificate_file)?;

                let (_, pem) = parse_x509_pem(&pem_value)?;

                let object = if pem.label == "CERTIFICATE" {
                    debug!("CLI: parsing certificate: {}", pem.label);
                    Object::Certificate {
                        certificate_type: CertificateType::X509,
                        certificate_value: pem_value,
                    }
                } else if pem.label.contains("PRIVATE KEY") {
                    debug!("CLI: parsing private key: {}", pem.label);
                    let pkey = PKey::private_key_from_pem(&pem_value)?;
                    match pkey.id() {
                        Id::EC => {
                            debug!("CLI: parsing private key with PKey: {:?}", pkey);
                            let private_key = EcKey::private_key_from_der(&pem.contents)?;
                            debug!("CLI: convert private key to EcKey");
                            let recommended_curve = match private_key.group().curve_name() {
                                Some(nid) => match nid {
                                    Nid::X9_62_PRIME192V1 => RecommendedCurve::P192,
                                    Nid::SECP224R1 => RecommendedCurve::P224,
                                    Nid::X9_62_PRIME256V1 => RecommendedCurve::P256,
                                    Nid::SECP384R1 => RecommendedCurve::P384,
                                    _ => {
                                        cli_bail!(
                                            "Elliptic curve not supported: {}",
                                            nid.long_name()?
                                        );
                                    }
                                },
                                None => cli_bail!("No curve name for this EC curve"),
                            };
                            let private_key_bytes = private_key.private_key().to_vec();
                            debug!("CLI: private_key_bytes len: {}", private_key_bytes.len());
                            get_private_key_object(private_key_bytes, recommended_curve)
                        }
                        Id::ED25519 => {
                            let private_key_bytes = pkey.raw_private_key()?;
                            get_private_key_object(
                                private_key_bytes,
                                RecommendedCurve::CURVEED25519,
                            )
                        }
                        Id::X25519 => {
                            let private_key_bytes = pkey.raw_private_key()?;
                            get_private_key_object(private_key_bytes, RecommendedCurve::CURVE25519)
                        }
                        _ => cli_bail!("Private key id not supported: {:?}", pkey.id()),
                    }
                } else {
                    cli_bail!("Unsupported PEM format: found {}", pem.label);
                };

                // import the certificate
                import_object(
                    client_connector,
                    self.certificate_id.clone(),
                    object,
                    false,
                    self.replace_existing,
                    &self.tags,
                )
                .await?
            }
        };

        // print the response
        println!(
            "The certificate in file {:?} was imported with id: {}",
            &self.certificate_file, unique_identifier,
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

fn get_private_key_object(
    private_key_bytes: Vec<u8>,
    recommended_curve: RecommendedCurve,
) -> Object {
    Object::PrivateKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentECPrivateKey,
            key_value: KeyValue {
                key_material: KeyMaterial::ByteString(private_key_bytes),
                attributes: Some(Attributes {
                    activation_date: None,
                    cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                    cryptographic_length: Some(Q_LENGTH_BITS),
                    cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                        q_length: Some(Q_LENGTH_BITS),
                        recommended_curve: Some(recommended_curve),
                    }),
                    cryptographic_parameters: None,
                    cryptographic_usage_mask: Some(
                        CryptographicUsageMask::Encrypt
                            | CryptographicUsageMask::Decrypt
                            | CryptographicUsageMask::WrapKey
                            | CryptographicUsageMask::UnwrapKey
                            | CryptographicUsageMask::KeyAgreement,
                    ),
                    key_format_type: Some(KeyFormatType::ECPrivateKey),
                    link: None,
                    object_type: Some(ObjectType::PrivateKey),
                    vendor_attributes: None,
                }),
            },
            cryptographic_algorithm: CryptographicAlgorithm::ECDH,
            cryptographic_length: Q_LENGTH_BITS,
            key_compression_type: None,
            key_wrapping_data: None,
        },
    }
}

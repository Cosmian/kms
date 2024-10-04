use std::{
    fmt::{Display, Formatter},
    path::PathBuf,
};

use clap::{Parser, ValueEnum};
use cosmian_kms_client::{
    cosmian_kmip::kmip::{
        kmip_objects::ObjectType,
        kmip_operations::Certify,
        kmip_types::{
            Attributes, CertificateAttributes, CertificateRequestType, LinkType,
            LinkedObjectIdentifier, UniqueIdentifier,
        },
    },
    kmip::kmip_types::{
        CryptographicAlgorithm, CryptographicDomainParameters, KeyFormatType, RecommendedCurve,
    },
    read_bytes_from_file, KmsClient,
};

use crate::{
    actions::console,
    error::{result::CliResult, CliError},
};

/// The algorithm to use for the keypair generation
#[derive(ValueEnum, Debug, Clone, Copy)]
pub(crate) enum Algorithm {
    #[cfg(not(feature = "fips"))]
    NistP192,
    NistP224,
    NistP256,
    NistP384,
    NistP521,
    #[cfg(not(feature = "fips"))]
    X25519,
    #[cfg(not(feature = "fips"))]
    Ed25519,
    #[cfg(not(feature = "fips"))]
    X448,
    #[cfg(not(feature = "fips"))]
    Ed448,
    #[cfg(not(feature = "fips"))]
    RSA1024,
    RSA2048,
    RSA3072,
    RSA4096,
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(not(feature = "fips"))]
            Self::NistP192 => write!(f, "nist-p192"),
            Self::NistP224 => write!(f, "nist-p224"),
            Self::NistP256 => write!(f, "nist-p256"),
            Self::NistP384 => write!(f, "nist-p384"),
            Self::NistP521 => write!(f, "nist-p521"),
            #[cfg(not(feature = "fips"))]
            Self::X25519 => write!(f, "x25519"),
            #[cfg(not(feature = "fips"))]
            Self::Ed25519 => write!(f, "ed25519"),
            #[cfg(not(feature = "fips"))]
            Self::X448 => write!(f, "x448"),
            #[cfg(not(feature = "fips"))]
            Self::Ed448 => write!(f, "ed448"),
            #[cfg(not(feature = "fips"))]
            Self::RSA1024 => write!(f, "rsa1024"),
            Self::RSA2048 => write!(f, "rsa2048"),
            Self::RSA3072 => write!(f, "rsa3072"),
            Self::RSA4096 => write!(f, "rsa4096"),
        }
    }
}

/// Issue or renew a X509 certificate
///
/// There are 4 possibilities to generate a certificate
/// 1. Provide a Certificate Signing Request (CSR)
///    using -certificate-signing-request
/// 2. Provide a public key id to certify
///    using -public-key-id-to-certify as well as a subject name
/// 3. Provide the id of an existing certificate to re-certify
///    using -certificate-id-to-re-certify
/// 4. Generate a keypair then sign the public key to generate a certificate
///    using -generate-key-pair as well as a subject name and an algorithm
///
/// The signer (issuer) is specified by providing
///  - an issuer private key id using -issuer-private-key-id
///  - and/or an issuer certificate id using -issuer-certificate-id.
///
/// If only one of this parameter is specified, the other one will be inferred
/// from the links of the cryptographic object behind the provided parameter.
///
/// If no signer is provided, the certificate will be self-signed.
/// It is not possible to self-sign a CSR.
///
/// When re-certifying a certificate, if no --certificate-id is provided,
/// the original certificate id will be used and the original certificate will
/// be replaced by the new one. In all other cases, a random certificate id
/// will be generated.
///
/// Tags can be later used to retrieve the certificate. Tags are optional.
///
/// Examples:
///
/// 1. Generate a self-signed certificate with 10 years validity using curve (NIST) P-256
///```sh
///ckms certificates certify --certificate-id acme_root_ca \
///--generate-key-pair --algorithm nist-p256  \
///--subject-name "CN=ACME Root CA,OU=IT,O=ACME,L=New York,ST=New York,C=US" \
///--days 3650
///```
///
/// 2. Generate an intermediate CA certificate signed by the root CA and using
///    some x509 extensions. The root CA certificate and private key are already in the KMS.
///    The Root CA (issuer) private key id is 1bba3cfa-4ecb-47ad-a9cf-7a2c236e25a8
///    and the x509 extensions are in the file intermediate.ext containing a `v3_ca` paragraph:
///
///```text
///  [ v3_ca ]
///  basicConstraints=CA:TRUE,pathlen:0
///  keyUsage=keyCertSign,digitalSignature
///  extendedKeyUsage=emailProtection
///  crlDistributionPoints=URI:https://acme.com/crl.pem
/// ```
///
/// ```sh
/// ckms -- certificates certify --certificate-id acme_intermediate_ca \
/// --issuer-private-key-id 1bba3cfa-4ecb-47ad-a9cf-7a2c236e25a8 \
/// --generate-key-pair --algorithm nist-p256  \
/// --subject-name "CN=ACME S/MIME intermediate,OU=IT,O=ACME,L=New York,ST=New York,C=US" \
/// --days 1825 \
/// --certificate-extensions intermediate.ext
/// ```
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CertifyAction {
    /// The unique identifier of the certificate to issue or renew.
    /// If not provided, a random one will be generated when issuing a certificate,
    /// or the original one will be used when renewing a certificate.
    #[clap(long = "certificate-id", short = 'c')]
    certificate_id: Option<String>,

    /// The path to a certificate signing request.
    #[clap(
        long = "certificate-signing-request",
        short = 'r',
        group = "csr_pk",
        required = false
    )]
    certificate_signing_request: Option<PathBuf>,

    /// The format of the certificate signing request.
    #[clap(long ="certificate-signing-request-format", short = 'f', default_value="pem", value_parser(["pem", "der"]))]
    certificate_signing_request_format: String,

    /// The id of a public key to certify
    #[clap(
        long = "public-key-id-to-certify",
        short = 'p',
        group = "csr_pk",
        requires = "subject_name",
        required = false
    )]
    public_key_id_to_certify: Option<String>,

    /// The id of a certificate to re-certify
    #[clap(
        long = "certificate-id-to-re-certify",
        short = 'n',
        group = "csr_pk",
        required = false
    )]
    certificate_id_to_re_certify: Option<String>,

    /// Generate a keypair then sign the public key
    /// and generate a certificate
    #[clap(
        long = "generate-key-pair",
        short = 'g',
        group = "csr_pk",
        requires = "subject_name",
        requires = "algorithm",
        required = false
    )]
    generate_key_pair: bool,

    /// When certifying a public key, or generating a keypair,
    /// the subject name to use.
    ///
    /// For instance: "CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"
    #[clap(long = "subject-name", short = 's', verbatim_doc_comment)]
    subject_name: Option<String>,

    /// The algorithm to use for the keypair generation
    #[clap(long = "algorithm", short = 'a', default_value = "rsa4096")]
    algorithm: Algorithm,

    /// The unique identifier of the private key of the issuer.
    /// A certificate must be linked to that private key
    /// if no issuer certificate id is provided.
    #[clap(long = "issuer-private-key-id", short = 'k')]
    issuer_private_key_id: Option<String>,

    /// The unique identifier of the certificate of the issuer.
    /// A private key must be linked to that certificate
    /// if no issuer private key id is provided.
    #[clap(long = "issuer-certificate-id", short = 'i')]
    issuer_certificate_id: Option<String>,

    /// The requested number of validity days
    /// The server may grant a different value
    #[clap(long = "days", short = 'd', default_value = "365")]
    number_of_days: usize,

    /// The path to a X509 extension's file, containing a `v3_ca` paragraph
    /// with the x509 extensions to use. For instance:
    ///
    /// ```text
    /// [ v3_ca ]
    /// basicConstraints=CA:TRUE,pathlen:0
    /// keyUsage=keyCertSign,digitalSignature
    /// extendedKeyUsage=emailProtection
    /// crlDistributionPoints=URI:https://acme.com/crl.pem
    /// ```
    #[clap(long = "certificate-extensions", short = 'e', verbatim_doc_comment)]
    certificate_extensions: Option<PathBuf>,

    /// The tag to associate to the certificate.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,
}

impl CertifyAction {
    pub async fn run(&self, client_connector: &KmsClient) -> CliResult<()> {
        let mut attributes = Attributes {
            object_type: Some(ObjectType::Certificate),
            ..Attributes::default()
        };

        // set the issuer certificate id
        if let Some(issuer_certificate_id) = &self.issuer_certificate_id {
            attributes.set_link(
                LinkType::CertificateLink,
                LinkedObjectIdentifier::TextString(issuer_certificate_id.clone()),
            );
        }

        // set the issuer private key id
        if let Some(issuer_private_key_id) = &self.issuer_private_key_id {
            attributes.set_link(
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

        attributes.set_tags(&self.tags)?;

        let mut certificate_request_value = None;
        let mut certificate_request_type = None;
        let mut unique_identifier = None;

        if let Some(certificate_signing_request) = &self.certificate_signing_request {
            certificate_request_value = Some(read_bytes_from_file(certificate_signing_request)?);
            certificate_request_type = match self.certificate_signing_request_format.as_str() {
                "der" => Some(CertificateRequestType::PKCS10),
                _ => Some(CertificateRequestType::PEM),
            };
        } else if let Some(public_key_to_certify) = &self.public_key_id_to_certify {
            attributes.certificate_attributes =
                Some(Box::new(CertificateAttributes::parse_subject_line(
                    self.subject_name.as_ref().ok_or_else(|| {
                        CliError::Default(
                            "subject name is required when certifying a public key".to_owned(),
                        )
                    })?,
                )?));
            unique_identifier = Some(UniqueIdentifier::TextString(
                public_key_to_certify.to_string(),
            ));
        } else if let Some(certificate_id_to_renew) = &self.certificate_id_to_re_certify {
            unique_identifier = Some(UniqueIdentifier::TextString(
                certificate_id_to_renew.clone(),
            ));
        } else if self.generate_key_pair {
            attributes.certificate_attributes =
                Some(Box::new(CertificateAttributes::parse_subject_line(
                    self.subject_name.as_ref().ok_or_else(|| {
                        CliError::Default(
                            "subject name is required when generating a keypair".to_owned(),
                        )
                    })?,
                )?));
            match self.algorithm {
                #[cfg(not(feature = "fips"))]
                Algorithm::RSA1024 => {
                    rsa_algorithm(&mut attributes, 1024);
                }
                Algorithm::RSA2048 => {
                    rsa_algorithm(&mut attributes, 2048);
                }
                Algorithm::RSA3072 => {
                    rsa_algorithm(&mut attributes, 3072);
                }
                Algorithm::RSA4096 => {
                    rsa_algorithm(&mut attributes, 4096);
                }
                #[cfg(not(feature = "fips"))]
                Algorithm::NistP192 => {
                    ec_algorithm(
                        &mut attributes,
                        CryptographicAlgorithm::EC,
                        RecommendedCurve::P192,
                    );
                }
                Algorithm::NistP224 => {
                    ec_algorithm(
                        &mut attributes,
                        CryptographicAlgorithm::EC,
                        RecommendedCurve::P224,
                    );
                }
                Algorithm::NistP256 => {
                    ec_algorithm(
                        &mut attributes,
                        CryptographicAlgorithm::EC,
                        RecommendedCurve::P256,
                    );
                }
                Algorithm::NistP384 => {
                    ec_algorithm(
                        &mut attributes,
                        CryptographicAlgorithm::EC,
                        RecommendedCurve::P384,
                    );
                }
                Algorithm::NistP521 => {
                    ec_algorithm(
                        &mut attributes,
                        CryptographicAlgorithm::EC,
                        RecommendedCurve::P521,
                    );
                }
                #[cfg(not(feature = "fips"))]
                Algorithm::X25519 => {
                    ec_algorithm(
                        &mut attributes,
                        CryptographicAlgorithm::EC,
                        RecommendedCurve::CURVE25519,
                    );
                }
                #[cfg(not(feature = "fips"))]
                Algorithm::Ed25519 => {
                    ec_algorithm(
                        &mut attributes,
                        CryptographicAlgorithm::Ed25519,
                        RecommendedCurve::CURVEED25519,
                    );
                }
                #[cfg(not(feature = "fips"))]
                Algorithm::X448 => {
                    ec_algorithm(
                        &mut attributes,
                        CryptographicAlgorithm::EC,
                        RecommendedCurve::CURVE448,
                    );
                }
                #[cfg(not(feature = "fips"))]
                Algorithm::Ed448 => {
                    ec_algorithm(
                        &mut attributes,
                        CryptographicAlgorithm::Ed448,
                        RecommendedCurve::CURVEED448,
                    );
                }
            }
        } else {
            return Err(CliError::Default(
                "Supply a certificate signing request, a public key id or an existing certificate \
                 id or request a keypair to be generated"
                    .to_string(),
            ));
        }

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
            .map_err(|e| CliError::ServerError(format!("failed creating certificate: {e:?}")))?
            .unique_identifier;

        let mut stdout = console::Stdout::new("The certificate was successfully generated.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_unique_identifier(certificate_unique_identifier);
        stdout.write()?;

        Ok(())
    }
}

fn ec_algorithm(
    attributes: &mut Attributes,
    cryptographic_algorithm: CryptographicAlgorithm,
    recommended_curve: RecommendedCurve,
) {
    attributes.cryptographic_algorithm = Some(cryptographic_algorithm);
    attributes.cryptographic_domain_parameters = Some(CryptographicDomainParameters {
        recommended_curve: Some(recommended_curve),
        ..CryptographicDomainParameters::default()
    });
    attributes.key_format_type = Some(KeyFormatType::ECPrivateKey);
    attributes.object_type = Some(ObjectType::PrivateKey);
}

fn rsa_algorithm(attributes: &mut Attributes, cryptographic_length: i32) {
    attributes.cryptographic_algorithm = Some(CryptographicAlgorithm::RSA);
    attributes.cryptographic_length = Some(cryptographic_length);
    attributes.cryptographic_domain_parameters = None;
    attributes.cryptographic_parameters = None;
    attributes.key_format_type = Some(KeyFormatType::TransparentRSAPrivateKey);
    attributes.object_type = Some(ObjectType::PrivateKey);
}

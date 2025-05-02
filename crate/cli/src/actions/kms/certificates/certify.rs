use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::kmip_types::UniqueIdentifier,
    read_bytes_from_file,
    reexport::cosmian_kms_client_utils::certificate_utils::{Algorithm, build_certify_request},
};

use crate::{
    actions::kms::{
        console,
        labels::{CERTIFICATE_ID, CERTIFICATE_RECERTIFY},
    },
    error::{KmsCliError, result::KmsCliResult},
};

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
///cosmian kms certificates certify --certificate-id acme_root_ca \
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
/// cosmian kms -- certificates certify --certificate-id acme_intermediate_ca \
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
    #[clap(long = CERTIFICATE_ID, short = 'c')]
    pub(crate) certificate_id: Option<String>,

    /// The path to a certificate signing request.
    #[clap(
        long = "certificate-signing-request",
        short = 'r',
        group = "csr_pk",
        required = false
    )]
    pub(crate) certificate_signing_request: Option<PathBuf>,

    /// The format of the certificate signing request.
    #[clap(long ="certificate-signing-request-format", short = 'f', default_value="pem", value_parser(["pem", "der"]))]
    pub(crate) certificate_signing_request_format: String,

    /// The id of a public key to certify
    #[clap(
        long = "public-key-id-to-certify",
        short = 'p',
        group = "csr_pk",
        requires = "subject_name",
        required = false
    )]
    pub(crate) public_key_id_to_certify: Option<String>,

    /// The id of a certificate to re-certify
    #[clap(
        long = CERTIFICATE_RECERTIFY,
        short = 'n',
        group = "csr_pk",
        required = false
    )]
    pub(crate) certificate_id_to_re_certify: Option<String>,

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
    pub(crate) generate_key_pair: bool,

    /// When certifying a public key, or generating a keypair,
    /// the subject name to use.
    ///
    /// For instance: "CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"
    #[clap(long = "subject-name", short = 's', verbatim_doc_comment)]
    pub(crate) subject_name: Option<String>,

    /// The algorithm to use for the keypair generation
    #[clap(long = "algorithm", short = 'a', default_value = "rsa4096")]
    pub(crate) algorithm: Algorithm,

    /// The unique identifier of the private key of the issuer.
    /// A certificate must be linked to that private key
    /// if no issuer certificate id is provided.
    #[clap(long = "issuer-private-key-id", short = 'k')]
    pub(crate) issuer_private_key_id: Option<String>,

    /// The unique identifier of the certificate of the issuer.
    /// A private key must be linked to that certificate
    /// if no issuer private key id is provided.
    #[clap(long = "issuer-certificate-id", short = 'i')]
    pub(crate) issuer_certificate_id: Option<String>,

    /// The requested number of validity days
    /// The server may grant a different value
    #[clap(long = "days", short = 'd', default_value = "365")]
    pub(crate) number_of_days: usize,

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
    pub(crate) certificate_extensions: Option<PathBuf>,

    /// The tag to associate to the certificate.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    pub(crate) tags: Vec<String>,
}

impl Default for CertifyAction {
    fn default() -> Self {
        Self {
            certificate_id: None,
            certificate_signing_request: None,
            certificate_signing_request_format: "pem".to_string(),
            public_key_id_to_certify: None,
            certificate_id_to_re_certify: None,
            generate_key_pair: false,
            subject_name: None,
            algorithm: Algorithm::RSA4096,
            issuer_private_key_id: None,
            issuer_certificate_id: None,
            number_of_days: 365,
            certificate_extensions: None,
            tags: vec![],
        }
    }
}

impl CertifyAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let certificate_signing_request_bytes = self
            .certificate_signing_request
            .as_ref()
            .map(read_bytes_from_file)
            .transpose()?;

        let certificate_extensions_bytes = self
            .certificate_extensions
            .as_ref()
            .map(std::fs::read)
            .transpose()?;

        let certify_request = build_certify_request(
            &self.certificate_id,
            &Some(self.certificate_signing_request_format.clone()),
            &certificate_signing_request_bytes,
            &self.public_key_id_to_certify,
            &self.certificate_id_to_re_certify,
            self.generate_key_pair,
            &self.subject_name,
            self.algorithm,
            &self.issuer_private_key_id,
            &self.issuer_certificate_id,
            self.number_of_days,
            &certificate_extensions_bytes,
            &self.tags,
        )?;

        let certificate_unique_identifier = kms_rest_client
            .certify(certify_request)
            .await
            .map_err(|e| KmsCliError::ServerError(format!("failed creating certificate: {e:?}")))?
            .unique_identifier;

        let mut stdout = console::Stdout::new("The certificate was successfully generated.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_unique_identifier(&certificate_unique_identifier);
        stdout.write()?;

        Ok(certificate_unique_identifier)
    }
}

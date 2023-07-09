use std::path::PathBuf;

use clap::Parser;
use cosmian_crypto_core::{
    reexport::pkcs8::{der::pem::PemLabel, EncodePrivateKey, LineEnding, PrivateKeyInfo},
    X25519Keypair, X25519PrivateKey, X25519PublicKey, CURVE_25519_SECRET_LENGTH,
    X25519_PUBLIC_KEY_LENGTH,
};
use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType},
};
use cosmian_kms_client::KmsRestClient;
use openssl::{pkey::PKey, stack::Stack, x509::X509};
use tracing::trace;

use super::{locate::locate_ca_cert, locate_and_get_key_bytes};
use crate::{
    actions::shared::utils::{export_object, write_bytes_to_file, write_kmip_object_to_file},
    cli_bail,
    error::CliError,
};

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum CertificateExportFormat {
    TTLV,
    PEM,
    PKCS12,
}

/// Export a certificate from the KMS
///
/// The certificate is exported either:
/// - in PEM format
/// - in PKCS12 format including private key and certificate file
/// - in TTLV JSON KMIP format
///
/// When using tags to retrieve the certificate, rather than the certificate id,
/// an error is returned if multiple certificates matching the tags are found.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ExportCertificateAction {
    /// The file to export the certificate to
    #[clap(required = true)]
    certificate_file: PathBuf,

    /// The certificate unique identifier stored in the KMS.
    /// If not specified, tags should be specified
    #[clap(long = "certificate-id", short = 'k', group = "certificate-tags")]
    certificate_id: Option<String>,

    /// Tag to use to retrieve the certificate when no certificate id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(
        long = "tag",
        short = 't',
        value_name = "TAG",
        group = "certificate-tags"
    )]
    tags: Option<Vec<String>>,

    /// Export the certificate in the selected format
    #[clap(long = "format", short = 'f')]
    output_format: CertificateExportFormat,

    /// Export the certificate in PKCS12 format and protect the private key using this password
    #[clap(long = "pkcs12_password", short = 'p')]
    pkcs12_password: Option<String>,

    /// Allow exporting revoked and destroyed certificates.
    /// The user must be the owner of the certificate.
    /// Destroyed certificates have their certificate material removed.
    #[clap(long = "allow-revoked", short = 'i', default_value = "false")]
    allow_revoked: bool,
}

impl ExportCertificateAction {
    /// Export a certificate from the KMS
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        trace!("Export certificate: {:?}", self);

        let certificate_uid: String = if let Some(certificate_id) = &self.certificate_id {
            certificate_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either `--certificate-id` or one or more `--tag` must be specified")
        };

        // export the object
        let object = export_object(
            client_connector,
            &certificate_uid,
            false,
            None,
            self.allow_revoked,
        )
        .await?;

        let certificate_bytes = match &object {
            Object::Certificate {
                certificate_value, ..
            } => certificate_value,
            _ => {
                cli_bail!(
                    "The object {} is not a certificate but a {}",
                    &certificate_uid,
                    object.object_type()
                );
            }
        };

        // write the object to a file
        match self.output_format {
            CertificateExportFormat::TTLV => {
                // save it to a file
                write_kmip_object_to_file(&object, &self.certificate_file)?;
            }
            CertificateExportFormat::PEM => {
                // save it to a file
                write_bytes_to_file(certificate_bytes, &self.certificate_file)?;
            }
            CertificateExportFormat::PKCS12 => {
                let password = self.pkcs12_password.clone().ok_or(CliError::Cryptographic(
                    "PKCS12 password is required".to_string(),
                ))?;
                let pkcs12_bytes = create_pkcs12(
                    client_connector,
                    certificate_bytes,
                    &certificate_uid,
                    &password,
                )
                .await?;
                write_bytes_to_file(&pkcs12_bytes, &self.certificate_file)?;
            }
        };

        println!(
            "The certificate {} of type {} was exported to {:?}",
            &certificate_uid,
            object.object_type(),
            &self.certificate_file
        );
        Ok(())
    }
}

/// Locate the related public key and private key matching the certificate unique identifier
/// Then rebuild the corresponding key pair
///
/// # Errors
///
/// This function will return an error if:
/// - no key is found for the unique identifier
/// - if keys found in server are not X25519 keys.
async fn rebuild_key_pair(
    client_connector: &KmsRestClient,
    certificate_uid: &str,
) -> Result<X25519Keypair, CliError> {
    let private_key = locate_and_get_key_bytes::<CURVE_25519_SECRET_LENGTH>(
        client_connector,
        certificate_uid,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
            key_format_type: Some(KeyFormatType::TransparentECPrivateKey),
            object_type: Some(ObjectType::PrivateKey),
            ..Attributes::default()
        },
    )
    .await?;
    let public_key = locate_and_get_key_bytes::<X25519_PUBLIC_KEY_LENGTH>(
        client_connector,
        certificate_uid,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
            key_format_type: Some(KeyFormatType::TransparentECPublicKey),
            object_type: Some(ObjectType::PublicKey),
            ..Attributes::default()
        },
    )
    .await?;

    let key_pair = X25519Keypair {
        private_key: X25519PrivateKey::try_from_bytes(private_key)?,
        public_key: X25519PublicKey::try_from_bytes(public_key)?,
    };
    Ok(key_pair)
}

/// .
///
/// # Errors
///
/// This function will return an error if retrieving or parsing x509 fails
async fn create_pkcs12(
    client_connector: &KmsRestClient,
    certificate_bytes: &[u8],
    certificate_uid: &str,
    password: &str,
) -> Result<Vec<u8>, CliError> {
    // Build the key pair to PKCS8 encode the private key. TODO(ECSE): should be done only with the private key
    let key_pair = rebuild_key_pair(client_connector, certificate_uid).await?;
    let private_key_as_pem = key_pair
        .to_pkcs8_der()?
        .to_pem(PrivateKeyInfo::PEM_LABEL, LineEnding::LF)?;

    // Create PKCS12 using Rust-OpenSSL
    let pkey = PKey::private_key_from_pem(private_key_as_pem.as_bytes())?;
    let cert = X509::from_pem(certificate_bytes)?;
    let mut cas = Stack::<X509>::new()?;
    for ca_issuer_name in cert.issuer_name().entries() {
        let pem = locate_ca_cert(
            client_connector,
            ca_issuer_name.data().as_utf8()?.as_ref(),
            &Attributes {
                object_type: Some(ObjectType::Certificate),
                ..Attributes::default()
            },
        )
        .await?;
        let cert = X509::from_pem(&pem)?;
        cas.push(cert)?;
    }

    // Create the PKCS12
    let pkcs12 = openssl::pkcs12::Pkcs12::builder()
        .pkey(&pkey)
        .cert(&cert)
        .ca(cas)
        .build2(password)?;

    // The DER-encoded bytes of the archive
    Ok(pkcs12.to_der()?)
}

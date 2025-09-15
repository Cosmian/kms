use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::{
    ExportObjectParams, KmsClient,
    cosmian_kmip::ttlv::to_ttlv,
    export_object,
    kmip_2_1::{
        kmip_objects::{Certificate, Object, PrivateKey},
        kmip_types::UniqueIdentifier,
    },
    reexport::cosmian_kms_client_utils::export_utils::{
        CertificateExportFormat, prepare_certificate_export_elements,
    },
    write_bytes_to_file, write_json_object_to_file, write_kmip_object_to_file,
};
use cosmian_logger::trace;

use crate::{
    actions::kms::{console, labels::CERTIFICATE_ID, shared::get_key_uid},
    cli_bail,
    error::result::KmsCliResult,
};

/// Export a certificate from the KMS
///
/// The certificate is exported either:
/// - in TTLV JSON KMIP format (json-ttlv)
/// - in X509 PEM format (pem)
/// - in PKCS12 format including private key, certificate and chain (pkcs12)
/// - in legacy PKCS12 format (pkcs12-legacy), compatible with openssl 1.x,
///   for keystores that do not support the new format
///   (e.g. Java keystores, `macOS` Keychains,...)
///   This format is not available in FIPS mode.
/// - in PKCS7 format including the entire certificates chain (pkcs7)
///
/// When using tags to retrieve rather than the unique id,
/// an error is returned if multiple objects match the tags.
#[derive(Parser, Default, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ExportCertificateAction {
    /// The file to export the certificate to
    #[clap(required = true)]
    pub(crate) certificate_file: PathBuf,

    /// The certificate unique identifier stored in the KMS; for PKCS#12, provide the private key id
    /// If not specified, tags should be specified
    #[clap(
        long = CERTIFICATE_ID,
        short = 'c',
        group = "certificate-tags",
        verbatim_doc_comment
    )]
    pub(crate) certificate_id: Option<String>,

    /// Tag to use to retrieve the certificate/private key when no unique id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(
        long = "tag",
        short = 't',
        value_name = "TAG",
        group = "certificate-tags",
        verbatim_doc_comment
    )]
    pub(crate) tags: Option<Vec<String>>,

    /// Export the certificate in the selected format
    #[clap(long = "format", short = 'f', default_value = "json-ttlv")]
    pub(crate) output_format: CertificateExportFormat,

    /// Password to use to protect the PKCS#12 file
    #[clap(long = "pkcs12-password", short = 'p')]
    pub(crate) pkcs12_password: Option<String>,

    /// Allow exporting revoked and destroyed certificates or private key (for PKCS#12).
    /// The user must be the owner of the certificate.
    /// Destroyed objects have their key material removed.
    #[clap(
        long = "allow-revoked",
        short = 'r',
        default_value = "false",
        verbatim_doc_comment
    )]
    pub(crate) allow_revoked: bool,
}

impl ExportCertificateAction {
    /// Export a certificate from the KMS
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        trace!("{self:?}");

        let id = get_key_uid(
            self.certificate_id.as_ref(),
            self.tags.as_ref(),
            CERTIFICATE_ID,
        )?;

        let (key_format_type, wrapping_key_id) =
            prepare_certificate_export_elements(&self.output_format, self.pkcs12_password.clone());

        // export the object
        let (id, object, export_attributes) = export_object(
            &kms_rest_client,
            &id,
            ExportObjectParams {
                wrapping_key_id: wrapping_key_id.as_deref(),
                allow_revoked: self.allow_revoked,
                key_format_type: Some(key_format_type),
                ..ExportObjectParams::default()
            },
        )
        .await?;

        match &object {
            Object::Certificate(Certificate {
                certificate_value, ..
            }) => {
                match self.output_format {
                    CertificateExportFormat::JsonTtlv => {
                        // save it to a file
                        write_kmip_object_to_file(&object, &self.certificate_file)?;
                    }
                    CertificateExportFormat::Pem => {
                        // save the pem to a file
                        let pem = pem::Pem::new("CERTIFICATE", certificate_value.as_slice());
                        write_bytes_to_file(pem.to_string().as_bytes(), &self.certificate_file)?;
                    }
                    CertificateExportFormat::Pkcs12 => {
                        // PKCS12 is exported as a private key object
                        cli_bail!("PKCS12: invalid object returned by the server.");
                    }
                    #[cfg(feature = "non-fips")]
                    CertificateExportFormat::Pkcs12Legacy => {
                        // PKCS12 is exported as a private key object
                        cli_bail!("PKCS12: invalid object returned by the server.");
                    }
                    CertificateExportFormat::Pkcs7 => {
                        // save the pem to a file
                        let pem =
                            pem::Pem::new(String::from("PKCS7"), certificate_value.as_slice());
                        write_bytes_to_file(pem.to_string().as_bytes(), &self.certificate_file)?;
                    }
                }
            }
            // PKCS12 is exported as a private key object
            Object::PrivateKey(PrivateKey { key_block }) => {
                let p12_bytes = key_block.pkcs_der_bytes()?.to_vec();
                // save it to a file
                write_bytes_to_file(&p12_bytes, &self.certificate_file)?;
            }
            _ => {
                cli_bail!(
                    "The object {} is not a certificate but a {}",
                    &id,
                    object.object_type()
                );
            }
        }

        let mut stdout = format!(
            "The certificate {} was exported to {}",
            &id,
            self.certificate_file.display()
        );

        // write attributes to a file
        if let Some(export_attributes) = export_attributes {
            let attributes_file = self.certificate_file.with_extension("attributes.json");
            write_json_object_to_file(&to_ttlv(&export_attributes)?, &attributes_file)?;
            let stdout_attributes = format!(
                "The attributes of the certificate {} were exported to {}",
                &id,
                attributes_file.display()
            );
            stdout = format!("{stdout} - {stdout_attributes}");
        }
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_unique_identifier(&id);
        stdout.write()?;

        Ok(id)
    }
}

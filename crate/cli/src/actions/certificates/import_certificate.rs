use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use cloudproof::reexport::crypto_core::reexport::x509_cert;
use cosmian_kms_client::{
    cosmian_kmip::kmip::{
        kmip_objects::Object,
        kmip_types::{
            Attributes, CertificateType, KeyFormatType, LinkType, LinkedObjectIdentifier,
        },
    },
    import_object, read_bytes_from_file, read_object_from_json_ttlv_file, KmsClient,
};
use der::{Decode, DecodePem, Encode};
use tracing::{debug, trace};
use x509_cert::Certificate;
use zeroize::Zeroizing;

use crate::{
    actions::{
        console,
        shared::{
            import_key::build_private_key_from_der_bytes,
            utils::{build_usage_mask_from_key_usage, KeyUsage},
        },
    },
    error::{result::CliResult, CliError},
};

const MOZILLA_CCADB: &str =
    "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites";

#[derive(ValueEnum, Debug, Clone)]
pub enum CertificateInputFormat {
    JsonTtlv,
    Pem,
    Der,
    Chain,
    CCADB,
    Pkcs12,
}

/// Import one of the following:
/// - a certificate: formatted as a X509 PEM (pem), X509 DER (der) or JSON TTLV (json-ttlv)
/// - a certificate chain as a PEM-stack (chain)
/// - a PKCS12 file containing a certificate, a private key and possibly a chain (pkcs12)
/// - the Mozilla Common CA Database (CCADB - fetched by the CLI before import) (ccadb)
///
/// When no unique id is specified, a unique id based on the key material is generated.
///
/// Tags can later be used to retrieve the certificate. Tags are optional.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ImportCertificateAction {
    /// The input file in PEM, KMIP-JSON-TTLV or PKCS#12 format.
    #[clap(
        required_if_eq_any([
            ("input_format", "json-ttlv"),
            ("input_format", "pem"),
            ("input_format", "der"),
            ("input_format", "chain"),
            ("input_format", "pkcs12")
            ])
    )]
    certificate_file: Option<PathBuf>,

    /// The unique id of the leaf certificate; a unique id
    /// based on the key material is generated if not specified.
    /// When importing a PKCS12, the unique id will be that of the private key.
    #[clap(required = false, verbatim_doc_comment)]
    certificate_id: Option<String>,

    /// Import the certificate in the selected format.
    #[clap(
        required = true,
        long = "format",
        short = 'f',
        default_value = "json-ttlv"
    )]
    input_format: CertificateInputFormat,

    /// The corresponding private key id if any.
    /// Ignored for PKCS12 and CCADB formats.
    #[clap(long, short = 'k')]
    private_key_id: Option<String>,

    /// The corresponding public key id if any.
    /// Ignored for PKCS12 and CCADB formats.
    #[clap(long, short = 'q')]
    public_key_id: Option<String>,

    /// The issuer certificate id if any.
    /// Ignored for PKCS12 and CCADB formats.
    #[clap(long, short = 'i')]
    issuer_certificate_id: Option<String>,

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

    /// For what operations should the certificate be used.
    #[clap(long = "key-usage")]
    key_usage: Option<Vec<KeyUsage>>,
}

impl ImportCertificateAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        trace!("CLI: entering import certificate: {:?}", self);

        //generate the leaf certificate attributes if links are specified
        let mut leaf_certificate_attributes = None;
        if let Some(issuer_certificate_id) = &self.issuer_certificate_id {
            let attributes = leaf_certificate_attributes.get_or_insert(Attributes::default());
            attributes.set_link(
                LinkType::CertificateLink,
                LinkedObjectIdentifier::TextString(issuer_certificate_id.clone()),
            );
        };
        if let Some(private_key_id) = &self.private_key_id {
            let attributes = leaf_certificate_attributes.get_or_insert(Attributes::default());
            attributes.set_link(
                LinkType::PrivateKeyLink,
                LinkedObjectIdentifier::TextString(private_key_id.clone()),
            );
        };
        if let Some(public_key_id) = &self.public_key_id {
            let attributes = leaf_certificate_attributes.get_or_insert(Attributes::default());
            attributes.set_link(
                LinkType::PublicKeyLink,
                LinkedObjectIdentifier::TextString(public_key_id.clone()),
            );
        };

        trace!(
            "CLI: leaf_certificate_attributes: {:?}",
            leaf_certificate_attributes
        );
        let (stdout_message, returned_unique_identifier) = match self.input_format {
            CertificateInputFormat::JsonTtlv => {
                trace!("CLI: import certificate as TTLV JSON file");
                // read the certificate file
                let object = read_object_from_json_ttlv_file(self.get_certificate_file()?)?;
                let certificate_id = self
                    .import_chain(
                        kms_rest_client,
                        vec![object],
                        self.replace_existing,
                        leaf_certificate_attributes,
                    )
                    .await?;
                (
                    "The certificate in the JSON TTLV was successfully imported!".to_owned(),
                    Some(certificate_id),
                )
            }
            CertificateInputFormat::Pem => {
                trace!("CLI: import certificate as PEM file");
                let pem_value = read_bytes_from_file(&self.get_certificate_file()?)?;
                // convert the PEM to X509 to make sure it is correct
                let certificate = Certificate::from_pem(&pem_value).map_err(|e| {
                    CliError::Conversion(format!("Cannot read PEM content to X509. Error: {e:?}"))
                })?;
                let object = Object::Certificate {
                    certificate_type: CertificateType::X509,
                    certificate_value: certificate.to_der()?,
                };
                let certificate_id = self
                    .import_chain(
                        kms_rest_client,
                        vec![object],
                        self.replace_existing,
                        leaf_certificate_attributes,
                    )
                    .await?;
                (
                    "The certificate in the PEM file was successfully imported!".to_owned(),
                    Some(certificate_id),
                )
            }
            CertificateInputFormat::Der => {
                debug!("CLI: import certificate as a DER file");
                let der_value = read_bytes_from_file(&self.get_certificate_file()?)?;
                // convert DER to X509 to make sure it is correct
                let certificate = Certificate::from_der(&der_value).map_err(|e| {
                    CliError::Conversion(format!("Cannot read DER content to X509. Error: {e:?}"))
                })?;
                let object = Object::Certificate {
                    certificate_type: CertificateType::X509,
                    certificate_value: certificate.to_der()?,
                };
                let certificate_id = self
                    .import_chain(
                        kms_rest_client,
                        vec![object],
                        self.replace_existing,
                        leaf_certificate_attributes,
                    )
                    .await?;
                (
                    "The certificate in the DER file was successfully imported!".to_owned(),
                    Some(certificate_id),
                )
            }
            CertificateInputFormat::Pkcs12 => {
                debug!("CLI: import certificate as PKCS12 file");
                let private_key_id = self.import_pkcs12(kms_rest_client).await?;
                (
                    "The certificate(s) and private key were successfully imported! The private \
                     key has id:"
                        .to_string(),
                    Some(private_key_id),
                )
            }
            CertificateInputFormat::Chain => {
                debug!("CLI: import certificate chain as PEM file");
                let pem_stack = read_bytes_from_file(&self.get_certificate_file()?)?;
                let objects = build_chain_from_stack(&pem_stack)?;
                // import the full chain
                let leaf_certificate_id = self
                    .import_chain(
                        kms_rest_client,
                        objects,
                        self.replace_existing,
                        leaf_certificate_attributes,
                    )
                    .await?;
                (
                    "The certificate chain in the PEM file was successfully imported!".to_owned(),
                    Some(leaf_certificate_id),
                )
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
                self.import_chain(kms_rest_client, objects, self.replace_existing, None)
                    .await?;

                ("The list of Mozilla CCADB certificates".to_owned(), None)
            }
        };
        let mut stdout = console::Stdout::new(&stdout_message);
        stdout.set_tags(Some(&self.tags));
        if let Some(id) = returned_unique_identifier {
            stdout.set_unique_identifier(id);
        }
        stdout.write()?;

        Ok(())
    }

    /// Import the certificate, the chain and the associated private key
    async fn import_pkcs12(&self, kms_rest_client: &KmsClient) -> CliResult<String> {
        let cryptographic_usage_mask = self
            .key_usage
            .as_deref()
            .and_then(build_usage_mask_from_key_usage);
        let pkcs12_bytes = Zeroizing::from(read_bytes_from_file(&self.get_certificate_file()?)?);

        // Create a KMIP private key from the PKCS12 private key
        let private_key = build_private_key_from_der_bytes(KeyFormatType::PKCS12, pkcs12_bytes);

        let mut attributes = private_key.attributes().cloned().unwrap_or_default();
        attributes.set_cryptographic_usage_mask(cryptographic_usage_mask);

        if let Some(password) = &self.pkcs12_password {
            attributes.set_link(
                LinkType::PKCS12PasswordLink,
                LinkedObjectIdentifier::TextString(password.clone()),
            );
        }

        let private_key_id = import_object(
            kms_rest_client,
            self.certificate_id.clone(),
            private_key,
            Some(attributes),
            false,
            self.replace_existing,
            &self.tags,
        )
        .await?;
        Ok(private_key_id)
    }

    fn get_certificate_file(&self) -> CliResult<&PathBuf> {
        self.certificate_file.as_ref().ok_or_else(|| {
            CliError::InvalidRequest(format!(
                "Certificate file parameter is MANDATORY for {:?} format",
                self.input_format
            ))
        })
    }

    /// Import the certificates in reverse order (from root to leaf)
    /// linking the child to the parent with `Link` of `LinkType::CertificateLink`
    async fn import_chain(
        &self,
        kms_rest_client: &KmsClient,
        mut objects: Vec<Object>,
        replace_existing: bool,
        leaf_certificate_attributes: Option<Attributes>,
    ) -> CliResult<String> {
        let mut previous_identifier: Option<String> = None;
        while let Some(object) = objects.pop() {
            let mut import_attributes = if objects.is_empty() {
                // this is the leaf certificate
                leaf_certificate_attributes.clone()
            } else {
                None
            };
            // add link to issuer/parent certificate if any
            if let Some(id) = previous_identifier {
                let attributes = import_attributes.get_or_insert(Attributes::default());
                attributes.set_link(
                    LinkType::CertificateLink,
                    LinkedObjectIdentifier::TextString(id.clone()),
                );
            }
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
            previous_identifier = Some(unique_identifier);
        }
        // return the identifier of the leaf certificate
        previous_identifier.ok_or_else(|| {
            CliError::Default("The certificate chain does not contain any certificate".to_owned())
        })
    }
}

/// Build a chain of certificates from a PEM stack
fn build_chain_from_stack(pem_chain: &[u8]) -> CliResult<Vec<Object>> {
    let pem_s = pem::parse_many(pem_chain)
        .map_err(|e| CliError::Conversion(format!("Cannot parse PEM content. Error: {e:?}")))?; // check the PEM is valid (no error
    let mut objects = vec![];
    for pem_data in pem_s {
        // convert the PEM to X509 to make sure it is correct
        let certificate = Certificate::from_der(pem_data.contents()).map_err(|e| {
            CliError::Conversion(format!("Cannot read DER content to X509. Error: {e:?}"))
        })?;
        let object = Object::Certificate {
            certificate_type: CertificateType::X509,
            certificate_value: certificate.to_der()?,
        };
        objects.push(object);
    }
    Ok(objects)
}

#[cfg(test)]
mod tests {
    use crate::actions::certificates::import_certificate::build_chain_from_stack;

    #[test]
    fn test_chain_parse() {
        let chain_str =
            include_bytes!("../../../test_data/certificates/mozilla_IncludedRootsPEM.txt");
        let objects = build_chain_from_stack(chain_str).unwrap();
        assert_eq!(objects.len(), 144);
    }
}

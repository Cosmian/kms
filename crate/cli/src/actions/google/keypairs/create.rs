use std::path::PathBuf;

use base64::{engine::general_purpose, Engine};
use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::crypto::{
        certificates::EXTENSION_CONFIG, rsa::kmip_requests::create_rsa_key_pair_request,
    },
    export_object,
    kmip::{
        extra::{VENDOR_ATTR_X509_EXTENSION, VENDOR_ID_COSMIAN},
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Certify, GetAttributes},
        kmip_types::{
            Attributes, BlockCipherMode, CertificateAttributes, KeyFormatType, Link, LinkType,
            LinkedObjectIdentifier, UniqueIdentifier, VendorAttribute,
        },
    },
    ExportObjectParams, KmsClient,
};
use serde::{Deserialize, Serialize};
use tracing::trace;

use super::KEY_PAIRS_ENDPOINT;
use crate::{actions::google::gmail_client::GmailClient, error::CliError};

const RSA_4096: usize = 4096;

/// Creates and uploads a client-side encryption S/MIME public key certificate chain and private key
/// metadata for a user.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateKeyPairsAction {
    /// The requester's primary email address
    #[clap(required = true)]
    user_id: String,

    /// CSE key ID to wrap exported user private key
    #[clap(long, short = 'w', required = true)]
    cse_key_id: String,

    /// The issuer private key id
    #[clap(long, short = 'i', required = true)]
    issuer_private_key_id: String,

    /// When certifying a public key, or generating a keypair,
    /// the subject name to use.
    ///
    /// For instance: "CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"
    #[clap(long, short = 's', verbatim_doc_comment, required = true)]
    subject_name: String,

    /// The existing private key id of an existing RSA keypair to use (optional - if no ID is provided, a RSA keypair will be created)
    #[clap(long, short = 'k')]
    rsa_private_key_id: Option<String>,

    /// Dry run mode. If set, the action will not be executed.
    #[clap(long, default_value = "false")]
    dry_run: bool,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct KeyFile {
    kacls_url: String,
    wrapped_private_key: String,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
struct KeyPairInfo {
    pkcs7: String,
    privateKeyMetadata: Vec<PrivateKeyMetadata>,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
struct PrivateKeyMetadata {
    kaclsKeyMetadata: KaclsKeyMetadata,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
struct KaclsKeyMetadata {
    kaclsUri: String,
    kaclsData: String,
}

impl CreateKeyPairsAction {
    async fn post_keypair(
        gmail_client: &GmailClient,
        certificate_value: Vec<u8>,
        wrapped_private_key: String,
        kacls_url: String,
    ) -> Result<(), CliError> {
        let key_pair_info = KeyPairInfo {
            pkcs7: pem::encode(&pem::Pem::new(String::from("PKCS7"), certificate_value)),
            privateKeyMetadata: vec![PrivateKeyMetadata {
                kaclsKeyMetadata: KaclsKeyMetadata {
                    kaclsUri: kacls_url,
                    kaclsData: wrapped_private_key,
                },
            }],
        };

        let response = gmail_client
            .post(KEY_PAIRS_ENDPOINT, serde_json::to_string(&key_pair_info)?)
            .await?;
        GmailClient::handle_response(response).await
    }

    #[allow(clippy::print_stdout)]
    pub async fn run(
        &self,
        conf_path: &PathBuf,
        kms_rest_client: &KmsClient,
    ) -> Result<(), CliError> {
        let gmail_client = GmailClient::new(conf_path, &self.user_id);

        let kacls_url = kms_rest_client.google_cse_status();

        let (private_key_id, public_key_id) = match &self.rsa_private_key_id {
            Some(id) => {
                let attributes_response = kms_rest_client
                    .get_attributes(GetAttributes {
                        unique_identifier: Some(UniqueIdentifier::TextString(id.to_string())),
                        attribute_references: None,
                    })
                    .await?;
                if attributes_response.attributes.object_type == Some(ObjectType::PrivateKey) {
                    // Do we need to add encryption Algorithm to RSA too ?
                    if let Some(linked_public_key_id) = attributes_response
                        .attributes
                        .get_link(LinkType::PublicKeyLink)
                    {
                        (id.to_string(), linked_public_key_id.to_string())
                    } else {
                        return Err(CliError::ServerError(
                            "Invalid private-key-id  - no linked public key found".to_string(),
                        ));
                    }
                } else {
                    return Err(CliError::ServerError(
                        "Invalid private-key-id - must be of PrivateKey type".to_string(),
                    ));
                }
            }
            None => {
                let created_key_pair = kms_rest_client
                    .create_key_pair(create_rsa_key_pair_request(
                        None,
                        Vec::<String>::new(),
                        RSA_4096,
                    )?)
                    .await?;
                (
                    created_key_pair.private_key_unique_identifier.to_string(),
                    created_key_pair.public_key_unique_identifier.to_string(),
                )
            }
        };

        // Export wrapped private key with google CSE key
        let (wrapped_private_key, _attributes) = export_object(
            kms_rest_client,
            &private_key_id,
            ExportObjectParams {
                wrapping_key_id: Some(&self.cse_key_id),
                block_cipher_mode: Some(BlockCipherMode::GCM),
                ..ExportObjectParams::default()
            },
        )
        .await?;

        let wrapped_key_bytes = wrapped_private_key.key_block()?.key_bytes()?;

        // Sign created public key with issuer private key
        let attributes = Attributes {
            object_type: Some(ObjectType::Certificate),
            certificate_attributes: Some(Box::new(CertificateAttributes::parse_subject_line(
                &self.subject_name,
            )?)),
            link: Some(vec![Link {
                link_type: LinkType::PrivateKeyLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(
                    self.issuer_private_key_id.clone(),
                ),
            }]),
            vendor_attributes: Some(vec![VendorAttribute {
                vendor_identification: VENDOR_ID_COSMIAN.to_string(),
                attribute_name: VENDOR_ATTR_X509_EXTENSION.to_string(),
                attribute_value: EXTENSION_CONFIG.to_vec(),
            }]),
            ..Attributes::default()
        };

        let certify_request = Certify {
            unique_identifier: Some(UniqueIdentifier::TextString(public_key_id)),
            attributes: Some(attributes),
            ..Certify::default()
        };

        let certificate_unique_identifier = kms_rest_client
            .certify(certify_request)
            .await
            .map_err(|e| CliError::ServerError(format!("failed creating certificate: {e:?}")))?
            .unique_identifier;

        // From the created leaf certificate, export the associated PKCS7 containing the whole cert chain
        let (pkcs7_object, _pkcs7_object_export_attributes) = export_object(
            kms_rest_client,
            &certificate_unique_identifier.to_string(),
            ExportObjectParams {
                key_format_type: Some(KeyFormatType::PKCS7),
                ..ExportObjectParams::default()
            },
        )
        .await?;

        if let Object::Certificate {
            certificate_value, ..
        } = &pkcs7_object
        {
            trace!(
                "pkcs7_object: {:?}",
                general_purpose::STANDARD.encode(certificate_value)
            );
            trace!(
                "wrapped_key_bytes: {:?}",
                general_purpose::STANDARD.encode(wrapped_key_bytes.clone())
            );
        }

        if self.dry_run {
            println!("Dry run mode - key pair not pushed to Gmail API");
        } else {
            let email = &self.user_id;
            println!("[{email}] - Pushing new keypair to Gmail API");
            if let Object::Certificate {
                certificate_value, ..
            } = pkcs7_object
            {
                tracing::info!("Processing {email:?}.");
                Self::post_keypair(
                    &gmail_client.await?,
                    certificate_value,
                    general_purpose::STANDARD.encode(wrapped_key_bytes.clone()),
                    kacls_url.await?.kacls_url,
                )
                .await?;
                tracing::info!("Key pair inserted for {email:?}.");
            } else {
                Err(CliError::ServerError(format!(
                    "Error inserting key pair for {email:?} - exported object is not a Certificate"
                )))?;
            };
        }
        Ok(())
    }
}

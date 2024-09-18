use std::path::PathBuf;

use base64::{engine::general_purpose, Engine};
use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::crypto::rsa::kmip_requests::create_rsa_key_pair_request,
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
    KmsClient,
};
use serde::{Deserialize, Serialize};

use super::KEYPAIRS_ENDPOINT;
// use super::KEYPAIRS_ENDPOINT;
use crate::{actions::google::gmail_client::GmailClient, error::CliError};

const RSA_4096: usize = 4096;

/// Extension configuration
const EXTENSION_CONFIG: &[u8] = b"[ v3_ca ]
    keyUsage=nonRepudiation,digitalSignature,dataEncipherment,keyEncipherment\
    extendedKeyUsage=emailProtection
";

/// Creates and uploads a client-side encryption S/MIME public key certificate chain and private key
/// metadata for a user.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateKeypairsAction {
    /// The requester's primary email address
    #[clap(required = true)]
    user_id: String,

    /// CSE key ID to wrap exported user private key
    #[clap(long = "csekey-id", short = 'w', required = true)]
    csekey_id: String,

    /// The issuer certificate id
    #[clap(long, short = 'i', required = true)]
    issuer_private_key_id: String,

    /// When certifying a public key, or generating a keypair,
    /// the subject name to use.
    ///
    /// For instance: "CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"
    #[clap(
        long = "subject-name",
        short = 's',
        verbatim_doc_comment,
        required = true
    )]
    subject_name: String,

    /// The existing private key id of an existing RSA keypair to use (optionnal - if no ID is provided, a RSA keypair will be created)
    #[clap(long, short = 'k')]
    rsa_private_key_id: Option<String>,
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

impl CreateKeypairsAction {
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
            .post(KEYPAIRS_ENDPOINT, serde_json::to_string(&key_pair_info)?)
            .await?;
        GmailClient::handle_response(response).await
    }

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
                if let Some(ObjectType::PrivateKey) = attributes_response.attributes.object_type {
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
                    .create_key_pair(create_rsa_key_pair_request(Vec::<String>::new(), RSA_4096)?)
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
            false,
            Some(&self.csekey_id),
            true,
            None,
            Some(BlockCipherMode::GCM),
            None,
        )
        .await?;

        let wrapped_key_bytes = wrapped_private_key.key_block()?.key_bytes()?;

        let encoded_private_key = general_purpose::STANDARD.encode(wrapped_key_bytes.clone());

        // println!("WRAPPED {encoded_private_key:?}");

        // let (not_wrapped_private_key, _attributes) = export_object(
        //     kms_rest_client,
        //     &private_key_id,
        //     true,
        //     None,
        //     true,
        //     None,
        //     None,
        //     None,
        // )
        // .await?;

        // let not_wrapped_key_bytes = not_wrapped_private_key.key_block()?.key_bytes()?;

        // let not_wrapped_encoded_private_key =
        //     general_purpose::STANDARD.encode(not_wrapped_key_bytes);

        // println!("NOT WRAPPED {not_wrapped_encoded_private_key:?}");

        // const NONCE_LENGTH: usize = 12;
        // const TAG_LENGTH: usize = 16;

        // let len = wrapped_key_bytes.clone().len();
        // let iv_counter_nonce = &wrapped_key_bytes[..NONCE_LENGTH];
        // let ciphertext = &wrapped_key_bytes[NONCE_LENGTH..len - TAG_LENGTH];
        // let authenticated_tag = &wrapped_key_bytes[len - TAG_LENGTH..];

        // let decrypt_request = build_decryption_request(
        //     &self.csekey_id,
        //     Some(iv_counter_nonce.to_vec()),
        //     ciphertext.to_vec(),
        //     Some(authenticated_tag.to_vec()),
        //     None,
        //     None,
        // );

        // let decrypt_response = kms_rest_client.decrypt(decrypt_request).await?;

        // let plaintext = decrypt_response.data.unwrap();
        // let res1 = general_purpose::STANDARD.encode(plaintext);

        // println!("RES 1 {res1:?}");

        // let mut second_wrapped_key = wrapped_private_key.clone();
        // let (unwrapping_key, _attributes) = export_object(
        //     kms_rest_client,
        //     &self.csekey_id,
        //     true,
        //     None,
        //     true,
        //     Some(KeyFormatType::TransparentSymmetricKey),
        //     None,
        //     None,
        // )
        // .await?;

        // let key_block = second_wrapped_key.key_block_mut()?;
        // let aad = &[];
        // key_block.attributes_mut()?.add_aad(aad);

        // unwrap_key_block(key_block, &unwrapping_key)?;
        // let plaintext2 = second_wrapped_key.key_block()?.key_bytes()?;
        // let res2 = general_purpose::STANDARD.encode(plaintext2);

        // println!("RES 2 {res2:?}");

        // let mut third_wrapped_key = wrapped_private_key.clone();

        // let key_block = third_wrapped_key.key_block_mut()?;
        // let aad = &[];
        // key_block.attributes_mut()?.add_aad(aad);

        // let third_wrapped_key_bytes = key_block.key_bytes()?;
        // let res30 = general_purpose::STANDARD.encode(third_wrapped_key_bytes);

        // println!("RES 3.0 {res30:?}");

        // let flags = 0;
        // let cryptographic_usage_mask = CryptographicUsageMask::from_bits(flags);

        // let import_attributes = third_wrapped_key
        //     .attributes()
        //     .unwrap_or(&Attributes {
        //         cryptographic_usage_mask,
        //         ..Default::default()
        //     })
        //     .clone();

        // let unique_identifier = import_object(
        //     kms_rest_client,
        //     None,
        //     third_wrapped_key,
        //     None,
        //     true,
        //     false,
        //     ["new"],
        // )
        // .await?;

        // let (imported_key, _attributes) = export_object(
        //     kms_rest_client,
        //     &unique_identifier,
        //     true,
        //     None,
        //     true,
        //     None,
        //     None,
        //     None,
        // )
        // .await?;

        // let imported_key_bytes = imported_key.key_block()?.key_bytes()?;

        // let imported_encoded_private_key = general_purpose::STANDARD.encode(imported_key_bytes);

        // println!("RES 3{imported_encoded_private_key:?}");

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
            unique_identifier: Some(
                cosmian_kms_client::kmip::kmip_types::UniqueIdentifier::TextString(public_key_id),
            ),
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
            false,
            None,
            false,
            Some(KeyFormatType::PKCS7),
            None,
            None,
        )
        .await?;

        let email = &self.user_id;
        if let Object::Certificate {
            certificate_value, ..
        } = pkcs7_object
        {
            tracing::info!("Processing {email:?}.");
            Self::post_keypair(
                &gmail_client.await?,
                certificate_value,
                encoded_private_key,
                kacls_url.await?.kacls_url,
            )
            .await?;
            tracing::info!("Keypair inserted for {email:?}.");
        } else {
            tracing::info!(
                "Error inserting keypair for {email:?} - exported object is not a Certificate"
            );
            Err(CliError::ServerError(format!(
                "Error inserting keypair for {email:?} - exported object is not a Certificate"
            )))?;
        };
        Ok(())
    }
}

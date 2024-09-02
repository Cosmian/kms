use std::path::PathBuf;

use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::crypto::{
        generic::kmip_requests::build_encryption_request,
        rsa::kmip_requests::create_rsa_key_pair_request,
    },
    export_object,
    kmip::{
        extra::{VENDOR_ATTR_X509_EXTENSION, VENDOR_ID_COSMIAN},
        kmip_objects::{Object, ObjectType},
        kmip_operations::Certify,
        kmip_types::{
            Attributes, CertificateAttributes, CryptographicAlgorithm, CryptographicParameters,
            KeyFormatType, Link, LinkType, LinkedObjectIdentifier, VendorAttribute,
        },
    },
    KmsClient,
};
use serde::{Deserialize, Serialize};

use super::KEYPAIRS_ENDPOINT;
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
    #[clap(long = "user-id", short = 'u', required = true)]
    user_id: String,

    /// CSE key ID to wrap exported user private key
    #[clap(long = "csekey-id", short = 'w', required = true)]
    csekey_id: String,

    /// The issuer certificate id
    #[clap(long = "issuer_private_key_id", short = 'i')]
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

        // Query the KMS to create RSA KEYPAIRS_ENDPOINT and get the key pair ids
        let created_key_pair = kms_rest_client
            .create_key_pair(create_rsa_key_pair_request(Vec::<String>::new(), RSA_4096)?)
            .await?;

        // Export wrapped private key with google CSE key
        let (raw_private_key_object, _) = export_object(
            kms_rest_client,
            &created_key_pair.private_key_unique_identifier.to_string(),
            true,
            None,
            false,
            None,
        )
        .await?;

        let key_bytes = raw_private_key_object.key_block()?.key_bytes()?;

        // Create the kmip query
        let encrypt_request = build_encryption_request(
            &self.csekey_id,
            None,
            key_bytes.to_vec(),
            None,
            None,
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Default::default()
            }),
        )?;

        let encrypt_response = kms_rest_client.encrypt(encrypt_request).await?;

        // extract the nonce and write it
        let iv_counter_nonce = encrypt_response.iv_counter_nonce.unwrap();

        // extract the ciphertext and write it
        let data = encrypt_response.data.unwrap();

        // extract the authentication tag and write it
        let authenticated_encryption_tag = encrypt_response.authenticated_encryption_tag.unwrap();

        let wrapped_private_key = [iv_counter_nonce, data, authenticated_encryption_tag].concat();

        let encoded_private_key = general_purpose::STANDARD.encode(&wrapped_private_key);

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

        let unique_identifier = created_key_pair.public_key_unique_identifier;

        let certify_request = Certify {
            unique_identifier: Some(unique_identifier),
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

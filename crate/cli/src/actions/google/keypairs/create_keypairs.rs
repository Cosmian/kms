use std::path::PathBuf;

use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::crypto::rsa::kmip_requests::create_rsa_key_pair_request,
    export_object,
    kmip::{
        kmip_objects::{Object, ObjectType},
        kmip_operations::Certify,
        kmip_types::{
            Attributes, CertificateAttributes, KeyFormatType, LinkType, LinkedObjectIdentifier,
            UniqueIdentifier,
        },
    },
    KmsClient,
};
use serde::{Deserialize, Serialize};

use super::KEYPAIRS_ENDPOINT;
use crate::{actions::google::gmail_client::GmailClient, error::CliError};

const RSA4096: usize = 4096;

/// Extension configuration
const EXTENSION_CONFIG: &[u8] = b"[ v3_ca ]
    keyUsage=nonRepudiation,digitalSignature,dataEncipherment,keyEncipherment\
    extendedKeyUsage=emailProtection
    crlDistributionPoints=URI:http://cse.cosmian.com/crl.pem\
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
    async fn wrap_key(
        key_id: &str,
        csekey_id: &str,
        kms_rest_client: &KmsClient,
    ) -> Result<String, CliError> {
        let (wrapped_private_key_object, _) =
            export_object(kms_rest_client, key_id, false, Some(csekey_id), false, None).await?;

        Ok(general_purpose::STANDARD.encode(wrapped_private_key_object.key_block()?.key_bytes()?))
    }

    async fn post_keypair(
        gmail_client: &GmailClient,
        cert_file: String,
        wrapped_private_key: String,
        kacls_url: String,
    ) -> Result<(), CliError> {
        let key_pair_info = KeyPairInfo {
            pkcs7: cert_file,
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

        // Create a RSA 4096 keypair for the user
        let create_key_pair_request = create_rsa_key_pair_request(Vec::<String>::new(), RSA4096)?;

        // Query the KMS to create RSA KEYPAIRS_ENDPOINT and get the key pair ids
        let create_key_pair_response = kms_rest_client
            .create_key_pair(create_key_pair_request)
            .await?;

        let private_key_unique_identifier = create_key_pair_response
            .private_key_unique_identifier
            .to_string();
        let public_key_unique_identifier = create_key_pair_response.public_key_unique_identifier;

        // Export wrapped private key with google CSE key
        let wrapped_private_key = Self::wrap_key(
            &private_key_unique_identifier,
            &self.csekey_id,
            kms_rest_client,
        );

        // Sign created public key with issuer private key
        let mut attributes = Attributes {
            object_type: Some(ObjectType::Certificate),
            ..Attributes::default()
        };
        let unique_identifier = Some(UniqueIdentifier::TextString(
            public_key_unique_identifier.to_string(),
        ));
        attributes.certificate_attributes = Some(Box::new(
            CertificateAttributes::parse_subject_line(&self.subject_name)?,
        ));
        attributes.set_link(
            LinkType::PrivateKeyLink,
            LinkedObjectIdentifier::TextString(self.issuer_private_key_id.clone()),
        );

        attributes.set_x509_extension_file(EXTENSION_CONFIG.to_vec());

        let certify_request = Certify {
            unique_identifier,
            attributes: Some(attributes),
            certificate_request_value: None,
            certificate_request_type: None,
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
        match pkcs7_object {
            Object::Certificate {
                certificate_value, ..
            } => {
                let pem = pem::Pem::new(String::from("PKCS7"), certificate_value);
                let pem_string = pem::encode(&pem);
                tracing::info!("Processing {email:?}.");
                Self::post_keypair(
                    &gmail_client.await?,
                    pem_string,
                    wrapped_private_key.await?,
                    kacls_url.await?.kacls_url,
                )
                .await?;
                tracing::info!("Keypair inserted for {email:?}.");
            }
            _ => {
                tracing::info!("Error inserting keypair for {email:?}");
                Err(CliError::ServerError(
                    "Error inserting keypair for {email:?}".to_string(),
                ))?
            }
        };
        Ok(())
    }
}

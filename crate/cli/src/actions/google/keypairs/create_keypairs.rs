use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    path::PathBuf,
};

use base64::encode;
use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::crypto::rsa::kmip_requests::create_rsa_key_pair_request, export_object, KmsClient,
};
use serde::{Deserialize, Serialize};

use super::KEYPAIRS_ENDPOINT;
use crate::{actions::google::gmail_client::GmailClient, error::CliError};

/// Creates and uploads a client-side encryption S/MIME public key certificate chain and private key
/// metadata for a user.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateKeypairsAction {
    /// The requester's primary email address
    #[clap(long = "user-id", short = 'u', required = true)]
    user_id: String,

    /// CSE key ID to wrap exported private key
    #[clap(long = "csekey-id", short = 'w', required = true)]
    csekey_id: String,

    /// The issuer certificate id if any.
    #[clap(long = "issuer-certificate-id", short = 'i')]
    issuer_certificate_id: String,

    /// Input directory with wrapped key files, with email as basename
    #[clap(long = "certificate-extension-config", short = 'c', required = true)]
    extension_config: PathBuf,
}

#[derive(Serialize, Deserialize)]
pub struct KeyFile {
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
    async fn post_keypairs(
        gmail_client: &GmailClient,
        cert_file: &str,
        email: &str,
        wrapped_private_key: &str,
        kacls_url: &str,
    ) -> Result<(), CliError> {
        tracing::info!("Processing {email:?}.");

        let key_pair_info = KeyPairInfo {
            pkcs7: cert_file.to_string(),
            privateKeyMetadata: vec![PrivateKeyMetadata {
                kaclsKeyMetadata: KaclsKeyMetadata {
                    kaclsUri: kacls_url.to_string(),
                    kaclsData: wrapped_private_key.to_string(),
                },
            }],
        };

        let response = gmail_client
            .post(KEYPAIRS_ENDPOINT, serde_json::to_string(&key_pair_info)?)
            .await?;
        let res = GmailClient::handle_response(response).await;
        match res {
            Ok(()) => tracing::info!("Keypairs inserted for {email:?}."),
            Err(error) => tracing::info!("Error inserting keypairs for {email:?} : {error:?}"),
        }
        Ok(())
    }

    pub async fn run(
        &self,
        conf_path: &PathBuf,
        kms_rest_client: &KmsClient,
    ) -> Result<(), CliError> {
        // let gmail_client = GmailClient::new(conf_path, &self.user_id).await?;

        // let kacls_url = kms_rest_client.google_cse_status().await?.kacls_url;

        let create_key_pair_request = create_rsa_key_pair_request(vec!["ok"], 4096)?;

        // Query the KMS with your kmip data and get the key pair ids
        let create_key_pair_response = kms_rest_client
            .create_key_pair(create_key_pair_request)
            .await?;

        let private_key_unique_identifier = &create_key_pair_response.private_key_unique_identifier;
        // let public_key_unique_identifier = &create_key_pair_response.public_key_unique_identifier;

        // let wrapped_private_key = kms_rest_client.export()
        let (wrapped_private_key_object, _) = export_object(
            kms_rest_client,
            &private_key_unique_identifier.to_string(),
            true,
            Some(&self.csekey_id),
            false,
            None,
        )
        .await?;

        let wrapped_private_key = encode(wrapped_private_key_object.key_block()?.key_bytes()?);
        // QUID good Raw format or PKCS1 ?
        println!("{:?}", wrapped_private_key);

        // let wrapped_key_files = Self::get_input_files(&self.inkeydir, "wrap")?;
        // let p7_cert_files = Self::get_input_files(&self.incertdir, "p7pem")?;

        // let email_key_file_map = Self::get_email_to_file(&wrapped_key_files, "wrap")?;
        // let email_cert_file_map = Self::get_email_to_file(&p7_cert_files, "p7pem")?;

        // tracing::info!("wrapped_key_files: {wrapped_key_files:?}.");
        // tracing::info!("p7_cert_files: {p7_cert_files:?}.");

        // for (email, key_file) in &email_key_file_map {
        //     if !email_cert_file_map.contains_key(email) {
        //         tracing::info!("Skipping {email:?}, missing cert file.");
        //         continue;
        //     }
        // Self::post_keypairs(
        //     &gmail_client,
        //     &email_cert_file_map,
        //     email,
        //     wrapped_private_key,
        //     kacls_url,
        // )
        // .await?;
        // }
        Ok(())
    }
}

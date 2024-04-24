use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    path::PathBuf,
};

use clap::Parser;
use serde::{Deserialize, Serialize};

use super::KEYPAIRS_ENDPOINT;
use crate::{actions::google::gmail_client::GmailClient, error::CliError};

/// Creates and uploads a client-side encryption S/MIME public key certificate chain and private key metadata for a user.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct InsertKeypairsAction {
    /// The requester's primary email address
    #[clap(long = "user-id", short = 'u', required = true)]
    user_id: String,

    /// Input directory with wrapped key files, with email as basename
    #[clap(long = "inkeydir", short = 'k', required = true)]
    inkeydir: PathBuf,

    /// Input directory with p7 pem certs with extension p7pem, with email as basename
    #[clap(long = "incertdir", short = 'c', required = true)]
    incertdir: PathBuf,
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

impl InsertKeypairsAction {
    fn get_input_files(indir: &PathBuf, ext: &str) -> Result<Vec<PathBuf>, CliError> {
        let full_names: Vec<PathBuf> = fs::read_dir(indir)?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .collect();

        let all_files: Vec<PathBuf> = full_names.iter().filter(|f| f.is_file()).cloned().collect();

        let input_files: Vec<PathBuf> = all_files
            .into_iter()
            .filter(|f| f.extension().map_or(false, |e| e == ext))
            .collect();

        Ok(input_files)
    }

    fn get_email_to_file(
        files: &[PathBuf],
        ext: &str,
    ) -> Result<HashMap<String, PathBuf>, CliError> {
        let mut email_file_map = HashMap::new();

        for file in files {
            let fname = file
                .file_name()
                .ok_or_else(|| {
                    CliError::Conversion(format!("cannot get file name from input file {file:?}",))
                })?
                .to_string_lossy();
            let (email, xtn) = match fname.rfind('.') {
                Some(idx) => fname.split_at(idx),
                None => continue,
            };

            if xtn[1..] != *ext {
                continue;
            }

            email_file_map.insert(email.to_string(), file.clone());
        }

        Ok(email_file_map)
    }

    async fn post_keypairs(
        gmail_client: &GmailClient,
        email_cert_file_map: &HashMap<String, PathBuf>,
        email: &str,
        key_file: &PathBuf,
    ) -> Result<(), CliError> {
        let endpoint: String = KEYPAIRS_ENDPOINT.to_string();
        println!("Processing {:?}.", email);

        // Open key file
        let mut kf = File::open(key_file)?;
        let mut kf_contents = String::new();
        kf.read_to_string(&mut kf_contents)?;

        // Parse JSON from key file
        let kf_resp: KeyFile = serde_json::from_str(&kf_contents)?;

        // Extract kacls_url and wrapped_private_key from kf_resp
        let kacls_url = kf_resp.kacls_url;
        let wrapped_private_key = kf_resp.wrapped_private_key;

        // Open cert file
        let mut cf = File::open(&email_cert_file_map[email])?;
        let mut certs = String::new();
        cf.read_to_string(&mut certs)?;

        // Construct key_pair_info
        let key_pair_info = KeyPairInfo {
            pkcs7: certs,
            privateKeyMetadata: vec![PrivateKeyMetadata {
                kaclsKeyMetadata: KaclsKeyMetadata {
                    kaclsUri: kacls_url,
                    kaclsData: wrapped_private_key,
                },
            }],
        };
        let res = gmail_client
            .post(&endpoint, serde_json::to_string(&key_pair_info)?)
            .await;
        match res {
            Ok(_) => println!("Keypairs inserted for {:?}.", email),
            Err(error) => println!("Error inserting keypairs for {:?} : {:?}", email, error),
        }
        Ok(())
    }

    pub async fn run(&self, conf_path: &PathBuf) -> Result<(), CliError> {
        let gmail_client = GmailClient::new(conf_path, &self.user_id).await?;

        let wrapped_key_files = Self::get_input_files(&self.inkeydir, "wrap")?;
        let p7_cert_files = Self::get_input_files(&self.incertdir, "p7pem")?;

        let email_key_file_map = Self::get_email_to_file(&wrapped_key_files, "wrap")?;
        let email_cert_file_map = Self::get_email_to_file(&p7_cert_files, "p7pem")?;

        println!("wrapped_key_files: {:?}.", wrapped_key_files);
        println!("p7_cert_files: {:?}.", p7_cert_files);

        for (email, key_file) in &email_key_file_map {
            if !email_cert_file_map.contains_key(email) {
                println!("Skipping {:?}, missing cert file.", email);
                continue;
            }
            Self::post_keypairs(&gmail_client, &email_cert_file_map, email, key_file).await?
        }
        Ok(())
    }
}

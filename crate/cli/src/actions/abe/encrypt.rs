use std::{fs::File, io::prelude::*, path::PathBuf};

use clap::Parser;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::generic::kmip_requests::build_hybrid_encryption_request;
use eyre::Context;

/// Encrypts a file with the given policy attributes
/// and the public key stored in the KMS.
#[derive(Parser, Debug)]
pub struct EncryptAction {
    /// The file to encrypt
    #[clap(required = true, name = "FILE")]
    input_file: PathBuf,

    /// The access policy to encrypt the file with
    /// Example: `--access-policy "department::marketing && level::confidential"`
    #[clap(required = true, long, short)]
    access_policy: String,

    /// The encrypted output file path
    #[clap(required = false, long, short = 'o')]
    output_file: PathBuf,

    /// The optional resource_uid. It's an extra encryption parameter to increase the security level
    #[clap(required = false, long, short, default_value = "")]
    resource_uid: String,

    /// The public key unique identifier stored in the KMS
    #[clap(required = true, long, short = 'p')]
    public_key_id: String,
}

impl EncryptAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> eyre::Result<()> {
        // Read the file to encrypt
        let mut f =
            File::open(&self.input_file).with_context(|| "Can't read the file to encrypt")?;
        let mut data = Vec::new();
        f.read_to_end(&mut data)
            .with_context(|| "Fail to read the file to encrypt")?;

        // Create the kmip query
        let encrypt_request = build_hybrid_encryption_request(
            &self.public_key_id,
            &self.access_policy,
            self.resource_uid.as_bytes().to_vec(),
            data,
            None,
        )?;

        // Query the KMS with your kmip data and get the key pair ids
        let encrypt_response = client_connector
            .encrypt(encrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        data = encrypt_response
            .data
            .ok_or_else(|| eyre::eyre!("The encrypted data are empty"))?;

        // Write the encrypted file
        let mut buffer =
            File::create(&self.output_file).with_context(|| "Fail to write the encrypted file")?;
        buffer
            .write_all(&data)
            .with_context(|| "Fail to write the encrypted file")?;

        println!("The encryption has been properly done.");
        println!("The encrypted file can be found at {:?}", &self.output_file);

        Ok(())
    }
}

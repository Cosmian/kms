use std::{fs::File, io::prelude::*, path::PathBuf};

use clap::StructOpt;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::generic::kmip_requests::build_decryption_request;
use eyre::Context;

/// Decrypts a file identified by its name and
/// given a user decryption key stored in the KMS.
#[derive(StructOpt, Debug)]
pub struct DecryptAction {
    /// The file to decrypt
    #[structopt(required = true, name = "FILE", parse(from_os_str))]
    input_file: PathBuf,

    /// The encrypted output file path
    #[structopt(required = false, parse(from_os_str), long, short = 'o')]
    output_file: PathBuf,

    /// The optional resource_uid. It's an extra encryption parameter to increase the security level
    #[structopt(required = false, long, short, default_value = "")]
    resource_uid: String,

    /// The user decryption key unique identifier stored in the KMS
    #[structopt(required = true, long, short = 'u')]
    user_key_id: String,
}

impl DecryptAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> eyre::Result<()> {
        // Read the file to decrypt
        let mut f =
            File::open(&self.input_file).with_context(|| "Can't read the file to decrypt")?;
        let mut data = Vec::new();
        f.read_to_end(&mut data)
            .with_context(|| "Fail to read the file to decrypt")?;

        // Create the kmip query
        let decrypt_request = build_decryption_request(
            &self.user_key_id,
            self.resource_uid.as_bytes().to_vec(),
            data,
        );

        // Query the KMS with your kmip data and get the key pair ids
        let decrypt_response = client_connector
            .decrypt(decrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        data = decrypt_response
            .data
            .ok_or_else(|| eyre::eyre!("The plain data are empty"))?;

        // Write the decrypted file
        let mut buffer =
            File::create(&self.output_file).with_context(|| "Fail to write the plain file")?;
        buffer
            .write_all(&data)
            .with_context(|| "Fail to write the plain file")?;

        println!("The decryption has been properly done.");
        println!("The decrypted file can be found at {:?}", &self.output_file);

        Ok(())
    }
}
